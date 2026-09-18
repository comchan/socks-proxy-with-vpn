package sshbackend

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type testSSHServer struct {
	listener   net.Listener
	echo       net.Listener
	closeOnce  sync.Once
	clientKey  ssh.Signer
	hostKey    ssh.Signer
	profile    config.ProfileConfig
	echoAddr   string
	knownHosts string
	privateKey string
}

func newTestSSHServer(t *testing.T) *testSSHServer {
	t.Helper()
	hostKey, _ := mustRSASigner(t)
	clientKey, clientPrivateKey := mustRSASigner(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}

	serverConfig := &ssh.ServerConfig{PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if metadata.User() != "test-user" || !bytes.Equal(key.Marshal(), clientKey.PublicKey().Marshal()) {
			return nil, fmt.Errorf("unauthorized test key")
		}
		return nil, nil
	}}
	serverConfig.AddHostKey(hostKey)
	testServer := &testSSHServer{
		listener:  listener,
		echo:      echo,
		clientKey: clientKey,
		hostKey:   hostKey,
		echoAddr:  echo.Addr().String(),
	}

	directory := t.TempDir()
	testServer.privateKey = filepath.Join(directory, "id_test")
	testServer.knownHosts = filepath.Join(directory, "known_hosts")
	writePrivateKey(t, testServer.privateKey, clientPrivateKey)
	writeKnownHosts(t, testServer.knownHosts, listener.Addr().String(), hostKey)
	port := listener.Addr().(*net.TCPAddr).Port
	testServer.profile = config.ProfileConfig{
		ID:             "test-ssh",
		Backend:        "ssh",
		Host:           "127.0.0.1",
		Port:           uint16(port),
		User:           "test-user",
		PrivateKeyPath: testServer.privateKey,
		KnownHostsPath: testServer.knownHosts,
	}

	go testSSHAcceptLoop(listener, serverConfig)
	go testEchoAcceptLoop(echo)
	t.Cleanup(testServer.close)
	return testServer
}

func (s *testSSHServer) close() {
	s.closeOnce.Do(func() {
		_ = s.listener.Close()
		_ = s.echo.Close()
	})
}

func writePrivateKey(t *testing.T, path string, key *rsa.PrivateKey) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeKnownHosts(t *testing.T, path, address string, signer ssh.Signer) {
	t.Helper()
	line := knownhosts.Line([]string{address}, signer.PublicKey()) + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustRSASigner(t *testing.T) (ssh.Signer, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer, key
}

func testSSHAcceptLoop(listener net.Listener, serverConfig *ssh.ServerConfig) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go handleTestSSHConnection(connection, serverConfig)
	}
}

func handleTestSSHConnection(connection net.Conn, serverConfig *ssh.ServerConfig) {
	serverConn, channels, requests, err := ssh.NewServerConn(connection, serverConfig)
	if err != nil {
		_ = connection.Close()
		return
	}
	go ssh.DiscardRequests(requests)
	defer func() { _ = serverConn.Close() }()
	for channel := range channels {
		if channel.ChannelType() != "direct-tcpip" {
			_ = channel.Reject(ssh.UnknownChannelType, "only direct-tcpip is supported")
			continue
		}
		var payload struct {
			RemoteAddr string
			RemotePort uint32
			LocalAddr  string
			LocalPort  uint32
		}
		if err := ssh.Unmarshal(channel.ExtraData(), &payload); err != nil {
			_ = channel.Reject(ssh.ConnectionFailed, "invalid direct-tcpip payload")
			continue
		}
		upstream, err := net.Dial("tcp", net.JoinHostPort(payload.RemoteAddr, strconv.Itoa(int(payload.RemotePort))))
		if err != nil {
			_ = channel.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		stream, requests, err := channel.Accept()
		if err != nil {
			_ = upstream.Close()
			continue
		}
		go ssh.DiscardRequests(requests)
		go bridgeTestStreams(stream, upstream)
	}
}

func bridgeTestStreams(left, right io.ReadWriteCloser) {
	finished := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(left, right)
		_ = left.Close()
		_ = right.Close()
		finished <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(right, left)
		_ = left.Close()
		_ = right.Close()
		finished <- struct{}{}
	}()
	<-finished
}

func testEchoAcceptLoop(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			_, _ = io.Copy(connection, connection)
			_ = connection.Close()
		}()
	}
}
