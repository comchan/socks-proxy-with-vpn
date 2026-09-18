//go:build integration

package sshbackend

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"golang.org/x/crypto/ssh"
)

func TestOpenTCPThroughOpenSSHContainer(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker engine is unavailable")
	}
	if _, err := exec.LookPath("ssh-keyscan"); err != nil {
		t.Skip("ssh-keyscan is not installed")
	}

	echo := startIntegrationEcho(t)
	clientSigner, clientKey := mustRSASigner(t)
	containerName := "vpnfront-ssh-integration-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	publicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(clientSigner.PublicKey())))
	args := []string{
		"run", "-d", "--rm", "--name", containerName,
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "PUID=1000", "-e", "PGID=1000", "-e", "TZ=UTC",
		"-e", "USER_NAME=test-user", "-e", "PUBLIC_KEY=" + publicKey,
		"-e", "PASSWORD_ACCESS=false", "-e", "DOCKER_MODS=linuxserver/mods:openssh-server-ssh-tunnel",
		"-p", "127.0.0.1::2222",
		"linuxserver/openssh-server:latest",
	}
	if output, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Skipf("OpenSSH integration image unavailable: %v (%s)", err, strings.TrimSpace(string(output)))
	}
	defer func() { _ = exec.Command("docker", "rm", "-f", containerName).Run() }()

	sshPort := waitForDockerPort(t, containerName)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	keyPath := filepath.Join(t.TempDir(), "id_test")
	writePrivateKey(t, keyPath, clientKey)
	keyscan := waitForHostKey(t, sshPort)
	if err := os.WriteFile(knownHosts, keyscan, 0o600); err != nil {
		t.Fatal(err)
	}
	profile := config.ProfileConfig{Backend: "ssh", Host: "127.0.0.1", Port: uint16(sshPort), User: "test-user", PrivateKeyPath: keyPath, KnownHostsPath: knownHosts}
	connector, err := New(context.Background(), profile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connector.Close() }()

	connection, err := connector.OpenTCP(context.Background(), domain.Destination{Host: "host.docker.internal", Port: uint16(echo.port)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	if _, err := connection.Write([]byte("openssh-container")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("openssh-container"))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "openssh-container" {
		t.Fatalf("echo response = %q", response)
	}
}

type integrationEcho struct{ port int }

func startIntegrationEcho(t *testing.T) integrationEcho {
	t.Helper()
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().(*net.TCPAddr)
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				_, _ = io.Copy(conn, conn)
				_ = conn.Close()
			}(connection)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return integrationEcho{port: address.Port}
}

func waitForDockerPort(t *testing.T, containerName string) int {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		output, err := exec.Command("docker", "port", containerName, "2222/tcp").Output()
		if err == nil {
			parts := strings.Split(strings.TrimSpace(string(output)), ":")
			if len(parts) == 2 {
				port, parseErr := strconv.Atoi(parts[1])
				if parseErr == nil {
					if connection, dialErr := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second); dialErr == nil {
						_ = connection.Close()
						return port
					}
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("OpenSSH container did not become ready")
	return 0
}

func waitForHostKey(t *testing.T, port int) []byte {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		output, err := exec.Command("ssh-keyscan", "-T", "5", "-p", strconv.Itoa(port), "127.0.0.1").Output()
		if err == nil && len(output) > 0 {
			return output
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("OpenSSH service did not provide a host key")
	return nil
}
