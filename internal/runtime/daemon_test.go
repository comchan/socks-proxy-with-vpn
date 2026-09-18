package runtime

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
)

type daemonTestConnector struct{}

func (daemonTestConnector) OpenTCP(context.Context, domain.Destination) (net.Conn, error) {
	return nil, errors.New("test connector has no upstream")
}
func (daemonTestConnector) OpenUDP(context.Context) (net.PacketConn, error) {
	return nil, errors.New("test connector has no UDP upstream")
}
func (daemonTestConnector) Resolve(context.Context, string) ([]net.IP, error) {
	return nil, errors.New("test connector has no resolver")
}

type securityTestConnector struct {
	upstream net.Conn
}

func (c *securityTestConnector) OpenTCP(context.Context, domain.Destination) (net.Conn, error) {
	if c.upstream == nil {
		return nil, errors.New("security test upstream already used")
	}
	upstream := c.upstream
	c.upstream = nil
	return upstream, nil
}
func (c *securityTestConnector) OpenUDP(context.Context) (net.PacketConn, error) {
	return nil, errors.New("security test connector has no UDP upstream")
}
func (c *securityTestConnector) Resolve(context.Context, string) ([]net.IP, error) {
	return nil, errors.New("security test connector has no resolver")
}

func daemonTestConfig() config.Config {
	return config.Config{
		Listeners: []config.ListenerConfig{{ID: "local", Protocol: "http", Host: "127.0.0.1", Port: 1080, Profile: "test"}},
		Profiles:  []config.ProfileConfig{{ID: "test", Backend: "fake"}},
	}
}

func TestDaemonShutdownClosesActiveConnectionsAfterDeadline(t *testing.T) {
	cfg := daemonTestConfig()
	cfg.ShutdownTimeout = "100ms"
	daemon, err := New(cfg, func(context.Context, config.ProfileConfig) (egress.Connector, error) {
		return daemonTestConnector{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	daemon.SetListenFunc(func(string, string) (net.Listener, error) {
		return net.Listen("tcp4", "127.0.0.1:0")
	})
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	address := daemon.Addresses()[0].String()
	client, err := net.Dial("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	deadline := time.Now().Add(time.Second)
	for {
		daemon.mu.Lock()
		active := len(daemon.connections)
		daemon.mu.Unlock()
		if active > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("client connection was not accepted")
		}
		time.Sleep(time.Millisecond)
	}

	if err := daemon.Shutdown(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown() error = %v, want deadline exceeded after active connection", err)
	}
	if len(daemon.Addresses()) != 1 {
		t.Fatal("listener addresses should remain inspectable after shutdown")
	}
}

func TestDaemonShutdownIsCleanWhenIdle(t *testing.T) {
	daemon, err := New(daemonTestConfig(), func(context.Context, config.ProfileConfig) (egress.Connector, error) {
		return daemonTestConnector{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	daemon.SetListenFunc(func(string, string) (net.Listener, error) {
		return net.Listen("tcp4", "127.0.0.1:0")
	})
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := daemon.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDaemonSecuresPublicListenerWithTLSAuthAndACL(t *testing.T) {
	t.Setenv("VPNFRONT_TEST_PASSWORD", "secret")
	certFile, keyFile := writeTestCertificate(t)
	upstreamClient, upstreamServer := net.Pipe()
	connector := &securityTestConnector{upstream: upstreamClient}
	cfg := daemonTestConfig()
	listener := &cfg.Listeners[0]
	listener.Host = "0.0.0.0"
	listener.TLS = &config.TLSConfig{CertFile: certFile, KeyFile: keyFile}
	listener.Auth = config.AuthConfig{Type: "basic", Username: "proxy", PasswordEnv: "VPNFRONT_TEST_PASSWORD"}
	listener.ACL = config.ACLConfig{DefaultAction: "deny", SourceCIDRs: []string{"127.0.0.0/8"}, AllowCIDRs: []string{"198.51.100.0/24"}}

	daemon, err := New(cfg, func(context.Context, config.ProfileConfig) (egress.Connector, error) {
		return connector, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	daemon.SetListenFunc(func(string, string) (net.Listener, error) {
		return net.Listen("tcp4", "127.0.0.1:0")
	})
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = daemon.Shutdown(context.Background()) }()

	tlsClient, err := tls.Dial("tcp4", daemon.Addresses()[0].String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tlsClient.Close() }()
	credentials := base64.StdEncoding.EncodeToString([]byte("proxy:secret"))
	request := "GET http://198.51.100.10/ HTTP/1.1\r\nHost: 198.51.100.10\r\nProxy-Authorization: Basic " + credentials + "\r\n\r\n"
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := tlsClient.Write([]byte(request))
		writeDone <- writeErr
	}()
	upstreamRequest, err := http.ReadRequest(bufio.NewReader(upstreamServer))
	if err != nil {
		t.Fatal(err)
	}
	if upstreamRequest.Host != "198.51.100.10" {
		t.Fatalf("upstream host = %q", upstreamRequest.Host)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	_, _ = upstreamServer.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
	_ = upstreamServer.Close()
	response, err := http.ReadResponse(bufio.NewReader(tlsClient), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("response body = %q", body)
	}
}

func writeTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certFile := directory + "/server.crt"
	keyFile := directory + "/server.key"
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
