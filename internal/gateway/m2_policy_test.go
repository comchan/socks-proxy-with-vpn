package gateway

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/policy"
)

func TestServeHTTPRequiresProxyAuthentication(t *testing.T) {
	t.Setenv("VPNFRONT_TEST_PASSWORD", "secret")
	auth, err := policy.NewAuthenticator(config.AuthConfig{Type: "basic", Username: "proxy", PasswordEnv: "VPNFRONT_TEST_PASSWORD"})
	if err != nil {
		t.Fatal(err)
	}
	gateway := New(&fakeConnector{})
	gateway.Authenticator = auth
	client, done := servePipe(t, func(conn net.Conn) error {
		return gateway.ServeHTTP(context.Background(), conn)
	})
	if _, err := client.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	response := readHTTPHeaders(t, bufio.NewReader(client))
	if !strings.HasPrefix(response, "HTTP/1.1 407 Proxy Authentication Required") || !strings.Contains(response, "Proxy-Authenticate: Basic") {
		t.Fatalf("response = %q", response)
	}
	_ = client.Close()
	if err := <-done; err == nil {
		t.Fatal("authentication failure should return an error")
	}
}

func TestServeHTTPRejectsACLBlockedDestination(t *testing.T) {
	acl, err := policy.NewACL(config.ACLConfig{DefaultAction: "deny", AllowCIDRs: []string{"198.51.100.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	gateway := New(&fakeConnector{openTCP: func(context.Context, domain.Destination) (net.Conn, error) {
		called = true
		return nil, errors.New("should not dial")
	}})
	gateway.DestinationACL = acl
	client, done := servePipe(t, func(conn net.Conn) error {
		return gateway.ServeHTTP(context.Background(), conn)
	})
	if _, err := client.Write([]byte("CONNECT 203.0.113.10:443 HTTP/1.1\r\nHost: 203.0.113.10:443\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	response := readHTTPHeaders(t, bufio.NewReader(client))
	if !strings.HasPrefix(response, "HTTP/1.1 403 Forbidden") {
		t.Fatalf("response = %q", response)
	}
	if called {
		t.Fatal("ACL-blocked destination reached the connector")
	}
	_ = client.Close()
	if err := <-done; err == nil {
		t.Fatal("ACL rejection should return an error")
	}
}

func TestServeSOCKS5RequiresUsernamePasswordAuthentication(t *testing.T) {
	t.Setenv("VPNFRONT_TEST_PASSWORD", "secret")
	auth, err := policy.NewAuthenticator(config.AuthConfig{Type: "basic", Username: "proxy", PasswordEnv: "VPNFRONT_TEST_PASSWORD"})
	if err != nil {
		t.Fatal(err)
	}
	gateway := New(&fakeConnector{})
	gateway.Authenticator = auth
	client, done := servePipe(t, func(conn net.Conn) error {
		return gateway.ServeSOCKS5(context.Background(), conn)
	})
	if _, err := client.Write([]byte{socks5Version, 0x02, socks5NoAuth, socks5UsernamePassword}); err != nil {
		t.Fatal(err)
	}
	if response := readN(t, client, 2); response[0] != socks5Version || response[1] != socks5UsernamePassword {
		t.Fatalf("method response = %x", response)
	}
	userPass := append([]byte{0x01, byte(len("proxy"))}, []byte("proxy")...)
	userPass = append(userPass, byte(len("secret")))
	userPass = append(userPass, []byte("secret")...)
	if _, err := client.Write(userPass); err != nil {
		t.Fatal(err)
	}
	if response := readN(t, client, 2); response[0] != 0x01 || response[1] != 0x00 {
		t.Fatalf("authentication response = %x", response)
	}
	if _, err := client.Write([]byte{socks5Version, 0x02, 0, socks5IPv4, 127, 0, 0, 1, 0, 80}); err != nil {
		t.Fatal(err)
	}
	if response := readN(t, client, 10); response[1] != socks5CommandUnsupported {
		t.Fatalf("post-authentication BIND response = %x", response)
	}
	_ = client.Close()
	if err := <-done; err == nil {
		t.Fatal("BIND should still return an error after authentication")
	}
}
