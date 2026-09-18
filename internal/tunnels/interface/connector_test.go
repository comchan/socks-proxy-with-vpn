package interfacebackend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
)

func attachedProfile(backend string) config.ProfileConfig {
	return config.ProfileConfig{ID: backend, Backend: backend, Mode: "attached-interface", LocalAddress: "127.0.0.1"}
}

func TestAttachedConnectorBindsTCPAndUDPToConfiguredAddress(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		_, _ = io.Copy(connection, connection)
		_ = connection.Close()
	}()

	connector, err := New(context.Background(), attachedProfile("wireguard"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connector.Close() }()
	status := connector.Status()
	if status.Backend != "wireguard" || !status.LocalAddress.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("status = %+v", status)
	}

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port := mustAttachedPort(t, portText)
	connection, err := connector.OpenTCP(context.Background(), domain.Destination{Host: host, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if !connection.LocalAddr().(*net.TCPAddr).IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("TCP local address = %v", connection.LocalAddr())
	}
	if _, err := connection.Write([]byte("attached-tcp")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("attached-tcp"))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if string(response) != "attached-tcp" {
		t.Fatalf("TCP response = %q", response)
	}

	packet, err := connector.OpenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = packet.Close() }()
	if !packet.LocalAddr().(*net.UDPAddr).IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("UDP local address = %v", packet.LocalAddr())
	}
}

func TestAttachedConnectorFailsClosedWhenInterfaceIsUnavailable(t *testing.T) {
	profile := attachedProfile("openvpn")
	profile.LocalAddress = ""
	profile.Interface = "vpnfront-interface-that-does-not-exist"
	_, err := New(context.Background(), profile)
	if !errors.Is(err, ErrInterfaceUnavailable) {
		t.Fatalf("error = %v, want ErrInterfaceUnavailable", err)
	}
}

func TestAttachedConnectorFailsClosedWithoutInterfaceOrAddress(t *testing.T) {
	_, err := New(context.Background(), attachedProfile("wireguard"))
	// attachedProfile supplies LocalAddress, so remove it for this validation.
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(context.Background(), config.ProfileConfig{Backend: "wireguard", Mode: "attached-interface"})
	if !errors.Is(err, ErrInterfaceUnavailable) {
		t.Fatalf("error = %v, want ErrInterfaceUnavailable", err)
	}
}

func TestAttachedConnectorDoesNotUseSystemDNSFallback(t *testing.T) {
	connector, err := New(context.Background(), attachedProfile("openvpn"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connector.Close() }()
	_, err = connector.Resolve(context.Background(), "example.com")
	if !errors.Is(err, ErrDNSNotConfigured) {
		t.Fatalf("Resolve() error = %v, want ErrDNSNotConfigured", err)
	}
	if egress.KindOf(err) != egress.FailureCommandNotSupported {
		t.Fatalf("Resolve() error kind = %v, want unsupported", egress.KindOf(err))
	}
}

func TestAttachedConnectorRejectsUseAfterClose(t *testing.T) {
	connector, err := New(context.Background(), attachedProfile("wireguard"))
	if err != nil {
		t.Fatal(err)
	}
	if err := connector.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = connector.OpenTCP(context.Background(), domain.Destination{Host: "127.0.0.1", Port: 1})
	if err == nil {
		t.Fatal("closed connector should reject TCP")
	}
}

func mustAttachedPort(t *testing.T, value string) uint16 {
	t.Helper()
	var port uint16
	if _, err := fmt.Sscanf(value, "%d", &port); err != nil || port == 0 {
		t.Fatal(err)
	}
	return port
}
