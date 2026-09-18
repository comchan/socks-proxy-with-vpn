package sshbackend

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
)

func TestOpenTCPUsesSSHDirectTCPIPAndRemoteHostname(t *testing.T) {
	server := newTestSSHServer(t)
	connector, err := New(context.Background(), server.profile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connector.Close() }()

	echoHost, echoPort, err := net.SplitHostPort(server.echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	port := mustPort(t, echoPort)
	connection, err := connector.OpenTCP(context.Background(), domain.Destination{Host: "localhost", Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	if echoHost != "127.0.0.1" {
		t.Fatalf("test echo host = %q", echoHost)
	}
	if _, err := connection.Write([]byte("through-ssh")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, len("through-ssh"))
	if _, err := io.ReadFull(connection, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "through-ssh" {
		t.Fatalf("echo response = %q", data)
	}
}

func TestNewRejectsStrictHostKeyMismatch(t *testing.T) {
	server := newTestSSHServer(t)
	wrongKey, _ := mustRSASigner(t)
	writeKnownHosts(t, server.knownHosts, server.listener.Addr().String(), wrongKey)
	if _, err := New(context.Background(), server.profile); err == nil {
		t.Fatal("host-key mismatch should fail connector construction")
	}
}

func TestNewRequiresKnownHostsFile(t *testing.T) {
	server := newTestSSHServer(t)
	server.profile.KnownHostsPath = ""
	if _, err := New(context.Background(), server.profile); err == nil {
		t.Fatal("missing known_hosts path should fail connector construction")
	}
}

func TestOpenUDPReturnsExplicitUnsupportedError(t *testing.T) {
	connector := &Connector{}
	_, err := connector.OpenUDP(context.Background())
	if !errors.Is(err, ErrUDPUnsupported) {
		t.Fatalf("OpenUDP() error = %v, want ErrUDPUnsupported", err)
	}
	if egress.KindOf(err) != egress.FailureCommandNotSupported {
		t.Fatalf("OpenUDP() error kind = %v, want command unsupported", egress.KindOf(err))
	}
}

func TestOpenTCPHonorsCanceledContext(t *testing.T) {
	server := newTestSSHServer(t)
	connector, err := New(context.Background(), server.profile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connector.Close() }()
	_, portText, err := net.SplitHostPort(server.echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = connector.OpenTCP(ctx, domain.Destination{Host: "localhost", Port: mustPort(t, portText)})
	if err == nil {
		t.Fatal("canceled context should fail OpenTCP")
	}
}

func mustPort(t *testing.T, value string) uint16 {
	t.Helper()
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil || port == 0 {
		t.Fatalf("invalid test port %q", value)
	}
	return uint16(port)
}
