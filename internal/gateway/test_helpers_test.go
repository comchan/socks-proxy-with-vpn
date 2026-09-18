package gateway

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
)

type fakeConnector struct {
	openTCP func(context.Context, domain.Destination) (net.Conn, error)
	openUDP func(context.Context) (net.PacketConn, error)
	resolve func(context.Context, string) ([]net.IP, error)
}

func (f *fakeConnector) OpenTCP(ctx context.Context, destination domain.Destination) (net.Conn, error) {
	if f.openTCP == nil {
		return nil, errors.New("fake TCP egress is not configured")
	}
	return f.openTCP(ctx, destination)
}

func (f *fakeConnector) OpenUDP(ctx context.Context) (net.PacketConn, error) {
	if f.openUDP == nil {
		return nil, errors.New("fake UDP egress is not configured")
	}
	return f.openUDP(ctx)
}

func (f *fakeConnector) Resolve(ctx context.Context, hostname string) ([]net.IP, error) {
	if f.resolve == nil {
		return nil, errors.New("fake resolver is not configured")
	}
	return f.resolve(ctx, hostname)
}

func readHTTPHeaders(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	var headers string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read HTTP header: %v", err)
		}
		headers += line
		if line == "\r\n" {
			return headers
		}
	}
}

func readN(t *testing.T, reader io.Reader, size int) []byte {
	t.Helper()
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		t.Fatalf("read %d bytes: %v", size, err)
	}
	return data
}

func servePipe(t *testing.T, serve func(net.Conn) error) (net.Conn, <-chan error) {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- serve(server)
		_ = server.Close()
	}()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, done
}
