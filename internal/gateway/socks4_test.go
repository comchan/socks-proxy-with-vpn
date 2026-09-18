package gateway

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
)

func TestServeSOCKS4Connect(t *testing.T) {
	var got domain.Destination
	upstreamClient, upstreamServer := net.Pipe()
	gateway := New(&fakeConnector{
		openTCP: func(_ context.Context, destination domain.Destination) (net.Conn, error) {
			got = destination
			return upstreamClient, nil
		},
	})
	client, done := servePipe(t, func(conn net.Conn) error {
		return gateway.ServeSOCKS4(context.Background(), conn)
	})
	t.Cleanup(func() { _ = upstreamServer.Close() })

	request := []byte{0x04, 0x01, 0, 80, 192, 0, 2, 10}
	request = append(request, []byte("user")...)
	request = append(request, 0)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := readN(t, client, 8)
	if reply[1] != socks4Granted {
		t.Fatalf("SOCKS4 reply = %x", reply)
	}
	if got.Host != "192.0.2.10" || got.Port != 80 {
		t.Fatalf("destination = %+v", got)
	}
	_ = client.Close()
	_ = upstreamServer.Close()
	<-done
}

func TestServeSOCKS4aPreservesHostname(t *testing.T) {
	var got domain.Destination
	upstreamClient, upstreamServer := net.Pipe()
	gateway := New(&fakeConnector{
		openTCP: func(_ context.Context, destination domain.Destination) (net.Conn, error) {
			got = destination
			return upstreamClient, nil
		},
	})
	client, done := servePipe(t, func(conn net.Conn) error {
		return gateway.ServeSOCKS4(context.Background(), conn)
	})

	request := []byte{0x04, 0x01, 0x01, 0xbb, 0, 0, 0, 1}
	request = append(request, 0)
	request = append(request, []byte("service.internal")...)
	request = append(request, 0)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := readN(t, client, 8)
	if reply[1] != socks4Granted {
		t.Fatalf("SOCKS4a reply = %x", reply)
	}
	if got.Host != "service.internal" || got.Port != 443 {
		t.Fatalf("destination = %+v", got)
	}
	_ = client.Close()
	_ = upstreamServer.Close()
	<-done
}

func TestServeSOCKS4RejectsUnsupportedCommand(t *testing.T) {
	gateway := New(&fakeConnector{})
	client, done := servePipe(t, func(conn net.Conn) error {
		return gateway.ServeSOCKS4(context.Background(), conn)
	})
	request := []byte{0x04, 0x02, 0, 80, 192, 0, 2, 10, 0}
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := readN(t, client, 8)
	if reply[1] != socks4Rejected {
		t.Fatalf("SOCKS4 reply = %x", reply)
	}
	_ = client.Close()
	if err := <-done; err == nil {
		t.Fatal("unsupported command should return an error")
	}
}

func TestSOCKS4PortEncodingFixture(t *testing.T) {
	request := make([]byte, 2)
	binary.BigEndian.PutUint16(request, 0x1234)
	if request[0] != 0x12 || request[1] != 0x34 {
		t.Fatalf("unexpected big-endian port fixture: %x", request)
	}
}
