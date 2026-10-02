package gateway

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
)

func TestGatewayLoadRelaysConcurrentHTTPConnects(t *testing.T) {
	const clients = 32
	echoListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echoListener.Close() }()
	go func() {
		for {
			connection, acceptErr := echoListener.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				_, _ = io.Copy(conn, conn)
				_ = conn.Close()
			}(connection)
		}
	}()
	gateway := New(&fakeConnector{openTCP: func(context.Context, domain.Destination) (net.Conn, error) {
		return net.Dial("tcp4", echoListener.Addr().String())
	}})
	var wait sync.WaitGroup
	wait.Add(clients)
	for index := 0; index < clients; index++ {
		go func(index int) {
			defer wait.Done()
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()
			done := make(chan error, 1)
			go func() {
				done <- gateway.ServeHTTP(context.Background(), server)
			}()
			request := "CONNECT load.example:" + portText(9000+index) + " HTTP/1.1\r\nHost: load.example\r\n\r\n"
			if _, err := client.Write([]byte(request)); err != nil {
				t.Errorf("client %d request: %v", index, err)
				return
			}
			if response := readHTTPHeaders(t, bufio.NewReader(client)); !strings.HasPrefix(response, "HTTP/1.1 200") {
				t.Errorf("client %d response = %q", index, response)
				return
			}
			payload := []byte("load-payload")
			go func() { _, _ = client.Write(payload) }()
			if got := readN(t, client, len(payload)); string(got) != string(payload) {
				t.Errorf("client %d response payload = %q", index, got)
			}
			_ = client.Close()
			<-done
		}(index)
	}
	waitDone := make(chan struct{})
	go func() { wait.Wait(); close(waitDone) }()
	select {
	case <-waitDone:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent gateway load did not complete")
	}
}

func TestGatewayFailureNeverFallsBackToDirectEgress(t *testing.T) {
	var opens atomic.Int32
	gateway := New(&fakeConnector{openTCP: func(context.Context, domain.Destination) (net.Conn, error) {
		opens.Add(1)
		return nil, egress.NewError(egress.FailureNetworkUnreachable, errors.New("test tunnel unavailable"))
	}})
	const clients = 16
	var wait sync.WaitGroup
	wait.Add(clients)
	for index := 0; index < clients; index++ {
		go func() {
			defer wait.Done()
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()
			done := make(chan error, 1)
			go func() { done <- gateway.ServeHTTP(context.Background(), server) }()
			_, _ = client.Write([]byte("CONNECT unavailable.example:443 HTTP/1.1\r\nHost: unavailable.example:443\r\n\r\n"))
			response := readHTTPHeaders(t, bufio.NewReader(client))
			if !strings.HasPrefix(response, "HTTP/1.1 502 Bad Gateway") {
				t.Errorf("failure response = %q", response)
			}
			_ = client.Close()
			<-done
		}()
	}
	wait.Wait()
	if got := opens.Load(); got != clients {
		t.Fatalf("connector opens = %d, want %d; direct fallback may have occurred", got, clients)
	}
}

func portText(port int) string {
	return strconv.Itoa(port)
}
