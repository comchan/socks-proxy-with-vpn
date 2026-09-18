package gateway

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
)

func TestServeHTTPConnectRelaysBidirectionally(t *testing.T) {
	var got domain.Destination
	upstreamClient, upstreamServer := net.Pipe()
	connector := &fakeConnector{
		openTCP: func(_ context.Context, destination domain.Destination) (net.Conn, error) {
			got = destination
			return upstreamClient, nil
		},
	}
	gateway := New(connector)
	client, done := servePipe(t, func(conn net.Conn) error {
		return gateway.ServeHTTP(context.Background(), conn)
	})
	t.Cleanup(func() { _ = upstreamServer.Close() })

	if _, err := client.Write([]byte("CONNECT example.internal:8443 HTTP/1.1\r\nHost: example.internal:8443\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	response := readHTTPHeaders(t, bufio.NewReader(client))
	if !strings.HasPrefix(response, "HTTP/1.1 200 Connection Established") {
		t.Fatalf("CONNECT response = %q", response)
	}
	if got.Host != "example.internal" || got.Port != 8443 {
		t.Fatalf("destination = %+v", got)
	}

	if _, err := client.Write([]byte("client-to-server")); err != nil {
		t.Fatal(err)
	}
	if gotBytes := readN(t, upstreamServer, len("client-to-server")); string(gotBytes) != "client-to-server" {
		t.Fatalf("upstream request = %q", gotBytes)
	}
	if _, err := upstreamServer.Write([]byte("server-to-client")); err != nil {
		t.Fatal(err)
	}
	if gotBytes := readN(t, client, len("server-to-client")); string(gotBytes) != "server-to-client" {
		t.Fatalf("client response = %q", gotBytes)
	}
	_ = client.Close()
	_ = upstreamServer.Close()
	<-done
}

func TestServeHTTPForwardRequestUsesOriginForm(t *testing.T) {
	var got domain.Destination
	upstreamClient, upstreamServer := net.Pipe()
	connector := &fakeConnector{
		openTCP: func(_ context.Context, destination domain.Destination) (net.Conn, error) {
			got = destination
			return upstreamClient, nil
		},
	}
	gateway := New(connector)
	client, done := servePipe(t, func(conn net.Conn) error {
		return gateway.ServeHTTP(context.Background(), conn)
	})
	t.Cleanup(func() { _ = upstreamServer.Close() })

	request := "GET http://origin.example:8080/path?q=1 HTTP/1.1\r\nHost: origin.example:8080\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic cHJveHk6c2VjcmV0\r\n\r\n"
	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}

	upstreamRequest, err := http.ReadRequest(bufio.NewReader(upstreamServer))
	if err != nil {
		t.Fatalf("read upstream request: %v", err)
	}
	if upstreamRequest.RequestURI != "/path?q=1" {
		t.Fatalf("upstream RequestURI = %q", upstreamRequest.RequestURI)
	}
	if upstreamRequest.Host != "origin.example:8080" {
		t.Fatalf("upstream Host = %q", upstreamRequest.Host)
	}
	if upstreamRequest.Header.Get("Proxy-Connection") != "" {
		t.Fatal("Proxy-Connection header was forwarded")
	}
	if upstreamRequest.Header.Get("Proxy-Authorization") != "" {
		t.Fatal("Proxy-Authorization header was forwarded")
	}
	if !upstreamRequest.Close {
		t.Fatal("upstream request should close after one M1 request")
	}
	if got.Host != "origin.example" || got.Port != 8080 {
		t.Fatalf("destination = %+v", got)
	}

	_, _ = io.WriteString(upstreamServer, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
	_ = upstreamServer.Close()
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read client response body: %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("response body = %q", body)
	}
	_ = client.Close()
	<-done
}

func TestServeHTTPRejectsInvalidConnectDestination(t *testing.T) {
	gateway := New(&fakeConnector{})
	client, done := servePipe(t, func(conn net.Conn) error {
		return gateway.ServeHTTP(context.Background(), conn)
	})
	if _, err := client.Write([]byte("CONNECT missing-port HTTP/1.1\r\nHost: missing-port\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	response := readHTTPHeaders(t, bufio.NewReader(client))
	if !strings.HasPrefix(response, "HTTP/1.1 400 Bad Request") {
		t.Fatalf("response = %q", response)
	}
	_ = client.Close()
	if err := <-done; err == nil {
		t.Fatal("invalid CONNECT should return an error")
	}
}
