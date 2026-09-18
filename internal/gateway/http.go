package gateway

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
)

// ServeHTTP handles one HTTP proxy request on conn. A connection is closed by
// the caller after this method returns.
func (g *Gateway) ServeHTTP(ctx context.Context, conn net.Conn) error {
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return protocolError("read HTTP proxy request", err)
	}

	if strings.EqualFold(request.Method, http.MethodConnect) {
		return g.serveConnect(ctx, conn, reader, request)
	}
	return g.serveForward(ctx, conn, request)
}

func (g *Gateway) serveConnect(ctx context.Context, client net.Conn, reader *bufio.Reader, request *http.Request) error {
	destination, err := domain.ParseAddress(request.Host)
	if err != nil {
		_ = writeHTTPError(client, http.StatusBadRequest, "invalid CONNECT destination")
		return protocolError("parse CONNECT destination", err)
	}

	upstream, err := g.openTCP(ctx, destination)
	if err != nil {
		_ = writeHTTPGatewayError(client, err)
		return protocolError("open CONNECT egress", err)
	}
	defer func() { _ = upstream.Close() }()

	if err := writeFull(client, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return protocolError("write CONNECT response", err)
	}
	return Relay(ctx, wrapBuffered(client, reader), upstream)
}

func (g *Gateway) serveForward(ctx context.Context, client net.Conn, request *http.Request) error {
	rawTarget := request.URL.Host
	if rawTarget == "" {
		rawTarget = request.Host
	}
	defaultPort := uint16(80)
	if strings.EqualFold(request.URL.Scheme, "https") {
		defaultPort = 443
	}
	destination, err := domain.ParseHostPort(rawTarget, defaultPort)
	if err != nil {
		_ = writeHTTPError(client, http.StatusBadRequest, "invalid proxy destination")
		return protocolError("parse HTTP destination", err)
	}

	upstream, err := g.openTCP(ctx, destination)
	if err != nil {
		_ = writeHTTPGatewayError(client, err)
		return protocolError("open HTTP egress", err)
	}
	defer func() { _ = upstream.Close() }()

	// Send origin-form to the destination server, never proxy-form. Closing the
	// upstream after one request keeps M1's request lifecycle deterministic.
	request.URL.Scheme = ""
	request.URL.Host = ""
	request.RequestURI = ""
	request.Close = true
	request.Header.Del("Proxy-Connection")
	request.Header.Set("Connection", "close")
	if err := request.Write(upstream); err != nil {
		return protocolError("write HTTP upstream request", err)
	}
	if _, err := io.Copy(client, upstream); err != nil {
		return protocolError("copy HTTP upstream response", err)
	}
	return nil
}

func writeHTTPError(conn net.Conn, status int, message string) error {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(message), message)
	return writeFull(conn, []byte(response))
}

func writeHTTPGatewayError(conn net.Conn, err error) error {
	status := http.StatusBadGateway
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		status = http.StatusGatewayTimeout
	}
	if typed, ok := err.(*egress.Error); ok && typed.Kind == egress.FailureHostUnreachable {
		status = http.StatusGatewayTimeout
	}
	return writeHTTPError(conn, status, http.StatusText(status))
}
