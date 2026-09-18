package gateway

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
)

type UDPBindFunc func(network string, address *net.UDPAddr) (net.PacketConn, error)

type Gateway struct {
	Connector egress.Connector
	UDPBind   UDPBindFunc
}

func New(connector egress.Connector) *Gateway {
	return &Gateway{
		Connector: connector,
		UDPBind:   defaultUDPBind,
	}
}

func defaultUDPBind(network string, address *net.UDPAddr) (net.PacketConn, error) {
	return net.ListenUDP(network, address)
}

func (g *Gateway) openTCP(ctx context.Context, destination domain.Destination) (net.Conn, error) {
	if g == nil || g.Connector == nil {
		return nil, egress.NewError(egress.FailureGeneral, errors.New("egress connector is not configured"))
	}
	return g.Connector.OpenTCP(ctx, destination)
}

func (g *Gateway) openUDP(ctx context.Context) (net.PacketConn, error) {
	if g == nil || g.Connector == nil {
		return nil, egress.NewError(egress.FailureGeneral, errors.New("egress connector is not configured"))
	}
	return g.Connector.OpenUDP(ctx)
}

type bufferedConn struct {
	reader *bufio.Reader
	conn   net.Conn
}

func (c *bufferedConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *bufferedConn) Write(p []byte) (int, error) { return c.conn.Write(p) }
func (c *bufferedConn) Close() error                { return c.conn.Close() }

func (c *bufferedConn) CloseWrite() error {
	if closer, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return nil
}

func wrapBuffered(conn net.Conn, reader *bufio.Reader) *bufferedConn {
	return &bufferedConn{reader: reader, conn: conn}
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := w.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func protocolError(name string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", name, err)
}
