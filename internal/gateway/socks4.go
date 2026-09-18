package gateway

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
)

const (
	socks4Version      = 0x04
	socks4Connect      = 0x01
	socks4Granted      = 0x5a
	socks4Rejected     = 0x5b
	maxHandshakeString = 255
)

// ServeSOCKS4 handles one SOCKS4 or SOCKS4a request on conn.
func (g *Gateway) ServeSOCKS4(ctx context.Context, conn net.Conn) error {
	reader := bufio.NewReader(conn)
	header := make([]byte, 8)
	if _, err := io.ReadFull(reader, header); err != nil {
		return protocolError("read SOCKS4 request", err)
	}
	if header[0] != socks4Version {
		_ = writeSOCKS4Reply(conn, socks4Rejected)
		return fmt.Errorf("unsupported SOCKS4 version %d", header[0])
	}

	userID, err := readCString(reader, maxHandshakeString)
	if err != nil {
		_ = writeSOCKS4Reply(conn, socks4Rejected)
		return protocolError("read SOCKS4 user ID", err)
	}
	_ = userID // Authentication is introduced in M2.
	if header[1] != socks4Connect {
		_ = writeSOCKS4Reply(conn, socks4Rejected)
		return fmt.Errorf("unsupported SOCKS4 command %d", header[1])
	}
	port := binary.BigEndian.Uint16(header[2:4])
	if port == 0 {
		_ = writeSOCKS4Reply(conn, socks4Rejected)
		return fmt.Errorf("SOCKS4 destination port is zero")
	}

	host := net.IP(header[4:8]).String()
	if header[4] == 0 && header[5] == 0 && header[6] == 0 && header[7] != 0 {
		host, err = readCString(reader, maxHandshakeString)
		if err != nil {
			_ = writeSOCKS4Reply(conn, socks4Rejected)
			return protocolError("read SOCKS4a hostname", err)
		}
	}
	destination := domain.Destination{Host: host, Port: port}
	upstream, err := g.openTCP(ctx, destination)
	if err != nil {
		_ = writeSOCKS4Reply(conn, socks4Rejected)
		return protocolError("open SOCKS4 egress", err)
	}
	defer func() { _ = upstream.Close() }()

	if err := writeSOCKS4Reply(conn, socks4Granted); err != nil {
		return protocolError("write SOCKS4 success reply", err)
	}
	return Relay(ctx, wrapBuffered(conn, reader), upstream)
}

func readCString(reader *bufio.Reader, max int) (string, error) {
	value := make([]byte, 0, minInt(max, 32))
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		if b == 0 {
			return string(value), nil
		}
		if len(value) >= max {
			return "", fmt.Errorf("NUL-terminated field exceeds %d bytes", max)
		}
		value = append(value, b)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func writeSOCKS4Reply(conn net.Conn, code byte) error {
	return writeFull(conn, []byte{0x00, code, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}
