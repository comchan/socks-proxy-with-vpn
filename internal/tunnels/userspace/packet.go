package userspace

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

type packetResult struct {
	data []byte
	addr net.Addr
	err  error
}

type dualPacketConn struct {
	connections []net.PacketConn
	results     chan packetResult
	done        chan struct{}
	closeOnce   sync.Once
}

func newPacketConn(tnet *netstack.Net, addresses []netip.Addr) (net.PacketConn, error) {
	if tnet == nil || len(addresses) == 0 {
		return nil, errors.New("userspace UDP socket requires a tunnel address")
	}
	var v4, v6 net.PacketConn
	for _, address := range addresses {
		if address.Is4() && v4 == nil {
			connection, err := tnet.ListenUDP(&net.UDPAddr{IP: address.AsSlice()})
			if err != nil {
				return nil, err
			}
			v4 = connection
		}
		if address.Is6() && v6 == nil {
			connection, err := tnet.ListenUDP(&net.UDPAddr{IP: address.AsSlice()})
			if err != nil {
				if v4 != nil {
					_ = v4.Close()
				}
				return nil, err
			}
			v6 = connection
		}
	}
	connections := make([]net.PacketConn, 0, 2)
	if v4 != nil {
		connections = append(connections, v4)
	}
	if v6 != nil {
		connections = append(connections, v6)
	}
	if len(connections) == 1 {
		return connections[0], nil
	}
	result := &dualPacketConn{
		connections: connections,
		results:     make(chan packetResult, len(connections)),
		done:        make(chan struct{}),
	}
	for _, connection := range connections {
		go result.readLoop(connection)
	}
	return result, nil
}

func (c *dualPacketConn) readLoop(connection net.PacketConn) {
	for {
		buffer := make([]byte, 64*1024)
		n, address, err := connection.ReadFrom(buffer)
		result := packetResult{data: buffer[:n], addr: address, err: err}
		select {
		case c.results <- result:
		case <-c.done:
			return
		}
		if err != nil {
			return
		}
	}
}

func (c *dualPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	select {
	case result := <-c.results:
		if len(result.data) > len(buffer) {
			copy(buffer, result.data[:len(buffer)])
			return len(buffer), result.addr, result.err
		}
		copy(buffer, result.data)
		return len(result.data), result.addr, result.err
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}

func (c *dualPacketConn) WriteTo(buffer []byte, address net.Addr) (int, error) {
	udpAddress, ok := address.(*net.UDPAddr)
	if !ok || udpAddress.IP == nil {
		return 0, errors.New("userspace UDP destination must be a UDP address")
	}
	for _, connection := range c.connections {
		local := connection.LocalAddr().(*net.UDPAddr)
		if (udpAddress.IP.To4() != nil) == (local.IP.To4() != nil) {
			return connection.WriteTo(buffer, address)
		}
	}
	return 0, errors.New("userspace UDP destination has no matching address family")
}

func (c *dualPacketConn) Close() error {
	var firstErr error
	c.closeOnce.Do(func() {
		close(c.done)
		for _, connection := range c.connections {
			if err := connection.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	})
	return firstErr
}

func (c *dualPacketConn) LocalAddr() net.Addr {
	if len(c.connections) == 0 {
		return &net.UDPAddr{}
	}
	return c.connections[0].LocalAddr()
}

func (c *dualPacketConn) SetDeadline(deadline time.Time) error {
	var firstErr error
	for _, connection := range c.connections {
		if err := connection.SetDeadline(deadline); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *dualPacketConn) SetReadDeadline(deadline time.Time) error {
	var firstErr error
	for _, connection := range c.connections {
		if err := connection.SetReadDeadline(deadline); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *dualPacketConn) SetWriteDeadline(deadline time.Time) error {
	var firstErr error
	for _, connection := range c.connections {
		if err := connection.SetWriteDeadline(deadline); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
