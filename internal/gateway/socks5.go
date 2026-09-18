package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
)

const (
	socks5Version             = 0x05
	socks5NoAuth              = 0x00
	socks5UsernamePassword    = 0x02
	socks5NoAcceptableMethods = 0xff
	socks5Connect             = 0x01
	socks5UDPAssociate        = 0x03
	socks5Success             = 0x00
	socks5GeneralFailure      = 0x01
	socks5NetworkUnreachable  = 0x03
	socks5HostUnreachable     = 0x04
	socks5ConnectionRefused   = 0x05
	socks5TTLExpired          = 0x06
	socks5CommandUnsupported  = 0x07
	socks5AddressUnsupported  = 0x08

	socks5IPv4   = 0x01
	socks5Domain = 0x03
	socks5IPv6   = 0x04
)

var errUnsupportedAddressType = errors.New("SOCKS5 address type is not supported")

// ServeSOCKS5 handles one SOCKS5 request on conn. M1 accepts only the
// unauthenticated method; listener authentication is introduced in M2.
func (g *Gateway) ServeSOCKS5(ctx context.Context, conn net.Conn) error {
	reader := bufio.NewReader(conn)
	if err := negotiateSOCKS5(reader, conn, g.Authenticator); err != nil {
		return protocolError("SOCKS5 method negotiation", err)
	}

	request, err := readSOCKS5Request(reader)
	if err != nil {
		_ = writeSOCKS5Reply(conn, socks5ReplyForError(err), nil)
		return protocolError("read SOCKS5 request", err)
	}

	switch request.command {
	case socks5Connect:
		return g.serveSOCKS5Connect(ctx, conn, reader, request.destination)
	case socks5UDPAssociate:
		return g.serveSOCKS5UDPAssociate(ctx, conn, request.destination)
	default:
		_ = writeSOCKS5Reply(conn, socks5CommandUnsupported, nil)
		return fmt.Errorf("SOCKS5 command 0x%02x is not supported", request.command)
	}
}

func negotiateSOCKS5(reader *bufio.Reader, conn net.Conn, auth Authenticator) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if header[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}
	requiresAuth := auth != nil && auth.Required()
	for _, method := range methods {
		if requiresAuth && method == socks5UsernamePassword {
			if err := writeFull(conn, []byte{socks5Version, socks5UsernamePassword}); err != nil {
				return err
			}
			return authenticateSOCKS5UserPass(reader, conn, auth)
		}
		if !requiresAuth && method == socks5NoAuth {
			return writeFull(conn, []byte{socks5Version, socks5NoAuth})
		}
	}
	if err := writeFull(conn, []byte{socks5Version, socks5NoAcceptableMethods}); err != nil {
		return err
	}
	return errors.New("no acceptable SOCKS5 authentication method")
}

func authenticateSOCKS5UserPass(reader *bufio.Reader, conn net.Conn, auth Authenticator) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if header[0] != 0x01 || header[1] == 0 {
		_ = writeFull(conn, []byte{0x01, 0x01})
		return errors.New("invalid SOCKS5 username/password request")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, username); err != nil {
		return err
	}
	passwordLength, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if passwordLength == 0 {
		_ = writeFull(conn, []byte{0x01, 0x01})
		return errors.New("empty SOCKS5 password")
	}
	password := make([]byte, int(passwordLength))
	if _, err := io.ReadFull(reader, password); err != nil {
		return err
	}
	if !auth.AuthenticateSOCKS5(string(username), string(password)) {
		_ = writeFull(conn, []byte{0x01, 0x01})
		return errors.New("invalid SOCKS5 credentials")
	}
	if err := writeFull(conn, []byte{0x01, 0x00}); err != nil {
		return err
	}
	return nil
}

type socks5Request struct {
	command     byte
	destination domain.Destination
}

func readSOCKS5Request(reader *bufio.Reader) (socks5Request, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return socks5Request{}, err
	}
	if header[0] != socks5Version {
		return socks5Request{}, fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	if header[2] != 0 {
		return socks5Request{}, fmt.Errorf("SOCKS5 reserved byte is non-zero")
	}
	destination, err := readSOCKS5Destination(reader, header[3], header[1] == socks5UDPAssociate)
	if err != nil {
		return socks5Request{}, err
	}
	return socks5Request{command: header[1], destination: destination}, nil
}

func readSOCKS5Destination(reader *bufio.Reader, addressType byte, allowZeroPort bool) (domain.Destination, error) {
	var host string
	switch addressType {
	case socks5IPv4:
		address := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, address); err != nil {
			return domain.Destination{}, err
		}
		host = net.IP(address).String()
	case socks5Domain:
		length, err := reader.ReadByte()
		if err != nil {
			return domain.Destination{}, err
		}
		if length == 0 {
			return domain.Destination{}, errors.New("SOCKS5 domain is empty")
		}
		address := make([]byte, int(length))
		if _, err := io.ReadFull(reader, address); err != nil {
			return domain.Destination{}, err
		}
		host = string(address)
	case socks5IPv6:
		address := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(reader, address); err != nil {
			return domain.Destination{}, err
		}
		host = net.IP(address).String()
	default:
		return domain.Destination{}, egress.NewError(egress.FailureAddressTypeNotSupported, errUnsupportedAddressType)
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return domain.Destination{}, err
	}
	port := binary.BigEndian.Uint16(portBytes)
	if port == 0 && !allowZeroPort {
		return domain.Destination{}, errors.New("SOCKS5 destination port is zero")
	}
	return domain.Destination{Host: host, Port: port}, nil
}

func (g *Gateway) serveSOCKS5Connect(ctx context.Context, conn net.Conn, reader *bufio.Reader, destination domain.Destination) error {
	if !destination.Valid() {
		err := errors.New("SOCKS5 CONNECT destination is invalid")
		_ = writeSOCKS5Reply(conn, socks5GeneralFailure, nil)
		return err
	}
	if err := g.authorizeDestination(destination); err != nil {
		_ = writeSOCKS5Reply(conn, socks5ConnectionRefused, nil)
		return protocolError("authorize SOCKS5 destination", err)
	}
	upstream, err := g.openTCP(ctx, destination)
	if err != nil {
		_ = writeSOCKS5Reply(conn, socks5ReplyForError(err), nil)
		return protocolError("open SOCKS5 egress", err)
	}
	defer func() { _ = upstream.Close() }()

	if err := writeSOCKS5Reply(conn, socks5Success, upstream.LocalAddr()); err != nil {
		return protocolError("write SOCKS5 success reply", err)
	}
	return Relay(ctx, wrapBuffered(conn, reader), upstream)
}

func (g *Gateway) serveSOCKS5UDPAssociate(ctx context.Context, control net.Conn, requested domain.Destination) error {
	_ = requested // The server chooses the relay address; the requested target is advisory.
	bindAddress := udpBindAddress(control.LocalAddr())
	if g == nil || g.UDPBind == nil {
		_ = writeSOCKS5Reply(control, socks5GeneralFailure, nil)
		return errors.New("UDP relay binder is not configured")
	}
	relay, err := g.UDPBind("udp", bindAddress)
	if err != nil {
		_ = writeSOCKS5Reply(control, socks5ReplyForError(err), nil)
		return protocolError("bind SOCKS5 UDP relay", err)
	}
	defer func() { _ = relay.Close() }()

	egressConn, err := g.openUDP(ctx)
	if err != nil {
		_ = writeSOCKS5Reply(control, socks5ReplyForError(err), nil)
		return protocolError("open SOCKS5 UDP egress", err)
	}
	defer func() { _ = egressConn.Close() }()

	if err := writeSOCKS5Reply(control, socks5Success, relay.LocalAddr()); err != nil {
		return protocolError("write SOCKS5 UDP reply", err)
	}
	return g.relaySOCKS5UDP(ctx, control, relay, egressConn)
}

func udpBindAddress(local net.Addr) *net.UDPAddr {
	if address, ok := local.(*net.TCPAddr); ok {
		return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: 0, Zone: address.Zone}
	}
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

func (g *Gateway) relaySOCKS5UDP(ctx context.Context, control net.Conn, relay, egressConn net.PacketConn) error {
	associationCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	clientIP := tcpRemoteIP(control.RemoteAddr())
	var clients struct {
		sync.RWMutex
		address net.Addr
	}

	done := make(chan error, 4)
	go g.relayClientDatagrams(associationCtx, relay, egressConn, clientIP, &clients, done)
	go relayEgressDatagrams(associationCtx, relay, egressConn, &clients, done)
	go watchSOCKS5Control(control, done)
	go watchSOCKS5Context(associationCtx, done)

	firstErr := <-done
	parentCanceled := ctx.Err() != nil
	cancel()
	_ = relay.Close()
	_ = egressConn.Close()
	_ = control.Close()
	for remaining := 1; remaining < 4; remaining++ {
		<-done
	}
	if parentCanceled || errors.Is(firstErr, io.EOF) || errors.Is(firstErr, net.ErrClosed) || errors.Is(firstErr, context.Canceled) {
		return nil
	}
	return firstErr
}

func (g *Gateway) relayClientDatagrams(ctx context.Context, relay, egressConn net.PacketConn, clientIP net.IP, clients *struct {
	sync.RWMutex
	address net.Addr
}, done chan<- error) {
	buffer := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			done <- nil
			return
		default:
		}
		count, source, err := relay.ReadFrom(buffer)
		if err != nil {
			done <- err
			return
		}
		if !allowedUDPSource(source, clientIP) {
			continue
		}
		destination, payload, err := parseSOCKS5UDPDatagram(buffer[:count])
		if err != nil {
			// SOCKS5 UDP has no response channel for malformed datagrams.
			continue
		}
		if err := g.authorizeDestination(destination); err != nil {
			continue
		}
		address, err := g.resolveUDPAddress(ctx, destination)
		if err != nil {
			continue
		}
		clients.Lock()
		clients.address = source
		clients.Unlock()
		if _, err := egressConn.WriteTo(payload, address); err != nil {
			done <- err
			return
		}
	}
}

func relayEgressDatagrams(ctx context.Context, relay, egressConn net.PacketConn, clients *struct {
	sync.RWMutex
	address net.Addr
}, done chan<- error) {
	buffer := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			done <- nil
			return
		default:
		}
		count, source, err := egressConn.ReadFrom(buffer)
		if err != nil {
			done <- err
			return
		}
		clients.RLock()
		client := clients.address
		clients.RUnlock()
		if client == nil {
			continue
		}
		destination, err := destinationFromUDPAddr(source)
		if err != nil {
			continue
		}
		packet, err := encodeSOCKS5UDPDatagram(destination, buffer[:count])
		if err != nil {
			continue
		}
		if _, err := relay.WriteTo(packet, client); err != nil {
			done <- err
			return
		}
	}
}

func watchSOCKS5Control(control net.Conn, done chan<- error) {
	var one [1]byte
	_, err := control.Read(one[:])
	done <- err
}

func watchSOCKS5Context(ctx context.Context, done chan<- error) {
	<-ctx.Done()
	done <- ctx.Err()
}

func allowedUDPSource(source net.Addr, clientIP net.IP) bool {
	if len(clientIP) == 0 {
		return true
	}
	address, ok := source.(*net.UDPAddr)
	return ok && address.IP.Equal(clientIP)
}

func (g *Gateway) resolveUDPAddress(ctx context.Context, destination domain.Destination) (*net.UDPAddr, error) {
	if ip := net.ParseIP(destination.Host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: int(destination.Port)}, nil
	}
	if g == nil || g.Connector == nil {
		return nil, errors.New("egress resolver is not configured")
	}
	addresses, err := g.Connector.Resolve(ctx, destination.Host)
	if err != nil || len(addresses) == 0 {
		if err == nil {
			err = errors.New("hostname returned no addresses")
		}
		return nil, err
	}
	return &net.UDPAddr{IP: addresses[0], Port: int(destination.Port)}, nil
}

func tcpRemoteIP(address net.Addr) net.IP {
	if tcp, ok := address.(*net.TCPAddr); ok {
		return append(net.IP(nil), tcp.IP...)
	}
	return nil
}

func destinationFromUDPAddr(address net.Addr) (domain.Destination, error) {
	udp, ok := address.(*net.UDPAddr)
	if !ok || udp.Port == 0 || udp.IP == nil {
		return domain.Destination{}, errors.New("egress returned an invalid UDP address")
	}
	return domain.Destination{Host: udp.IP.String(), Port: uint16(udp.Port)}, nil
}

func parseSOCKS5UDPDatagram(packet []byte) (domain.Destination, []byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 {
		return domain.Destination{}, nil, errors.New("invalid SOCKS5 UDP reserved bytes")
	}
	if packet[2] != 0 {
		return domain.Destination{}, nil, errors.New("SOCKS5 UDP fragmentation is not supported")
	}
	reader := bufio.NewReader(bytes.NewReader(packet[4:]))
	destination, err := readSOCKS5Destination(reader, packet[3], true)
	if err != nil {
		return domain.Destination{}, nil, err
	}
	consumed := len(packet[4:]) - reader.Buffered()
	return destination, packet[4+consumed:], nil
}

func encodeSOCKS5UDPDatagram(destination domain.Destination, payload []byte) ([]byte, error) {
	if !destination.Valid() {
		return nil, errors.New("invalid SOCKS5 UDP response destination")
	}
	ip := net.ParseIP(destination.Host)
	var addressType byte
	var address []byte
	switch {
	case ip != nil && ip.To4() != nil:
		addressType = socks5IPv4
		address = ip.To4()
	case ip != nil:
		addressType = socks5IPv6
		address = ip.To16()
	default:
		if len(destination.Host) > 255 {
			return nil, errors.New("SOCKS5 UDP domain is too long")
		}
		addressType = socks5Domain
		address = append([]byte{byte(len(destination.Host))}, destination.Host...)
	}
	packet := make([]byte, 0, 6+len(address)+len(payload))
	packet = append(packet, 0, 0, 0, addressType)
	packet = append(packet, address...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], destination.Port)
	packet = append(packet, port[:]...)
	packet = append(packet, payload...)
	return packet, nil
}

func writeSOCKS5Reply(conn net.Conn, reply byte, address net.Addr) error {
	addressType, encodedAddress, port, err := encodeSOCKS5Address(address)
	if err != nil {
		return err
	}
	packet := []byte{socks5Version, reply, 0, addressType}
	packet = append(packet, encodedAddress...)
	packet = append(packet, byte(port>>8), byte(port))
	return writeFull(conn, packet)
}

func encodeSOCKS5Address(address net.Addr) (byte, []byte, uint16, error) {
	if address == nil {
		return socks5IPv4, []byte{0, 0, 0, 0}, 0, nil
	}
	var ip net.IP
	var port int
	switch value := address.(type) {
	case *net.TCPAddr:
		ip, port = value.IP, value.Port
	case *net.UDPAddr:
		ip, port = value.IP, value.Port
	default:
		return socks5IPv4, []byte{0, 0, 0, 0}, 0, nil
	}
	if port < 0 || port > 65535 {
		return 0, nil, 0, errors.New("SOCKS5 bound port is invalid")
	}
	if ip4 := ip.To4(); ip4 != nil {
		return socks5IPv4, ip4, uint16(port), nil
	}
	if ip16 := ip.To16(); ip16 != nil {
		return socks5IPv6, ip16, uint16(port), nil
	}
	return socks5IPv4, []byte{0, 0, 0, 0}, uint16(port), nil
}

func socks5ReplyForError(err error) byte {
	switch egress.KindOf(err) {
	case egress.FailureNetworkUnreachable:
		return socks5NetworkUnreachable
	case egress.FailureHostUnreachable:
		return socks5HostUnreachable
	case egress.FailureConnectionRefused:
		return socks5ConnectionRefused
	case egress.FailureTTLExpired:
		return socks5TTLExpired
	case egress.FailureCommandNotSupported:
		return socks5CommandUnsupported
	case egress.FailureAddressTypeNotSupported:
		return socks5AddressUnsupported
	default:
		return socks5GeneralFailure
	}
}
