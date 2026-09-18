package interfacebackend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
)

var (
	ErrInterfaceUnavailable = errors.New("attached VPN interface is unavailable")
	ErrDNSNotConfigured     = errors.New("attached VPN profile has no tunnel DNS servers configured")
)

type Connector struct {
	backend       string
	interfaceName string
	localIP       net.IP
	dnsServers    []string

	mu     sync.RWMutex
	closed bool
}

type Status struct {
	Backend        string
	Interface      string
	LocalAddress   net.IP
	InterfaceFlags net.Flags
	DNSConfigured  bool
}

func New(ctx context.Context, profile config.ProfileConfig) (*Connector, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	backend := strings.ToLower(strings.TrimSpace(profile.Backend))
	if backend != "openvpn" && backend != "wireguard" {
		return nil, fmt.Errorf("attached-interface connector does not support backend %q", profile.Backend)
	}
	if strings.ToLower(strings.TrimSpace(profile.Mode)) != "attached-interface" {
		return nil, fmt.Errorf("%s connector requires mode attached-interface", backend)
	}

	var iface *net.Interface
	var err error
	if strings.TrimSpace(profile.Interface) != "" {
		iface, err = net.InterfaceByName(strings.TrimSpace(profile.Interface))
		if err != nil {
			return nil, fmt.Errorf("%w: interface %q: %v", ErrInterfaceUnavailable, profile.Interface, err)
		}
		if iface.Flags&net.FlagUp == 0 {
			return nil, fmt.Errorf("%w: interface %q is down", ErrInterfaceUnavailable, profile.Interface)
		}
	}

	localIP, err := resolveLocalIP(profile.LocalAddress, iface)
	if err != nil {
		return nil, err
	}
	return &Connector{
		backend:       backend,
		interfaceName: strings.TrimSpace(profile.Interface),
		localIP:       localIP,
		dnsServers:    normalizeDNSServers(profile.DNS.Servers),
	}, nil
}

func (c *Connector) Status() Status {
	if c == nil {
		return Status{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	var flags net.Flags
	if c.interfaceName != "" {
		if iface, err := net.InterfaceByName(c.interfaceName); err == nil {
			flags = iface.Flags
		}
	}
	return Status{
		Backend:        c.backend,
		Interface:      c.interfaceName,
		LocalAddress:   append(net.IP(nil), c.localIP...),
		InterfaceFlags: flags,
		DNSConfigured:  len(c.dnsServers) > 0,
	}
}

func (c *Connector) OpenTCP(ctx context.Context, destination domain.Destination) (net.Conn, error) {
	if err := c.check(destination.Valid()); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dialer := net.Dialer{LocalAddr: c.tcpLocalAddr()}
	connection, err := dialer.DialContext(ctx, tcpNetwork(c.localIP), destination.String())
	if err != nil {
		return nil, classifyNetworkError(err)
	}
	return connection, nil
}

func (c *Connector) OpenUDP(ctx context.Context) (net.PacketConn, error) {
	if err := c.check(true); err != nil {
		return nil, err
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	connection, err := net.ListenUDP(udpNetwork(c.localIP), c.udpLocalAddr())
	if err != nil {
		return nil, classifyNetworkError(err)
	}
	return connection, nil
}

func (c *Connector) Resolve(ctx context.Context, hostname string) ([]net.IP, error) {
	if err := c.check(strings.TrimSpace(hostname) != ""); err != nil {
		return nil, err
	}
	if len(c.dnsServers) == 0 {
		return nil, egress.NewError(egress.FailureCommandNotSupported, ErrDNSNotConfigured)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(dialContext context.Context, network, _ string) (net.Conn, error) {
			server := c.dnsServers[0]
			var local net.Addr
			if strings.HasPrefix(network, "udp") {
				local = c.udpLocalAddr()
			} else {
				local = c.tcpLocalAddr()
			}
			return (&net.Dialer{LocalAddr: local}).DialContext(dialContext, network, server)
		},
	}
	addresses, err := resolver.LookupIP(ctx, "ip", hostname)
	if err != nil {
		return nil, classifyNetworkError(err)
	}
	return addresses, nil
}

func (c *Connector) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *Connector) check(valid bool) error {
	if c == nil {
		return egress.NewError(egress.FailureGeneral, errors.New("attached VPN connector is nil"))
	}
	c.mu.RLock()
	closed := c.closed
	c.mu.RUnlock()
	if closed {
		return egress.NewError(egress.FailureGeneral, errors.New("attached VPN connector is closed"))
	}
	if !valid {
		return egress.NewError(egress.FailureGeneral, errors.New("attached VPN destination is invalid"))
	}
	return nil
}

func resolveLocalIP(configured string, iface *net.Interface) (net.IP, error) {
	if configured = strings.TrimSpace(configured); configured != "" {
		ip := net.ParseIP(configured)
		if ip == nil || ip.IsUnspecified() {
			return nil, fmt.Errorf("invalid attached VPN local address %q", configured)
		}
		return append(net.IP(nil), ip...), nil
	}
	if iface == nil {
		return nil, fmt.Errorf("%w: no interface or localAddress configured", ErrInterfaceUnavailable)
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("%w: read addresses for %q: %v", ErrInterfaceUnavailable, iface.Name, err)
	}
	for _, address := range addresses {
		var ip net.IP
		switch value := address.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		}
		if ip != nil && !ip.IsUnspecified() {
			return append(net.IP(nil), ip...), nil
		}
	}
	return nil, fmt.Errorf("%w: interface %q has no usable IP address", ErrInterfaceUnavailable, iface.Name)
}

func normalizeDNSServers(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(value); err != nil {
			value = strings.Trim(value, "[]")
			value = net.JoinHostPort(value, "53")
		}
		result = append(result, value)
	}
	return result
}

func (c *Connector) tcpLocalAddr() net.Addr {
	return &net.TCPAddr{IP: append(net.IP(nil), c.localIP...)}
}

func (c *Connector) udpLocalAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), c.localIP...), Port: 0}
}

func tcpNetwork(ip net.IP) string {
	if ip.To4() != nil {
		return "tcp4"
	}
	return "tcp6"
}

func udpNetwork(ip net.IP) string {
	if ip.To4() != nil {
		return "udp4"
	}
	return "udp6"
}

func classifyNetworkError(err error) error {
	if err == nil {
		return nil
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return egress.NewError(egress.FailureHostUnreachable, err)
	}
	return egress.NewError(egress.FailureGeneral, err)
}
