package userspace

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	ErrClosed        = errors.New("userspace WireGuard connector is closed")
	ErrNoDNS         = errors.New("userspace WireGuard profile has no tunnel DNS servers configured")
	ErrNoDestination = errors.New("userspace WireGuard destination is invalid")
)

// Connector owns a WireGuard device and an in-process IP stack. It never
// creates an operating-system tunnel interface and never installs host routes.
type Connector struct {
	device         *device.Device
	net            *netstack.Net
	dnsConfigured  bool
	localAddresses []netip.Addr

	mu     sync.RWMutex
	closed bool
}

func New(ctx context.Context, profile config.ProfileConfig) (*Connector, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.ToLower(strings.TrimSpace(profile.Backend)) != "wireguard" {
		return nil, fmt.Errorf("userspace connector does not support backend %q", profile.Backend)
	}
	if strings.ToLower(strings.TrimSpace(profile.Mode)) != "userspace-netstack" {
		return nil, errors.New("userspace WireGuard connector requires mode userspace-netstack")
	}
	wireguardConfig, err := LoadConfig(profile.ConfigPath)
	if err != nil {
		return nil, err
	}
	endpoints, err := resolveEndpoints(ctx, wireguardConfig.Peers)
	if err != nil {
		return nil, err
	}

	localAddresses := make([]netip.Addr, 0, len(wireguardConfig.Addresses))
	for _, prefix := range wireguardConfig.Addresses {
		localAddresses = append(localAddresses, prefix.Addr())
	}
	tun, tnet, err := netstack.CreateNetTUN(localAddresses, wireguardConfig.DNS, wireguardConfig.MTU)
	if err != nil {
		return nil, fmt.Errorf("create userspace network stack: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	if err := dev.IpcSet(buildUAPI(wireguardConfig, endpoints)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure userspace WireGuard device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("start userspace WireGuard device: %w", err)
	}
	return &Connector{
		device:         dev,
		net:            tnet,
		dnsConfigured:  len(wireguardConfig.DNS) > 0,
		localAddresses: localAddresses,
	}, nil
}

func (c *Connector) OpenTCP(ctx context.Context, destination domain.Destination) (net.Conn, error) {
	if err := c.check(destination.Valid()); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	host, err := c.destinationHost(ctx, destination.Host)
	if err != nil {
		return nil, err
	}
	connection, err := c.net.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", destination.Port)))
	if err != nil {
		return nil, classifyError(err)
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
	connection, err := newPacketConn(c.net, c.localAddresses)
	if err != nil {
		return nil, classifyError(err)
	}
	return connection, nil
}

func (c *Connector) Resolve(ctx context.Context, hostname string) ([]net.IP, error) {
	if err := c.check(strings.TrimSpace(hostname) != ""); err != nil {
		return nil, err
	}
	if !c.dnsConfigured {
		return nil, egress.NewError(egress.FailureCommandNotSupported, ErrNoDNS)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	addresses, err := c.net.LookupContextHost(ctx, hostname)
	if err != nil {
		return nil, classifyError(err)
	}
	result := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		ip := net.ParseIP(address)
		if ip != nil {
			result = append(result, ip)
		}
	}
	if len(result) == 0 {
		return nil, egress.NewError(egress.FailureHostUnreachable, errors.New("tunnel DNS returned no addresses"))
	}
	return result, nil
}

func (c *Connector) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	if c.device != nil {
		c.device.Close()
	}
	return nil
}

func (c *Connector) check(valid bool) error {
	if c == nil || c.net == nil {
		return egress.NewError(egress.FailureGeneral, ErrClosed)
	}
	c.mu.RLock()
	closed := c.closed
	c.mu.RUnlock()
	if closed {
		return egress.NewError(egress.FailureGeneral, ErrClosed)
	}
	if !valid {
		return egress.NewError(egress.FailureGeneral, ErrNoDestination)
	}
	return nil
}

func (c *Connector) destinationHost(ctx context.Context, host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	addresses, err := c.Resolve(ctx, host)
	if err != nil {
		return "", err
	}
	return addresses[0].String(), nil
}

func resolveEndpoints(ctx context.Context, peers []Peer) ([]string, error) {
	resolver := net.DefaultResolver
	endpoints := make([]string, 0, len(peers))
	for index, peer := range peers {
		host, port, err := net.SplitHostPort(peer.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("peer[%d] endpoint: %w", index, err)
		}
		if ip := net.ParseIP(host); ip != nil {
			endpoints = append(endpoints, net.JoinHostPort(ip.String(), port))
			continue
		}
		addresses, err := resolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve WireGuard endpoint %q: %w", host, err)
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("resolve WireGuard endpoint %q: no addresses", host)
		}
		endpoints = append(endpoints, net.JoinHostPort(addresses[0].String(), port))
	}
	return endpoints, nil
}

func buildUAPI(config Config, endpoints []string) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "private_key=%s\n", config.PrivateKey)
	if config.ListenPort > 0 {
		fmt.Fprintf(&builder, "listen_port=%d\n", config.ListenPort)
	}
	builder.WriteString("replace_peers=true\n")
	for index, peer := range config.Peers {
		fmt.Fprintf(&builder, "public_key=%s\n", peer.PublicKey)
		if peer.PresharedKey != "" {
			fmt.Fprintf(&builder, "preshared_key=%s\n", peer.PresharedKey)
		}
		fmt.Fprintf(&builder, "endpoint=%s\n", endpoints[index])
		if peer.PersistentKeepalive > 0 {
			fmt.Fprintf(&builder, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
		}
		builder.WriteString("replace_allowed_ips=true\n")
		for _, allowedIP := range peer.AllowedIPs {
			fmt.Fprintf(&builder, "allowed_ip=%s\n", allowedIP.String())
		}
	}
	builder.WriteByte('\n')
	return builder.String()
}

func classifyError(err error) error {
	if err == nil {
		return nil
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return egress.NewError(egress.FailureHostUnreachable, err)
	}
	return egress.NewError(egress.FailureGeneral, err)
}
