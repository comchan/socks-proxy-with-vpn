package tunnels

import (
	"context"
	"fmt"
	"strings"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
	interfacebackend "github.com/comchan/socks-proxy-thru-wireguard/internal/tunnels/interface"
	managedbackend "github.com/comchan/socks-proxy-thru-wireguard/internal/tunnels/managed"
	sshbackend "github.com/comchan/socks-proxy-thru-wireguard/internal/tunnels/ssh"
	userspacebackend "github.com/comchan/socks-proxy-thru-wireguard/internal/tunnels/userspace"
)

// NewConnector maps a validated profile to its tunnel backend. SSH and the
// OpenVPN/WireGuard attached, managed, and userspace modes are explicit.
func NewConnector(ctx context.Context, profile config.ProfileConfig) (egress.Connector, error) {
	switch strings.ToLower(strings.TrimSpace(profile.Backend)) {
	case "ssh":
		return sshbackend.New(ctx, profile)
	case "openvpn", "wireguard":
		mode := strings.ToLower(strings.TrimSpace(profile.Mode))
		switch mode {
		case "managed-process":
			return managedbackend.New(ctx, profile)
		case "userspace-netstack":
			if strings.ToLower(strings.TrimSpace(profile.Backend)) != "wireguard" {
				return nil, fmt.Errorf("userspace-netstack mode is only supported for WireGuard")
			}
			return userspacebackend.New(ctx, profile)
		default:
			return interfacebackend.New(ctx, profile)
		}
	default:
		return nil, fmt.Errorf("unknown tunnel backend %q", profile.Backend)
	}
}
