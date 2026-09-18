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
)

// NewConnector maps a validated profile to its tunnel backend. M3 supports
// SSH; OpenVPN and WireGuard are intentionally explicit future errors.
func NewConnector(ctx context.Context, profile config.ProfileConfig) (egress.Connector, error) {
	switch strings.ToLower(strings.TrimSpace(profile.Backend)) {
	case "ssh":
		return sshbackend.New(ctx, profile)
	case "openvpn", "wireguard":
		if strings.EqualFold(strings.TrimSpace(profile.Mode), "managed-process") {
			return managedbackend.New(ctx, profile)
		}
		return interfacebackend.New(ctx, profile)
	default:
		return nil, fmt.Errorf("unknown tunnel backend %q", profile.Backend)
	}
}
