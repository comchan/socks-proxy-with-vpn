package tunnels

import (
	"context"
	"strings"
	"testing"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
)

func TestNewConnectorRequiresAttachedInterfaceConfig(t *testing.T) {
	for _, backend := range []string{"openvpn", "wireguard"} {
		t.Run(backend, func(t *testing.T) {
			_, err := NewConnector(context.Background(), config.ProfileConfig{Backend: backend, Mode: "attached-interface"})
			if err == nil || !strings.Contains(err.Error(), "interface or localAddress") {
				t.Fatalf("error = %v, want attached-interface requirement", err)
			}
		})
	}
}

func TestNewConnectorRejectsUnknownBackend(t *testing.T) {
	_, err := NewConnector(context.Background(), config.ProfileConfig{Backend: "unknown"})
	if err == nil || !strings.Contains(err.Error(), "unknown tunnel backend") {
		t.Fatalf("error = %v, want unknown-backend error", err)
	}
}
