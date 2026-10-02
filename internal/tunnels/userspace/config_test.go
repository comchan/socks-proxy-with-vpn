package userspace

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func testKey(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func TestParseConfigAcceptsStandardProxyOnlyConfig(t *testing.T) {
	configText := `[Interface]
PrivateKey = ` + testKey(1) + `
Address = 10.8.0.2/32, fd00::2/128
DNS = 10.8.0.1, fd00::1
MTU = 1380

[Peer]
PublicKey = ` + testKey(2) + `
PresharedKey = ` + testKey(3) + `
Endpoint = vpn.example.test:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`

	config, err := ParseConfig([]byte(configText))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if config.MTU != 1380 || len(config.Addresses) != 2 || len(config.DNS) != 2 || len(config.Peers) != 1 {
		t.Fatalf("parsed config = %+v", config)
	}
	if config.Peers[0].Endpoint != "vpn.example.test:51820" || len(config.Peers[0].AllowedIPs) != 2 {
		t.Fatalf("parsed peer = %+v", config.Peers[0])
	}
}

func TestParseConfigRejectsHostRoutingAndHooks(t *testing.T) {
	for _, setting := range []string{"Table = auto", "PostUp = route add", "SaveConfig = true"} {
		configText := "[Interface]\nPrivateKey = " + testKey(1) + "\nAddress = 10.0.0.2/32\n" + setting + "\n\n[Peer]\nPublicKey = " + testKey(2) + "\nEndpoint = 127.0.0.1:51820\nAllowedIPs = 0.0.0.0/0\n"
		_, err := ParseConfig([]byte(configText))
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "not supported") {
			t.Errorf("setting %q error = %v, want unsupported", setting, err)
		}
	}
}

func TestParseConfigRequiresProxyPeerEndpoint(t *testing.T) {
	configText := "[Interface]\nPrivateKey = " + testKey(1) + "\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = " + testKey(2) + "\nAllowedIPs = 0.0.0.0/0\n"
	_, err := ParseConfig([]byte(configText))
	if err == nil || !strings.Contains(err.Error(), "endpoint is required") {
		t.Fatalf("error = %v, want endpoint requirement", err)
	}
}
