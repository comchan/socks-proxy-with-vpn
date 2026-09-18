package config

import (
	"strings"
	"testing"
)

func validConfig() Config {
	return Config{
		Listeners: []ListenerConfig{{ID: "local", Protocol: "socks5", Profile: "test"}},
		Profiles:  []ProfileConfig{{ID: "test", Backend: "fake"}},
	}
}

func TestDecodeYAMLAppliesSafeLoopbackDefaults(t *testing.T) {
	cfg, err := Decode([]byte(`listeners:
  - id: local
    protocol: socks5
    profile: test
profiles:
  - id: test
    backend: fake
`), "yaml")
	if err != nil {
		t.Fatal(err)
	}
	listener := cfg.Listeners[0]
	if listener.Host != "127.0.0.1" || listener.Port != 1080 || listener.Auth.Type != "none" || listener.ACL.DefaultAction != "allow" {
		t.Fatalf("defaults = %+v", listener)
	}
}

func TestDecodeJSONRejectsUnknownFields(t *testing.T) {
	_, err := Decode([]byte(`{"listeners":[],"profiles":[],"unexpected":true}`), ".json")
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %v, want unknown-field rejection", err)
	}
}

func TestValidateRejectsUnsafePublicListener(t *testing.T) {
	cfg := validConfig()
	cfg.Listeners[0].Host = "0.0.0.0"
	if err := cfg.Validate(); err == nil {
		t.Fatal("public listener without TLS/auth/source policy should be rejected")
	} else {
		for _, expected := range []string{"tls.certFile", "basic auth", "sourceCidrs"} {
			if !strings.Contains(err.Error(), expected) {
				t.Fatalf("error = %v, want %q", err, expected)
			}
		}
	}
}

func TestValidateAcceptsSecuredPublicListener(t *testing.T) {
	cfg := validConfig()
	listener := &cfg.Listeners[0]
	listener.Host = "0.0.0.0"
	listener.TLS = &TLSConfig{CertFile: "server.crt", KeyFile: "server.key"}
	listener.Auth = AuthConfig{Type: "basic", Username: "proxy", PasswordEnv: "VPNFRONT_TEST_PASSWORD"}
	listener.ACL = ACLConfig{DefaultAction: "deny", SourceCIDRs: []string{"192.0.2.0/24"}, AllowCIDRs: []string{"198.51.100.0/24"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsInvalidRouteShape(t *testing.T) {
	cfg := validConfig()
	cfg.Listeners[0].Routes = []RouteConfig{{CIDR: "10.0.0.0/8", DomainSuffix: ".internal", Profile: "test"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("error = %v, want route shape rejection", err)
	}
}

func TestValidateRejectsUnknownRouteProfile(t *testing.T) {
	cfg := validConfig()
	cfg.Listeners[0].Profile = ""
	cfg.Listeners[0].Routes = []RouteConfig{{Default: true, Profile: "missing"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("error = %v, want unknown profile rejection", err)
	}
}

func TestShutdownTimeoutDefaultsAndValidates(t *testing.T) {
	cfg := validConfig()
	cfg.ApplyDefaults()
	if cfg.ShutdownTimeout != "30s" {
		t.Fatalf("shutdown timeout = %q, want 30s", cfg.ShutdownTimeout)
	}
	if timeout, err := cfg.GracefulShutdownTimeout(); err != nil || timeout.String() != "30s" {
		t.Fatalf("GracefulShutdownTimeout() = %v, %v", timeout, err)
	}
	cfg.ShutdownTimeout = "not-a-duration"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "shutdownTimeout") {
		t.Fatalf("error = %v, want shutdown timeout rejection", err)
	}
}
