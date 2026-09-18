package policy

import (
	"encoding/base64"
	"net"
	"net/http"
	"testing"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
)

func TestBasicAuthenticatorUsesEnvironmentBackedPassword(t *testing.T) {
	t.Setenv("VPNFRONT_TEST_PASSWORD", "correct")
	auth, err := NewAuthenticator(config.AuthConfig{Type: "basic", Username: "proxy", PasswordEnv: "VPNFRONT_TEST_PASSWORD"})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodConnect, "http://example.test:443", nil)
	request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("proxy:correct")))
	if !auth.AuthenticateHTTP(request) || auth.HTTPChallenge() == "" {
		t.Fatal("valid HTTP credentials were rejected")
	}
	request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("proxy:wrong")))
	if auth.AuthenticateHTTP(request) {
		t.Fatal("invalid HTTP credentials were accepted")
	}
	if !auth.AuthenticateSOCKS5("proxy", "correct") {
		t.Fatal("valid SOCKS5 credentials were rejected")
	}
}

func TestACLDeniesMetadataAndAppliesAllowRules(t *testing.T) {
	acl, err := NewACL(config.ACLConfig{
		DefaultAction: "deny",
		AllowCIDRs:    []string{"198.51.100.0/24"},
		AllowDomains:  []string{"internal.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, allowed := range []domain.Destination{{Host: "198.51.100.10", Port: 443}, {Host: "api.internal.example", Port: 443}} {
		if err := acl.Allow(allowed); err != nil {
			t.Fatalf("allowed destination %+v rejected: %v", allowed, err)
		}
	}
	for _, denied := range []domain.Destination{{Host: "169.254.169.254", Port: 80}, {Host: "203.0.113.10", Port: 443}} {
		if err := acl.Allow(denied); err == nil {
			t.Fatalf("denied destination %+v was allowed", denied)
		}
	}
}

func TestSourceFilterMatchesRemoteIP(t *testing.T) {
	filter, err := NewSourceFilter([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if !filter.Allow(&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}) {
		t.Fatal("allowed source was rejected")
	}
	if filter.Allow(&net.TCPAddr{IP: net.ParseIP("198.51.100.10"), Port: 1234}) {
		t.Fatal("disallowed source was accepted")
	}
}
