package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var envNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// Config is the complete daemon configuration.
type Config struct {
	ShutdownTimeout string           `json:"shutdownTimeout" yaml:"shutdownTimeout"`
	Listeners       []ListenerConfig `json:"listeners" yaml:"listeners"`
	Profiles        []ProfileConfig  `json:"profiles" yaml:"profiles"`
}

type ListenerConfig struct {
	ID       string        `json:"id" yaml:"id"`
	Protocol string        `json:"protocol" yaml:"protocol"`
	Host     string        `json:"host" yaml:"host"`
	Port     uint16        `json:"port" yaml:"port"`
	Profile  string        `json:"profile" yaml:"profile"`
	Routes   []RouteConfig `json:"routes" yaml:"routes"`
	TLS      *TLSConfig    `json:"tls,omitempty" yaml:"tls,omitempty"`
	Auth     AuthConfig    `json:"auth" yaml:"auth"`
	ACL      ACLConfig     `json:"acl" yaml:"acl"`
}

type ProfileConfig struct {
	ID             string    `json:"id" yaml:"id"`
	Backend        string    `json:"backend" yaml:"backend"`
	Mode           string    `json:"mode" yaml:"mode"`
	Host           string    `json:"host" yaml:"host"`
	Port           uint16    `json:"port" yaml:"port"`
	User           string    `json:"user" yaml:"user"`
	PrivateKeyPath string    `json:"privateKeyPath" yaml:"privateKeyPath"`
	KnownHostsPath string    `json:"knownHostsPath" yaml:"knownHostsPath"`
	Interface      string    `json:"interface" yaml:"interface"`
	LocalAddress   string    `json:"localAddress" yaml:"localAddress"`
	DNS            DNSConfig `json:"dns" yaml:"dns"`
}

type DNSConfig struct {
	Mode    string   `json:"mode" yaml:"mode"`
	Servers []string `json:"servers" yaml:"servers"`
}

type TLSConfig struct {
	CertFile                 string `json:"certFile" yaml:"certFile"`
	KeyFile                  string `json:"keyFile" yaml:"keyFile"`
	ClientCAFile             string `json:"clientCAFile" yaml:"clientCAFile"`
	RequireClientCertificate bool   `json:"requireClientCertificate" yaml:"requireClientCertificate"`
}

type AuthConfig struct {
	Type        string `json:"type" yaml:"type"`
	Username    string `json:"username" yaml:"username"`
	PasswordEnv string `json:"passwordEnv" yaml:"passwordEnv"`
	Realm       string `json:"realm" yaml:"realm"`
}

type ACLConfig struct {
	DefaultAction string   `json:"defaultAction" yaml:"defaultAction"`
	SourceCIDRs   []string `json:"sourceCidrs" yaml:"sourceCidrs"`
	AllowCIDRs    []string `json:"allowCidrs" yaml:"allowCidrs"`
	DenyCIDRs     []string `json:"denyCidrs" yaml:"denyCidrs"`
	AllowDomains  []string `json:"allowDomains" yaml:"allowDomains"`
	DenyDomains   []string `json:"denyDomains" yaml:"denyDomains"`
}

type RouteConfig struct {
	CIDR         string `json:"cidr" yaml:"cidr"`
	DomainSuffix string `json:"domainSuffix" yaml:"domainSuffix"`
	Profile      string `json:"profile" yaml:"profile"`
	Default      bool   `json:"default" yaml:"default"`
}

// Load reads YAML or JSON based on the file extension and validates the
// resulting configuration. Unknown fields are rejected in both formats.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	if err := decode(data, filepath.Ext(path), &cfg); err != nil {
		return Config{}, fmt.Errorf("decode config %q: %w", path, err)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Decode(data []byte, format string) (Config, error) {
	var cfg Config
	if err := decode(data, format, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) GracefulShutdownTimeout() (time.Duration, error) {
	c.ApplyDefaults()
	timeout, err := time.ParseDuration(c.ShutdownTimeout)
	if err != nil || timeout <= 0 {
		return 0, errors.New("shutdownTimeout must be a positive duration")
	}
	return timeout, nil
}

func decode(data []byte, extension string, cfg *Config) error {
	if strings.EqualFold(extension, ".yaml") || strings.EqualFold(extension, ".yml") || strings.TrimSpace(extension) == "yaml" {
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		return decoder.Decode(cfg)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(cfg)
}

func (c *Config) ApplyDefaults() {
	if c.ShutdownTimeout == "" {
		c.ShutdownTimeout = "30s"
	}
	for i := range c.Listeners {
		listener := &c.Listeners[i]
		listener.Protocol = strings.ToLower(strings.TrimSpace(listener.Protocol))
		if listener.Host == "" {
			listener.Host = "127.0.0.1"
		}
		if listener.Port == 0 {
			listener.Port = 1080
		}
		listener.Auth.Type = strings.ToLower(strings.TrimSpace(listener.Auth.Type))
		if listener.Auth.Type == "" {
			listener.Auth.Type = "none"
		}
		listener.ACL.DefaultAction = strings.ToLower(strings.TrimSpace(listener.ACL.DefaultAction))
		if listener.ACL.DefaultAction == "" {
			if IsLoopbackHost(listener.Host) {
				listener.ACL.DefaultAction = "allow"
			} else {
				listener.ACL.DefaultAction = "deny"
			}
		}
	}
}

func (c Config) Validate() error {
	c.ApplyDefaults()
	var problems []string
	if timeout, err := time.ParseDuration(c.ShutdownTimeout); err != nil || timeout <= 0 {
		problems = append(problems, "shutdownTimeout must be a positive duration")
	}
	if len(c.Listeners) == 0 {
		problems = append(problems, "at least one listener is required")
	}
	profiles := make(map[string]struct{}, len(c.Profiles))
	for index, profile := range c.Profiles {
		prefix := fmt.Sprintf("profiles[%d]", index)
		if strings.TrimSpace(profile.ID) == "" {
			problems = append(problems, prefix+".id is required")
			continue
		}
		if strings.TrimSpace(profile.Backend) == "" {
			problems = append(problems, prefix+".backend is required")
		}
		problems = append(problems, validateProfile(prefix, profile)...)
		if _, exists := profiles[profile.ID]; exists {
			problems = append(problems, "duplicate profile id "+profile.ID)
		}
		profiles[profile.ID] = struct{}{}
	}

	listeners := make(map[string]struct{}, len(c.Listeners))
	for index, listener := range c.Listeners {
		prefix := fmt.Sprintf("listeners[%d]", index)
		if strings.TrimSpace(listener.ID) == "" {
			problems = append(problems, prefix+".id is required")
		} else if _, exists := listeners[listener.ID]; exists {
			problems = append(problems, "duplicate listener id "+listener.ID)
		} else {
			listeners[listener.ID] = struct{}{}
		}
		if !supportedProtocol(listener.Protocol) {
			problems = append(problems, prefix+".protocol must be http, socks4, or socks5")
		}
		if strings.TrimSpace(listener.Host) == "" {
			problems = append(problems, prefix+".host is required")
		}
		if listener.Profile != "" {
			if _, exists := profiles[listener.Profile]; !exists {
				problems = append(problems, prefix+".profile references unknown profile "+listener.Profile)
			}
		}
		if listener.Profile == "" && !hasDefaultRoute(listener.Routes) {
			problems = append(problems, prefix+" requires profile or a default route")
		}
		problems = append(problems, validateTLS(prefix, listener.TLS)...)
		problems = append(problems, validateAuth(prefix, listener.Auth, listener.Protocol)...)
		problems = append(problems, validateACL(prefix, listener.ACL)...)
		problems = append(problems, validateRoutes(prefix, listener.Routes, profiles)...)
		if !IsLoopbackHost(listener.Host) {
			if listener.TLS == nil || listener.TLS.CertFile == "" || listener.TLS.KeyFile == "" {
				problems = append(problems, prefix+" non-loopback listeners require tls.certFile and tls.keyFile")
			}
			if listener.Auth.Type == "none" && (listener.TLS == nil || !listener.TLS.RequireClientCertificate) {
				problems = append(problems, prefix+" non-loopback listeners require basic auth or a client certificate")
			}
			if len(listener.ACL.SourceCIDRs) == 0 {
				problems = append(problems, prefix+" non-loopback listeners require acl.sourceCidrs")
			}
			if listener.Protocol == "socks4" && listener.Auth.Type != "none" && (listener.TLS == nil || !listener.TLS.RequireClientCertificate) {
				problems = append(problems, prefix+" socks4 basic auth requires mutual TLS")
			}
		}
	}
	if len(problems) > 0 {
		return errors.New("invalid configuration:\n- " + strings.Join(problems, "\n- "))
	}
	return nil
}

func validateProfile(prefix string, profile ProfileConfig) []string {
	backend := strings.ToLower(strings.TrimSpace(profile.Backend))
	if backend != "openvpn" && backend != "wireguard" {
		return nil
	}
	var problems []string
	if strings.ToLower(strings.TrimSpace(profile.Mode)) != "attached-interface" {
		problems = append(problems, prefix+".mode must be attached-interface for OpenVPN/WireGuard in M4")
	}
	if strings.TrimSpace(profile.Interface) == "" && strings.TrimSpace(profile.LocalAddress) == "" {
		problems = append(problems, prefix+" requires interface or localAddress for attached VPN egress")
	}
	if profile.LocalAddress != "" && net.ParseIP(strings.TrimSpace(profile.LocalAddress)) == nil {
		problems = append(problems, prefix+".localAddress must be an IP address")
	}
	if profile.DNS.Mode != "" && profile.DNS.Mode != "remote-tcp" && profile.DNS.Mode != "tunnel" {
		problems = append(problems, prefix+".dns.mode must be remote-tcp or tunnel")
	}
	if profile.DNS.Mode != "" && len(profile.DNS.Servers) == 0 {
		problems = append(problems, prefix+".dns.servers is required when dns.mode is configured")
	}
	return problems
}

func validateTLS(prefix string, tlsConfig *TLSConfig) []string {
	if tlsConfig == nil {
		return nil
	}
	var problems []string
	if (tlsConfig.CertFile == "") != (tlsConfig.KeyFile == "") {
		problems = append(problems, prefix+" tls.certFile and tls.keyFile must be provided together")
	}
	if tlsConfig.RequireClientCertificate && tlsConfig.ClientCAFile == "" {
		problems = append(problems, prefix+" tls.clientCAFile is required when client certificates are required")
	}
	return problems
}

func validateAuth(prefix string, auth AuthConfig, protocol string) []string {
	if auth.Type != "none" && auth.Type != "basic" {
		return []string{prefix + ".auth.type must be none or basic"}
	}
	if auth.Type != "basic" {
		return nil
	}
	var problems []string
	if auth.Username == "" {
		problems = append(problems, prefix+" auth.username is required for basic auth")
	}
	if !envNamePattern.MatchString(auth.PasswordEnv) {
		problems = append(problems, prefix+" auth.passwordEnv must be an uppercase environment variable name")
	}
	if protocol == "socks4" {
		problems = append(problems, prefix+" socks4 does not support password authentication")
	}
	return problems
}

func validateACL(prefix string, acl ACLConfig) []string {
	if acl.DefaultAction != "allow" && acl.DefaultAction != "deny" {
		return []string{prefix + ".acl.defaultAction must be allow or deny"}
	}
	var problems []string
	for _, field := range []struct {
		name   string
		values []string
	}{
		{name: "sourceCidrs", values: acl.SourceCIDRs},
		{name: "allowCidrs", values: acl.AllowCIDRs},
		{name: "denyCidrs", values: acl.DenyCIDRs},
	} {
		for _, value := range field.values {
			if _, _, err := net.ParseCIDR(value); err != nil {
				problems = append(problems, fmt.Sprintf("%s.acl.%s contains invalid CIDR %q", prefix, field.name, value))
			}
		}
	}
	problems = append(problems, validateDomains(prefix, "allowDomains", acl.AllowDomains)...)
	problems = append(problems, validateDomains(prefix, "denyDomains", acl.DenyDomains)...)
	return problems
}

func validateDomains(prefix, field string, values []string) []string {
	var problems []string
	for _, value := range values {
		if normalizeDomain(value) == "" {
			problems = append(problems, fmt.Sprintf("%s.acl.%s contains an empty domain", prefix, field))
		}
	}
	return problems
}

func validateRoutes(prefix string, routes []RouteConfig, profiles map[string]struct{}) []string {
	var problems []string
	defaults := 0
	for index, route := range routes {
		routePrefix := fmt.Sprintf("%s.routes[%d]", prefix, index)
		matches := 0
		if route.CIDR != "" {
			matches++
			if _, _, err := net.ParseCIDR(route.CIDR); err != nil {
				problems = append(problems, routePrefix+".cidr is invalid")
			}
		}
		if route.DomainSuffix != "" {
			matches++
		}
		if route.Default {
			matches++
			defaults++
		}
		if matches != 1 {
			problems = append(problems, routePrefix+" must specify exactly one of cidr, domainSuffix, or default")
		}
		if route.Profile == "" {
			problems = append(problems, routePrefix+".profile is required")
		} else if _, exists := profiles[route.Profile]; !exists {
			problems = append(problems, routePrefix+".profile references unknown profile "+route.Profile)
		}
	}
	if defaults > 1 {
		problems = append(problems, prefix+".routes may contain only one default route")
	}
	return problems
}

func hasDefaultRoute(routes []RouteConfig) bool {
	for _, route := range routes {
		if route.Default {
			return true
		}
	}
	return false
}

func supportedProtocol(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "http", "socks4", "socks5":
		return true
	default:
		return false
	}
}

func IsLoopbackHost(host string) bool {
	host = strings.Trim(host, "[]")
	return strings.EqualFold(host, "localhost") || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
}

func normalizeDomain(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(value, ".")))
	value = strings.TrimPrefix(value, "*.")
	return strings.TrimPrefix(value, ".")
}
