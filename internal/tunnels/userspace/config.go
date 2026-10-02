package userspace

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

const defaultMTU = 1420

// Config is the safe subset of a standard WireGuard configuration understood by
// the in-process backend. Host route and shell-hook settings are deliberately
// not accepted because this mode must never mutate host networking.
type Config struct {
	PrivateKey string
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	ListenPort uint16
	MTU        int
	Peers      []Peer
}

type Peer struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []netip.Prefix
	PersistentKeepalive uint16
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read WireGuard config %q: %w", path, err)
	}
	config, err := ParseConfig(data)
	if err != nil {
		return Config{}, fmt.Errorf("parse WireGuard config %q: %w", path, err)
	}
	return config, nil
}

func ParseConfig(data []byte) (Config, error) {
	var raw rawConfig
	raw.interfaceValues = make(map[string]string)
	section := ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
				if raw.interfaceSeen {
					return Config{}, fmt.Errorf("line %d: duplicate [Interface] section", lineNumber)
				}
				raw.interfaceSeen = true
			case "peer":
				raw.peers = append(raw.peers, make(map[string]string))
			default:
				return Config{}, fmt.Errorf("line %d: unsupported section %q", lineNumber, section)
			}
			continue
		}
		if section == "" {
			return Config{}, fmt.Errorf("line %d: setting appears before a section", lineNumber)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Config{}, fmt.Errorf("line %d: expected key = value", lineNumber)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			return Config{}, fmt.Errorf("line %d: key and value are required", lineNumber)
		}
		if section == "interface" {
			if _, exists := raw.interfaceValues[key]; exists {
				return Config{}, fmt.Errorf("line %d: duplicate Interface setting %q", lineNumber, key)
			}
			raw.interfaceValues[key] = value
		} else {
			peer := raw.peers[len(raw.peers)-1]
			if _, exists := peer[key]; exists {
				return Config{}, fmt.Errorf("line %d: duplicate Peer setting %q", lineNumber, key)
			}
			peer[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return raw.build()
}

type rawConfig struct {
	interfaceSeen   bool
	interfaceValues map[string]string
	peers           []map[string]string
}

func (r *rawConfig) build() (Config, error) {
	if !r.interfaceSeen {
		return Config{}, errors.New("missing [Interface] section")
	}
	config := Config{MTU: defaultMTU}
	if r.interfaceValues == nil {
		r.interfaceValues = map[string]string{}
	}
	for key, value := range r.interfaceValues {
		switch key {
		case "privatekey":
			config.PrivateKey, _ = keyToHex(value)
			if config.PrivateKey == "" {
				return Config{}, errors.New("Interface.PrivateKey must be a valid base64 WireGuard key")
			}
		case "address":
			prefixes, err := parsePrefixes(value)
			if err != nil {
				return Config{}, fmt.Errorf("Interface.Address: %w", err)
			}
			config.Addresses = append(config.Addresses, prefixes...)
		case "dns":
			addresses, err := parseAddresses(value)
			if err != nil {
				return Config{}, fmt.Errorf("Interface.DNS: %w", err)
			}
			config.DNS = append(config.DNS, addresses...)
		case "listenport":
			port, err := parseUint16(value)
			if err != nil {
				return Config{}, fmt.Errorf("Interface.ListenPort: %w", err)
			}
			config.ListenPort = port
		case "mtu":
			mtu, err := strconv.Atoi(value)
			if err != nil || mtu < 576 || mtu > 65535 {
				return Config{}, fmt.Errorf("Interface.MTU must be between 576 and 65535")
			}
			config.MTU = mtu
		case "table", "preup", "postup", "predown", "postdown", "saveconfig":
			return Config{}, fmt.Errorf("interface.%s is not supported in userspace-netstack mode", key)
		default:
			return Config{}, fmt.Errorf("unsupported Interface setting %q", key)
		}
	}
	if config.PrivateKey == "" {
		return Config{}, errors.New("Interface.PrivateKey is required")
	}
	if len(config.Addresses) == 0 {
		return Config{}, errors.New("Interface.Address is required")
	}
	if len(r.peers) == 0 {
		return Config{}, errors.New("at least one [Peer] section is required")
	}
	for index, values := range r.peers {
		peer, err := buildPeer(values)
		if err != nil {
			return Config{}, fmt.Errorf("peer[%d]: %w", index, err)
		}
		config.Peers = append(config.Peers, peer)
	}
	return config, nil
}

func buildPeer(values map[string]string) (Peer, error) {
	var peer Peer
	for key, value := range values {
		switch key {
		case "publickey":
			peer.PublicKey, _ = keyToHex(value)
			if peer.PublicKey == "" {
				return Peer{}, errors.New("PublicKey must be a valid base64 WireGuard key")
			}
		case "presharedkey":
			peer.PresharedKey, _ = keyToHex(value)
			if peer.PresharedKey == "" {
				return Peer{}, errors.New("PresharedKey must be a valid base64 WireGuard key")
			}
		case "endpoint":
			if _, _, err := net.SplitHostPort(value); err != nil {
				return Peer{}, fmt.Errorf("endpoint must be host:port: %w", err)
			}
			peer.Endpoint = value
		case "allowedips":
			prefixes, err := parsePrefixes(value)
			if err != nil {
				return Peer{}, fmt.Errorf("AllowedIPs: %w", err)
			}
			peer.AllowedIPs = append(peer.AllowedIPs, prefixes...)
		case "persistentkeepalive":
			if strings.EqualFold(value, "off") {
				peer.PersistentKeepalive = 0
				continue
			}
			keepalive, err := parseUint16(value)
			if err != nil {
				return Peer{}, fmt.Errorf("persistentkeepalive: %w", err)
			}
			peer.PersistentKeepalive = keepalive
		default:
			return Peer{}, fmt.Errorf("unsupported setting %q", key)
		}
	}
	if peer.PublicKey == "" {
		return Peer{}, errors.New("PublicKey is required")
	}
	if peer.Endpoint == "" {
		return Peer{}, errors.New("endpoint is required for proxy egress")
	}
	if len(peer.AllowedIPs) == 0 {
		return Peer{}, errors.New("AllowedIPs is required")
	}
	return peer, nil
}

func parsePrefixes(value string) ([]netip.Prefix, error) {
	var result []netip.Prefix
	for _, item := range strings.Split(value, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil {
			return nil, fmt.Errorf("invalid prefix %q", strings.TrimSpace(item))
		}
		result = append(result, prefix)
	}
	return result, nil
}

func parseAddresses(value string) ([]netip.Addr, error) {
	var result []netip.Addr
	for _, item := range strings.Split(value, ",") {
		address, err := netip.ParseAddr(strings.TrimSpace(item))
		if err != nil {
			return nil, fmt.Errorf("invalid address %q", strings.TrimSpace(item))
		}
		result = append(result, address)
	}
	return result, nil
}

func parseUint16(value string) (uint16, error) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil {
		return 0, errors.New("must be an unsigned 16-bit integer")
	}
	return uint16(parsed), nil
}

func keyToHex(value string) (string, error) {
	value = strings.TrimSpace(value)
	decoders := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding}
	for _, decoder := range decoders {
		decoded, err := decoder.DecodeString(value)
		if err == nil && len(decoded) == 32 {
			return hex.EncodeToString(decoded), nil
		}
	}
	return "", errors.New("key must decode to 32 bytes")
}
