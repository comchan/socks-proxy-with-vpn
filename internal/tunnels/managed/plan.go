package managed

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
)

type Plan struct {
	Start       Command
	Stop        *Command
	ReadyMarker string
	OneShot     bool
}

func BuildPlan(profile config.ProfileConfig) (Plan, error) {
	backend := strings.ToLower(strings.TrimSpace(profile.Backend))
	if backend != "openvpn" && backend != "wireguard" {
		return Plan{}, fmt.Errorf("managed backend %q is unsupported", profile.Backend)
	}
	if strings.ToLower(strings.TrimSpace(profile.Mode)) != "managed-process" {
		return Plan{}, errors.New("managed plan requires mode managed-process")
	}
	if strings.TrimSpace(profile.ConfigPath) == "" {
		return Plan{}, errors.New("managed VPN configPath is required")
	}
	clientPath := strings.TrimSpace(profile.ClientPath)
	if clientPath == "" {
		clientPath = defaultClientPath(backend)
	}
	if backend == "openvpn" {
		return Plan{
			Start:       Command{Name: clientPath, Args: []string{"--config", profile.ConfigPath}},
			ReadyMarker: "Initialization Sequence Completed",
		}, nil
	}
	if runtime.GOOS == "windows" {
		serviceName := strings.TrimSuffix(filepath.Base(profile.ConfigPath), filepath.Ext(profile.ConfigPath))
		return Plan{
			Start:   Command{Name: clientPath, Args: []string{"/installtunnelservice", profile.ConfigPath}},
			Stop:    &Command{Name: clientPath, Args: []string{"/uninstalltunnelservice", serviceName}},
			OneShot: true,
		}, nil
	}
	return Plan{
		Start:   Command{Name: clientPath, Args: []string{"up", profile.ConfigPath}},
		Stop:    &Command{Name: clientPath, Args: []string{"down", profile.ConfigPath}},
		OneShot: true,
	}, nil
}

func defaultClientPath(backend string) string {
	if backend == "openvpn" {
		return "openvpn"
	}
	if runtime.GOOS == "windows" {
		return "wireguard.exe"
	}
	return "wg-quick"
}
