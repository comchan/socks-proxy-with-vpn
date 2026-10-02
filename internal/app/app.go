package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	runtimepkg "github.com/comchan/socks-proxy-thru-wireguard/internal/runtime"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/tunnels"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/version"
)

const usage = `vpnfront is a VPN-fronted HTTP and SOCKS proxy daemon.

The proxy listeners and tunnel backends are configured in a YAML or JSON file.

Commands:
  start --config <path>  start the configured proxy listeners and tunnel backends

Global options:
  --version             print the version and exit
  --validate-config     validate a YAML or JSON configuration file
`

// Run executes the CLI and returns a process exit code. Keeping the seam
// independent of os.Args and os.Stdout makes command behavior unit-testable.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if err := ctx.Err(); err != nil {
		if !writef(stderr, "%v\n", err) {
			return 1
		}
		return 1
	}
	if len(args) > 0 && args[0] == "start" {
		return runStart(ctx, args[1:], stdout, stderr, tunnels.NewConnector)
	}

	flags := flag.NewFlagSet("vpnfront", flag.ContinueOnError)
	flags.SetOutput(stderr)
	showVersion := flags.Bool("version", false, "print the version and exit")
	validateConfig := flags.String("validate-config", "", "validate a YAML or JSON configuration file")
	flags.Usage = func() {
		writeText(stderr, usage)
	}

	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		if !writef(stderr, "unexpected arguments: %s\n", strings.Join(flags.Args(), " ")) {
			return 1
		}
		return 2
	}
	if *validateConfig != "" {
		if _, err := config.Load(*validateConfig); err != nil {
			if !writef(stderr, "invalid configuration: %v\n", err) {
				return 1
			}
			return 2
		}
		if !writef(stdout, "configuration valid\n") {
			return 1
		}
		return 0
	}
	if *showVersion {
		if !writef(stdout, "vpnfront %s\n", version.String()) {
			return 1
		}
		return 0
	}

	flags.Usage()
	return 0
}

func runStart(ctx context.Context, args []string, stdout, stderr io.Writer, factory runtimepkg.ConnectorFactory) int {
	flags := flag.NewFlagSet("vpnfront start", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "path to a YAML or JSON daemon configuration file")
	flags.Usage = func() {
		writeText(stderr, "Usage: vpnfront start --config <path>\n\n")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		if !writef(stderr, "unexpected arguments: %s\n", strings.Join(flags.Args(), " ")) {
			return 1
		}
		return 2
	}
	if strings.TrimSpace(*configPath) == "" {
		if !writef(stderr, "start requires --config <path>\n") {
			return 1
		}
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		if !writef(stderr, "invalid configuration: %v\n", err) {
			return 1
		}
		return 2
	}
	daemon, err := runtimepkg.New(cfg, factory)
	if err != nil {
		if !writef(stderr, "cannot create daemon: %v\n", err) {
			return 1
		}
		return 1
	}
	if err := daemon.Start(ctx); err != nil {
		if !writef(stderr, "cannot start daemon: %v\n", err) {
			return 1
		}
		return 1
	}
	if !writef(stdout, "vpnfront started\n") {
		_ = daemon.Shutdown(context.Background())
		return 1
	}
	for index, address := range daemon.Addresses() {
		listener := cfg.Listeners[index]
		if !writef(stdout, "listener id=%s protocol=%s address=%s\n", listener.ID, listener.Protocol, addressString(address)) {
			_ = daemon.Shutdown(context.Background())
			return 1
		}
	}

	<-ctx.Done()
	if err := daemon.Shutdown(context.Background()); err != nil {
		if !writef(stderr, "daemon shutdown failed: %v\n", err) {
			return 1
		}
		return 1
	}
	return 0
}

func addressString(address net.Addr) string {
	if address == nil {
		return "<unknown>"
	}
	return address.String()
}

func writeText(w io.Writer, text string) {
	_, _ = io.WriteString(w, text)
}

func writef(w io.Writer, format string, args ...any) bool {
	_, err := fmt.Fprintf(w, format, args...)
	return err == nil
}
