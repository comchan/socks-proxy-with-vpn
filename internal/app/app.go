package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/version"
)

const usage = `vpnfront is a VPN-fronted HTTP and SOCKS proxy daemon.

The proxy listeners and tunnel backends will be added in later milestones.
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

	flags := flag.NewFlagSet("vpnfront", flag.ContinueOnError)
	flags.SetOutput(stderr)
	showVersion := flags.Bool("version", false, "print the version and exit")
	validateConfig := flags.String("validate-config", "", "validate a YAML or JSON configuration file")
	flags.Usage = func() {
		writeText(stderr, usage)
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
		if !writef(stdout, "vpnfront %s\n", version.Value) {
			return 1
		}
		return 0
	}

	flags.Usage()
	return 0
}

func writeText(w io.Writer, text string) {
	_, _ = io.WriteString(w, text)
}

func writef(w io.Writer, format string, args ...any) bool {
	_, err := fmt.Fprintf(w, format, args...)
	return err == nil
}
