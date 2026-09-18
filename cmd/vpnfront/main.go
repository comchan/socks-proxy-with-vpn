package main

import (
	"context"
	"os"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/app"
)

func main() {
	os.Exit(app.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
