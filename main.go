// Command upspin-webdav serves the upspin name space over WebDAV.
//
// This requires no passwords on localhost, and is therefore insecure if
// running on a multi-user system.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"

	"upspin.io/config"
	"upspin.io/flags"
)

func main() {
	addr := flag.String("http", "localhost:http", "HTTP listen address")
	flags.Parse(flags.Client)

	if err := isLocal(*addr); err != nil {
		exit(err)
	}

	cfg, err := config.FromFile(flags.Config)
	if err != nil {
		exit(err)
	}

	fs, err := newFilesystem(cfg)
	if err != nil {
		exit(err)
	}

	srv := &http.Server{
		Addr:    *addr,
		Handler: fs,
	}
	exit(srv.ListenAndServe())
}

func exit(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// isLocal returns an error if the given address is not a loopback address.
func isLocal(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if !ip.IsLoopback() {
			return fmt.Errorf("cannot listen on non-loopback address %q", addr)
		}
	}
	return nil
}