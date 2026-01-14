package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const dialTimeout = 5 * time.Second

// RunHealthCheck performs diagnostic checks and writes results to w.
func RunHealthCheck(w io.Writer, version, configPath string) {
	_, _ = fmt.Fprintf(w, "Version: %s\n", version)
	_, _ = fmt.Fprintf(w, "Operating System: %s\n", runtime.GOOS)
	_, _ = fmt.Fprintf(w, "Architecture: %s\n", runtime.GOARCH)
	_, _ = fmt.Fprintf(w, "Go Version: %s\n", runtime.Version())
	_, _ = fmt.Fprintf(w, "Compiler: %s\n", runtime.Compiler)

	// Config read check
	if _, err := os.ReadFile(configPath); err != nil {
		if os.IsNotExist(err) {
			_, _ = fmt.Fprintf(w, "Config file %q Read => Ok (file does not exist)\n", configPath)
		} else {
			_, _ = fmt.Fprintf(w, "Config file %q Read => Ko (%v)\n", configPath, err)
		}
	} else {
		_, _ = fmt.Fprintf(w, "Config file %q Read => Ok\n", configPath)
	}

	// Config write check
	if f, err := os.OpenFile(configPath, os.O_WRONLY|os.O_APPEND, 0644); err != nil {
		if os.IsNotExist(err) {
			dir := filepath.Dir(configPath)
			if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
				_, _ = fmt.Fprintf(w, "Config file %q Write => Ko (directory does not exist)\n", configPath)
			} else {
				_, _ = fmt.Fprintf(w, "Config file %q Write => Ok (file does not exist, directory writable)\n", configPath)
			}
		} else {
			_, _ = fmt.Fprintf(w, "Config file %q Write => Ko (%v)\n", configPath, err)
		}
	} else {
		_ = f.Close()
		_, _ = fmt.Fprintf(w, "Config file %q Write => Ok\n", configPath)
	}

	checkConnectivity(w, "udp", "UDP", "scanme.sh", "53")
	checkConnectivity(w, "tcp4", "IPv4", "scanme.sh", "80")
	checkConnectivity(w, "tcp6", "IPv6", "scanme.sh", "80")
}

func checkConnectivity(w io.Writer, network, label, host, port string) {
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.Dial(network, addr)
	if err != nil {
		_, _ = fmt.Fprintf(w, "%s connectivity to %s => Ko (%v)\n", label, addr, err)
		return
	}
	_ = conn.Close()
	_, _ = fmt.Fprintf(w, "%s connectivity to %s => Ok\n", label, addr)
}
