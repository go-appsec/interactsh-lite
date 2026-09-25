package oobsrv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// Overridable for testing
var (
	checkIPURL = "https://checkip.amazonaws.com/"
	udpTarget  = "scanme.sh:12345"
)

// ServerIPs holds IPv4 and IPv6 addresses for DNS responses.
type ServerIPs struct {
	IPv4 []net.IP
	IPv6 []net.IP
}

// ClassifyIPs sorts IP strings into IPv4 and IPv6 categories.
func ClassifyIPs(ips []string) ServerIPs {
	var result ServerIPs
	for _, s := range ips {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil {
			continue
		}

		if ip.To4() != nil {
			result.IPv4 = append(result.IPv4, ip.To4())
		} else {
			result.IPv6 = append(result.IPv6, ip)
		}
	}
	return result
}

// DetectIPs discovers public IPv4 and IPv6 addresses. Errors only if both
// fail; partial failure returns the detected family.
func DetectIPs(ctx context.Context, logger *slog.Logger) (ServerIPs, error) {
	var result ServerIPs
	var v4err, v6err error

	if ip, err := detectIPv4(ctx); err != nil {
		v4err = err
		logger.Warn("ipv4 auto-detection failed", "error", err)
	} else {
		result.IPv4 = []net.IP{ip}
	}

	if ip, err := detectIPv6(ctx); err != nil {
		v6err = err
		logger.Warn("ipv6 auto-detection failed", "error", err)
	} else {
		result.IPv6 = []net.IP{ip}
	}

	if v4err != nil && v6err != nil {
		return result, fmt.Errorf("ip auto-detection failed: %w (configure ips in config)", errors.Join(v4err, v6err))
	}
	return result, nil
}

func detectIPv4(ctx context.Context) (net.IP, error) {
	if ip, err := detectIPExternal(ctx, "tcp4"); err == nil && validateLocalIP(ip) {
		return ip, nil
	}
	return detectPublicUDP(ctx, "udp4")
}

func detectIPv6(ctx context.Context) (net.IP, error) {
	if ip, err := detectIPExternal(ctx, "tcp6"); err == nil && validateLocalIP(ip) {
		return ip, nil
	}
	return detectPublicUDP(ctx, "udp6")
}

// detectIPExternal queries an external service for the public IP.
func detectIPExternal(ctx context.Context, network string) (net.IP, error) {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("redirect not allowed")
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkIPURL, nil)
	if err != nil {
		return nil, fmt.Errorf("external ip check: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("external ip check: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("external ip check: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if ip == nil {
		return nil, fmt.Errorf("invalid ip from external service: %q", strings.TrimSpace(string(body)))
	}

	if ip.To4() != nil {
		return ip.To4(), nil
	}
	return ip, nil
}

// validateLocalIP checks if the ip matches any local network interface.
func validateLocalIP(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		var ifaceIP net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ifaceIP = v.IP
		case *net.IPAddr:
			ifaceIP = v.IP
		}
		if ifaceIP != nil && ifaceIP.Equal(ip) {
			return true
		}
	}
	return false
}

// isUsablePublicIP checks that an IP is globally routable and not private.
func isUsablePublicIP(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}

// detectPublicUDP accepts the UDP source address only when it's a usable public IP.
func detectPublicUDP(ctx context.Context, network string) (net.IP, error) {
	ip, err := detectIPUDP(ctx, network)
	if err != nil {
		return nil, err
	}
	if !isUsablePublicIP(ip) || !validateLocalIP(ip) {
		return nil, fmt.Errorf("udp source %v is not a usable public ip", ip)
	}
	return ip, nil
}
func detectIPUDP(ctx context.Context, network string) (net.IP, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, udpTarget)
	if err != nil {
		return nil, fmt.Errorf("udp dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return nil, fmt.Errorf("parsing local address: %w", err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid local ip: %q", host)
	}

	if ip.To4() != nil {
		return ip.To4(), nil
	}
	return ip, nil
}
