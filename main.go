package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/go-appsec/interactsh-lite/oobclient"
)

func main() {
	var (
		serverFlag       string
		configFlag       string
		numberFlag       int
		tokenFlag        string
		pollIntervalFlag int
		noHTTPFallback   bool
		cidLength        int
		cidnLength       int
		sessionFile      string
		keepAliveFlag    time.Duration
		matchPatterns    []string
		filterPatterns   []string
		dnsOnly          bool
		httpOnly         bool
		smtpOnly         bool
		ftpOnly          bool
		ldapOnly         bool
		outputFile       string
		jsonOutput       bool
		verbose          bool
		payloadStore     bool
		payloadStoreFile string
		timeoutFlag      time.Duration
		countFlag        int
		showVersion      bool
		healthCheck      bool
	)

	pflag.StringVarP(&serverFlag, "server", "s", "", "Interactsh server(s) to use (comma-separated)")
	pflag.StringVar(&configFlag, "config", "", "Path to config file")
	pflag.IntVarP(&numberFlag, "number", "n", 0, "Number of payloads to generate")
	pflag.StringVarP(&tokenFlag, "token", "t", "", "Authentication token for protected server")
	pflag.IntVar(&pollIntervalFlag, "poll-interval", 0, "Poll interval in seconds")
	pflag.IntVar(&pollIntervalFlag, "pi", 0, "Poll interval in seconds")
	pflag.BoolVar(&noHTTPFallback, "no-http-fallback", false, "Disable HTTP fallback")
	pflag.BoolVar(&noHTTPFallback, "nf", false, "Disable HTTP fallback")
	pflag.IntVar(&cidLength, "correlation-id-length", 0, "Length of correlation ID")
	pflag.IntVar(&cidLength, "cidl", 0, "Length of correlation ID")
	pflag.IntVar(&cidnLength, "correlation-id-nonce-length", 0, "Length of correlation ID nonce")
	pflag.IntVar(&cidnLength, "cidn", 0, "Length of correlation ID nonce")
	pflag.StringVar(&sessionFile, "session-file", "", "Session file for persistence")
	pflag.StringVar(&sessionFile, "sf", "", "Session file for persistence")
	pflag.DurationVar(&keepAliveFlag, "keep-alive-interval", 0, "Keep-alive interval")
	pflag.DurationVar(&keepAliveFlag, "kai", 0, "Keep-alive interval")

	pflag.StringSliceVarP(&matchPatterns, "match", "m", nil, "Match patterns (regex)")
	pflag.StringSliceVarP(&filterPatterns, "filter", "f", nil, "Filter patterns (regex)")
	pflag.BoolVar(&dnsOnly, "dns-only", false, "Display only DNS interactions")
	pflag.BoolVar(&httpOnly, "http-only", false, "Display only HTTP interactions")
	pflag.BoolVar(&smtpOnly, "smtp-only", false, "Display only SMTP interactions")
	pflag.BoolVar(&ftpOnly, "ftp-only", false, "Display only FTP interactions")
	pflag.BoolVar(&ldapOnly, "ldap-only", false, "Display only LDAP interactions")

	pflag.StringVarP(&outputFile, "output", "o", "", "Output file path")
	pflag.BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	pflag.BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	pflag.BoolVar(&payloadStore, "payload-store", false, "Store payloads to file")
	pflag.BoolVar(&payloadStore, "ps", false, "Store payloads to file")
	pflag.StringVar(&payloadStoreFile, "payload-store-file", "interactsh_payload.txt", "Payload store file path")
	pflag.StringVar(&payloadStoreFile, "psf", "interactsh_payload.txt", "Payload store file path")

	pflag.DurationVar(&timeoutFlag, "timeout", 0, "Exit after specified duration (e.g. 30s, 5m)")
	pflag.IntVarP(&countFlag, "count", "c", 0, "Exit after receiving N interactions")

	pflag.BoolVar(&showVersion, "version", false, "Show version")
	pflag.BoolVar(&healthCheck, "health-check", false, "Run health check")
	pflag.BoolVar(&healthCheck, "hc", false, "Run health check")

	pflag.Parse()

	if showVersion {
		fmt.Printf("interactsh-lite version %s\n", oobclient.Version)
		os.Exit(0)
	}

	configPath := configFlag
	if configPath == "" {
		configPath = DefaultConfigPath()
	}

	if healthCheck {
		runHealthCheck(os.Stdout, oobclient.Version, configPath)
		os.Exit(0)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[ERR] Could not load config: %v\n", err)
		os.Exit(1)
	}

	if pflag.Lookup("server").Changed {
		cfg.Server = serverFlag
	}
	if pflag.Lookup("token").Changed {
		cfg.Token = tokenFlag
	}
	if pflag.Lookup("number").Changed {
		cfg.Number = numberFlag
	}
	if pflag.Lookup("poll-interval").Changed || pflag.Lookup("pi").Changed {
		cfg.PollInterval = pollIntervalFlag
	}
	if pflag.Lookup("no-http-fallback").Changed || pflag.Lookup("nf").Changed {
		cfg.NoHTTPFallback = noHTTPFallback
	}
	if pflag.Lookup("correlation-id-length").Changed || pflag.Lookup("cidl").Changed {
		cfg.CorrelationIdLength = cidLength
	}
	if pflag.Lookup("correlation-id-nonce-length").Changed || pflag.Lookup("cidn").Changed {
		cfg.CorrelationIdNonceLength = cidnLength
	}
	if pflag.Lookup("keep-alive-interval").Changed || pflag.Lookup("kai").Changed {
		cfg.KeepAliveInterval = keepAliveFlag
	}
	if pflag.Lookup("dns-only").Changed {
		cfg.DNSOnly = dnsOnly
	}
	if pflag.Lookup("http-only").Changed {
		cfg.HTTPOnly = httpOnly
	}
	if pflag.Lookup("smtp-only").Changed {
		cfg.SMTPOnly = smtpOnly
	}
	if pflag.Lookup("ftp-only").Changed {
		cfg.FTPOnly = ftpOnly
	}
	if pflag.Lookup("ldap-only").Changed {
		cfg.LDAPOnly = ldapOnly
	}
	if pflag.Lookup("json").Changed {
		cfg.JSON = jsonOutput
	}
	if pflag.Lookup("verbose").Changed {
		cfg.Verbose = verbose
	}
	if pflag.Lookup("timeout").Changed {
		cfg.Timeout = timeoutFlag
	}
	if pflag.Lookup("count").Changed {
		cfg.Count = countFlag
	}

	if cfg.Timeout < 0 {
		_, _ = fmt.Fprintf(os.Stderr, "[ERR] --timeout must not be negative\n")
		os.Exit(1)
	}
	if cfg.Count < 0 {
		_, _ = fmt.Fprintf(os.Stderr, "[ERR] --count must not be negative\n")
		os.Exit(1)
	}

	allMatchPatterns, err := expandPatterns(matchPatterns)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[ERR] Could not read match patterns: %v\n", err)
		os.Exit(1)
	}
	allFilterPatterns, err := expandPatterns(filterPatterns)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[ERR] Could not read filter patterns: %v\n", err)
		os.Exit(1)
	}

	matchRegexes, err := compilePatterns(allMatchPatterns, "match")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[ERR] %v\n", err)
		os.Exit(1)
	}
	filterRegexes, err := compilePatterns(allFilterPatterns, "filter")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[ERR] %v\n", err)
		os.Exit(1)
	}

	writers := make([]io.Writer, 1, 2)
	writers[0] = os.Stdout
	var outFile *os.File
	if outputFile != "" {
		outFile, err = os.Create(outputFile)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[ERR] Could not open output file: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = outFile.Close() }()
		writers = append(writers, outFile)
	}
	output := io.MultiWriter(writers...)

	opts := oobclient.Options{
		ServerURLs:               ParseCommaSeparated(cfg.Server),
		Token:                    cfg.Token,
		KeepAliveInterval:        cfg.KeepAliveInterval,
		DisableKeepAlive:         cfg.KeepAliveInterval <= 0,
		DisableHTTPFallback:      cfg.NoHTTPFallback,
		CorrelationIdLength:      cfg.CorrelationIdLength,
		CorrelationIdNonceLength: cfg.CorrelationIdNonceLength,
	}

	ctx := context.Background()
	var client *oobclient.Client

	if sessionFile != "" {
		if _, statErr := os.Stat(sessionFile); statErr == nil {
			client, err = oobclient.LoadSession(ctx, sessionFile, opts)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "[ERR] Could not load session: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("[INF] Loaded session from %s\n", sessionFile)
		}
	}

	if client == nil {
		client, err = oobclient.New(ctx, opts)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[ERR] Could not create client: %v\n", err)
			os.Exit(1)
		}
	}

	payloadCount := cfg.Number
	if payloadCount < 1 {
		payloadCount = 1
	}

	payloads := make([]string, payloadCount)
	for i := range payloads {
		payloads[i] = client.Domain()
	}

	fmt.Printf("[INF] Listing %d payload for OOB Testing\n", payloadCount)
	for _, p := range payloads {
		fmt.Printf("[INF] %s\n", p)
	}

	if payloadStore {
		if f, createErr := os.Create(payloadStoreFile); createErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[WRN] Could not store payloads: %v\n", createErr)
		} else {
			for _, p := range payloads {
				_, _ = fmt.Fprintln(f, p)
			}
			_ = f.Close()
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	doneCh := make(chan struct{})
	var displayCount atomic.Int64

	pollInterval := time.Duration(cfg.PollInterval) * time.Second
	if err := client.StartPolling(pollInterval, func(i *oobclient.Interaction) {
		if shouldDisplay(i, cfg.DNSOnly, cfg.HTTPOnly, cfg.SMTPOnly, cfg.FTPOnly, cfg.LDAPOnly, matchRegexes, filterRegexes) {
			var fmtErr error
			if cfg.JSON {
				fmtErr = formatJSON(output, i)
			} else {
				fmtErr = formatStandard(output, i, cfg.Verbose)
			}
			if fmtErr != nil {
				_, _ = fmt.Fprintf(os.Stderr, "[WRN] Format error: %v\n", fmtErr)
			}
			if cfg.Count > 0 {
				if displayCount.Add(1) == int64(cfg.Count) {
					close(doneCh)
				}
			}
		}
	}); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[ERR] Could not start polling: %v\n", err)
		_ = client.Close()
		os.Exit(1)
	}

	var exitCode int

	var timeoutCh <-chan time.Time
	if cfg.Timeout > 0 {
		timeoutCh = time.After(cfg.Timeout)
	}

	var reason string
	select {
	case <-sigCh:
		reason = "signal"
	case <-timeoutCh:
		reason = "timeout"
	case <-doneCh:
		reason = "count"
	}

	if sessionFile != "" {
		_ = client.StopPolling()

		if saveErr := client.SaveSession(sessionFile); saveErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[WRN] Could not save session: %v\n", saveErr)
		}
	} else {
		_ = client.Close()
	}

	// All callbacks have completed. displayCount is final
	switch reason {
	case "signal":
		fmt.Println("[INF] Received interrupt, shutting down...")
	case "timeout":
		if cfg.Count > 0 {
			received := displayCount.Load()
			if received >= int64(cfg.Count) {
				fmt.Printf("[INF] Received %d/%d interactions, shutting down...\n", received, cfg.Count)
			} else {
				fmt.Printf("[INF] Timeout reached (%d/%d interactions received), shutting down...\n", received, cfg.Count)
				exitCode = 1
			}
		} else {
			fmt.Println("[INF] Timeout reached, shutting down...")
		}
	case "count":
		fmt.Printf("[INF] Received %d/%d interactions, shutting down...\n", displayCount.Load(), cfg.Count)
	}

	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

const dialTimeout = 10 * time.Second

func runHealthCheck(w io.Writer, version, configPath string) {
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
