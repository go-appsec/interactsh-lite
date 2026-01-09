package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/go-harden/interactsh-lite/oobclient"
)

var (
	version = "dev"
	rev     = ""
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
		outputFile       string
		jsonOutput       bool
		verbose          bool
		payloadStore     bool
		payloadStoreFile string
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

	pflag.StringVarP(&outputFile, "output", "o", "", "Output file path")
	pflag.BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	pflag.BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	pflag.BoolVar(&payloadStore, "payload-store", false, "Store payloads to file")
	pflag.BoolVar(&payloadStore, "ps", false, "Store payloads to file")
	pflag.StringVar(&payloadStoreFile, "payload-store-file", "interactsh_payload.txt", "Payload store file path")
	pflag.StringVar(&payloadStoreFile, "psf", "interactsh_payload.txt", "Payload store file path")

	pflag.BoolVar(&showVersion, "version", false, "Show version")
	pflag.BoolVar(&healthCheck, "health-check", false, "Run health check")
	pflag.BoolVar(&healthCheck, "hc", false, "Run health check")

	pflag.Parse()

	versionStr := version + "-" + rev

	if showVersion {
		fmt.Printf("interactshlite version %s\n", versionStr)
		os.Exit(0)
	}

	configPath := configFlag
	if configPath == "" {
		configPath = DefaultConfigPath()
	}

	if healthCheck {
		RunHealthCheck(os.Stdout, versionStr, configPath)
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
		cfg.CorrelationIDLength = cidLength
	}
	if pflag.Lookup("correlation-id-nonce-length").Changed || pflag.Lookup("cidn").Changed {
		cfg.CorrelationIDNonceLength = cidnLength
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
	if pflag.Lookup("json").Changed {
		cfg.JSON = jsonOutput
	}
	if pflag.Lookup("verbose").Changed {
		cfg.Verbose = verbose
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

	opts := &oobclient.Options{
		ServerURLs:               ParseCommaSeparated(cfg.Server),
		Token:                    cfg.Token,
		KeepAliveInterval:        cfg.KeepAliveInterval,
		DisableHTTPFallback:      cfg.NoHTTPFallback,
		CorrelationIdLength:      cfg.CorrelationIDLength,
		CorrelationIdNonceLength: cfg.CorrelationIDNonceLength,
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
		payloads[i] = client.URL()
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

	pollInterval := time.Duration(cfg.PollInterval) * time.Second
	if err := client.StartPolling(pollInterval, func(i *oobclient.Interaction) {
		if shouldDisplay(i, cfg.DNSOnly, cfg.HTTPOnly, cfg.SMTPOnly, matchRegexes, filterRegexes) {
			var fmtErr error
			if cfg.JSON {
				fmtErr = formatJSON(output, i)
			} else {
				fmtErr = formatStandard(output, i, cfg.Verbose)
			}
			if fmtErr != nil {
				_, _ = fmt.Fprintf(os.Stderr, "[WRN] Format error: %v\n", fmtErr)
			}
		}
	}); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[ERR] Could not start polling: %v\n", err)
		_ = client.Close()
		os.Exit(1)
	}

	<-sigCh

	if client.IsPolling() {
		_ = client.StopPolling()
	}

	if sessionFile != "" {
		if saveErr := client.SaveSession(sessionFile); saveErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[WRN] Could not save session: %v\n", saveErr)
		}
	}

	_ = client.Close()
	// exit normally
}

// expandPatterns expands pattern values that may be files or comma-separated patterns.
func expandPatterns(values []string) ([]string, error) {
	var result []string
	for _, v := range values {
		if info, err := os.Stat(v); err == nil && !info.IsDir() {
			f, err := os.Open(v)
			if err != nil {
				return nil, err
			}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					result = append(result, line)
				}
			}
			if err := scanner.Err(); err != nil {
				_ = f.Close()
				return nil, err
			}
			_ = f.Close()
		} else {
			result = append(result, ParseCommaSeparated(v)...)
		}
	}
	return result, nil
}
