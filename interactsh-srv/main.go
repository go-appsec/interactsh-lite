package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/go-appsec/interactsh-lite/interactsh-srv/oobsrv"
	"github.com/go-appsec/interactsh-lite/oobclient"
)

var version = "dev"

func init() {
	if version != "dev" {
		return
	} else if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = info.Main.Version
	} else {
		version = oobclient.Version
	}
}

func main() {
	var (
		// Input flags
		domains          []string
		ips              []string
		listenIP         string
		eviction         int
		noEviction       bool
		evictionStrategy string
		auth             bool
		token            string
		acaoURL          string
		skipACME         bool
		scanEverywhere   bool
		cidLength        int
		cidnLength       int
		certFile         string
		privkeyFile      string
		originIPHeader   string
		maxRequestSize   int

		// Config flags
		configPath          string
		resolvers           []string
		dynamicResp         bool
		customRecords       string
		httpIndex           string
		httpDirectory       string
		defaultHTTPResponse string
		disk                bool
		diskPath            string
		serverHeader        string
		disableVersion      bool

		// Service flags
		dnsPort         int
		httpPort        int
		httpsPort       int
		smtpPort        int
		smtpsPort       int
		smtpAutoTLSPort int
		ldapPort        int
		ldap            bool
		wildcard        bool
		ftp             bool
		ftpPort         int
		ftpsPort        int
		ftpDir          string

		// Debug flags
		showVersion        bool
		debugFlag          bool
		verbose            bool
		enablePprof        bool
		healthCheck        bool
		metrics            bool
		disableUpdateCheck bool
		configUpdate       bool
	)

	defaults := oobsrv.DefaultConfig()

	pflag.StringSliceVarP(&domains, "domain", "d", nil, "Configured domain(s)")
	pflag.StringSliceVarP(&ips, "ip", "i", nil, "Public IP address(es)")
	pflag.StringVar(&listenIP, "listen-ip", defaults.ListenIP, "Bind address for all listeners")
	pflag.StringVar(&listenIP, "lip", defaults.ListenIP, "Bind address for all listeners")
	pflag.IntVarP(&eviction, "eviction", "e", defaults.Eviction, "Eviction TTL in days")
	pflag.BoolVar(&noEviction, "no-eviction", false, "Disable TTL-based eviction")
	pflag.BoolVar(&noEviction, "ne", false, "Disable TTL-based eviction")
	pflag.StringVar(&evictionStrategy, "eviction-strategy", defaults.EvictionStrategy, "Eviction strategy (sliding or fixed)")
	pflag.StringVar(&evictionStrategy, "es", defaults.EvictionStrategy, "Eviction strategy (sliding or fixed)")
	pflag.BoolVarP(&auth, "auth", "a", false, "Enable authentication")
	pflag.StringVarP(&token, "token", "t", "", "Authentication token")
	pflag.StringVar(&acaoURL, "acao-url", defaults.ACAOUrl, "CORS Access-Control-Allow-Origin value")
	pflag.BoolVar(&skipACME, "skip-acme", false, "Skip ACME certificate generation")
	pflag.BoolVar(&skipACME, "sa", false, "Skip ACME certificate generation")
	pflag.BoolVar(&scanEverywhere, "scan-everywhere", false, "Scan entire request for correlation IDs")
	pflag.BoolVar(&scanEverywhere, "se", false, "Scan entire request for correlation IDs")
	pflag.IntVar(&cidLength, "correlation-id-length", defaults.CorrelationIdLength, "Correlation ID length")
	pflag.IntVar(&cidLength, "cidl", defaults.CorrelationIdLength, "Correlation ID length")
	pflag.IntVar(&cidnLength, "correlation-id-nonce-length", 0, "Deprecated: ignored")
	pflag.IntVar(&cidnLength, "cidn", 0, "Deprecated: ignored")
	pflag.StringVar(&certFile, "cert", "", "Custom TLS certificate file path")
	pflag.StringVar(&privkeyFile, "privkey", "", "Custom TLS private key file path")
	pflag.StringVar(&originIPHeader, "origin-ip-header", "", "HTTP header for real client IP")
	pflag.StringVar(&originIPHeader, "oih", "", "HTTP header for real client IP")
	pflag.IntVar(&maxRequestSize, "max-request-size", defaults.MaxRequestSize, "Max request/message size in MB (0=unlimited)")
	pflag.IntVar(&maxRequestSize, "mrs", defaults.MaxRequestSize, "Max request/message size in MB (0=unlimited)")

	// Config flags
	pflag.StringVar(&configPath, "config", "", "Config file path")
	pflag.StringSliceVarP(&resolvers, "resolvers", "r", nil, "DNS resolvers for ACME")
	pflag.BoolVar(&dynamicResp, "dynamic-resp", false, "Enable dynamic HTTP responses")
	pflag.BoolVar(&dynamicResp, "dr", false, "Enable dynamic HTTP responses")
	pflag.StringVar(&customRecords, "custom-records", "", "Custom DNS records YAML file")
	pflag.StringVar(&customRecords, "cr", "", "Custom DNS records YAML file")
	pflag.StringVar(&httpIndex, "http-index", "", "Custom HTML index file")
	pflag.StringVar(&httpIndex, "hi", "", "Custom HTML index file")
	pflag.StringVar(&httpDirectory, "http-directory", "", "Static file directory for /s/")
	pflag.StringVar(&httpDirectory, "hd", "", "Static file directory for /s/")
	pflag.StringVar(&defaultHTTPResponse, "default-http-response", "", "File served for all HTTP requests")
	pflag.StringVar(&defaultHTTPResponse, "dhr", "", "File served for all HTTP requests")
	pflag.BoolVar(&disk, "disk", false, "Enable disk storage")
	pflag.BoolVar(&disk, "ds", false, "Enable disk storage")
	pflag.StringVar(&diskPath, "disk-path", "", "Disk storage directory")
	pflag.StringVar(&diskPath, "dsp", "", "Disk storage directory")
	pflag.StringVar(&serverHeader, "server-header", "", "Custom Server header value")
	pflag.StringVar(&serverHeader, "csh", "", "Custom Server header value")
	pflag.BoolVar(&disableVersion, "disable-version", false, "Suppress X-Interactsh-Version header")
	pflag.BoolVar(&disableVersion, "dv", false, "Suppress X-Interactsh-Version header")

	// Service flags
	pflag.IntVar(&dnsPort, "dns-port", defaults.DNSPort, "DNS server port")
	pflag.IntVar(&httpPort, "http-port", defaults.HTTPPort, "HTTP server port")
	pflag.IntVar(&httpsPort, "https-port", defaults.HTTPSPort, "HTTPS server port")
	pflag.IntVar(&smtpPort, "smtp-port", defaults.SMTPPort, "SMTP server port")
	pflag.IntVar(&smtpsPort, "smtps-port", defaults.SMTPSPort, "SMTPS server port")
	pflag.IntVar(&smtpAutoTLSPort, "smtp-autotls-port", defaults.SMTPAutoTLSPort, "SMTP implicit TLS port")
	pflag.IntVar(&ldapPort, "ldap-port", defaults.LDAPPort, "LDAP server port")
	pflag.BoolVar(&ldap, "ldap", false, "Enable LDAP full logging")
	pflag.BoolVar(&wildcard, "wildcard", false, "Enable root TLD capture")
	pflag.BoolVar(&wildcard, "wc", false, "Enable root TLD capture")
	pflag.BoolVar(&ftp, "ftp", false, "Enable FTP service")
	pflag.IntVar(&ftpPort, "ftp-port", defaults.FTPPort, "FTP server port")
	pflag.IntVar(&ftpsPort, "ftps-port", defaults.FTPSPort, "FTPS server port")
	pflag.StringVar(&ftpDir, "ftp-dir", "", "FTP root directory")

	// Debug flags
	pflag.BoolVar(&showVersion, "version", false, "Print version and exit")
	pflag.BoolVar(&debugFlag, "debug", false, "Enable debug logging")
	pflag.BoolVarP(&verbose, "verbose", "v", false, "Verbose interaction logging")
	pflag.BoolVar(&enablePprof, "enable-pprof", false, "Enable pprof on 127.0.0.1:8086")
	pflag.BoolVar(&enablePprof, "ep", false, "Enable pprof on 127.0.0.1:8086")
	pflag.BoolVar(&healthCheck, "health-check", false, "Run diagnostics and exit")
	pflag.BoolVar(&healthCheck, "hc", false, "Run diagnostics and exit")
	pflag.BoolVar(&metrics, "metrics", false, "Enable /metrics endpoint")
	pflag.BoolVar(&disableUpdateCheck, "disable-update-check", false, "No-op, accepted for compatibility")
	pflag.BoolVar(&disableUpdateCheck, "duc", false, "No-op, accepted for compatibility")
	pflag.BoolVar(&configUpdate, "config-update", false, "Write merged config to file and exit")

	pflag.Parse()

	if showVersion {
		fmt.Printf("interactsh-srv version %s\n", version)
		os.Exit(0)
	}

	// Config file path
	cfgPath := configPath
	configExplicit := pflag.Lookup("config").Changed
	if cfgPath == "" {
		cfgPath = DefaultConfigPath()
	}

	if healthCheck {
		runHealthCheck(os.Stdout, version, cfgPath, configExplicit)
		os.Exit(0)
	}

	// Load YAML config
	cfg, err := LoadConfig(cfgPath, configExplicit)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[ERR] Could not load config: %v\n", err)
		os.Exit(1)
	}

	// CLI flags override YAML values
	if flagChanged("domain") {
		cfg.Domains = domains
	}
	if flagChanged("ip") {
		cfg.IPs = ips
	}
	if flagChanged("listen-ip", "lip") {
		cfg.ListenIP = listenIP
	}
	if flagChanged("eviction") {
		cfg.Eviction = eviction
	}
	if flagChanged("no-eviction", "ne") {
		cfg.NoEviction = noEviction
	}
	if flagChanged("eviction-strategy", "es") {
		cfg.EvictionStrategy = evictionStrategy
	}
	if flagChanged("auth") {
		cfg.Auth = auth
	}
	if flagChanged("token") {
		cfg.Token = token
	}
	if flagChanged("acao-url") {
		cfg.ACAOUrl = acaoURL
	}
	if flagChanged("skip-acme", "sa") {
		cfg.SkipACME = skipACME
	}
	if flagChanged("scan-everywhere", "se") {
		cfg.ScanEverywhere = scanEverywhere
	}
	if flagChanged("correlation-id-length", "cidl") {
		cfg.CorrelationIdLength = cidLength
	}
	if flagChanged("cert") {
		cfg.CertFile = certFile
	}
	if flagChanged("privkey") {
		cfg.PrivKeyFile = privkeyFile
	}
	if flagChanged("origin-ip-header", "oih") {
		cfg.OriginIPHeader = originIPHeader
	}
	if flagChanged("max-request-size", "mrs") {
		cfg.MaxRequestSize = maxRequestSize
	}
	if flagChanged("resolvers") {
		cfg.Resolvers = resolvers
	}
	if flagChanged("dynamic-resp", "dr") {
		cfg.DynamicResp = dynamicResp
	}
	if flagChanged("custom-records", "cr") {
		cfg.CustomRecords = customRecords
	}
	if flagChanged("http-index", "hi") {
		cfg.HTTPIndex = httpIndex
	}
	if flagChanged("http-directory", "hd") {
		cfg.HTTPDirectory = httpDirectory
	}
	if flagChanged("default-http-response", "dhr") {
		cfg.DefaultHTTPResponse = defaultHTTPResponse
	}
	if flagChanged("disk", "ds") {
		cfg.Disk = disk
	}
	if flagChanged("disk-path", "dsp") {
		cfg.DiskPath = diskPath
	}
	if flagChanged("server-header", "csh") {
		cfg.ServerHeader = serverHeader
	}
	if flagChanged("disable-version", "dv") {
		cfg.DisableVersion = disableVersion
	}
	if flagChanged("dns-port") {
		cfg.DNSPort = dnsPort
	}
	if flagChanged("http-port") {
		cfg.HTTPPort = httpPort
	}
	if flagChanged("https-port") {
		cfg.HTTPSPort = httpsPort
	}
	if flagChanged("smtp-port") {
		cfg.SMTPPort = smtpPort
	}
	if flagChanged("smtps-port") {
		cfg.SMTPSPort = smtpsPort
	}
	if flagChanged("smtp-autotls-port") {
		cfg.SMTPAutoTLSPort = smtpAutoTLSPort
	}
	if flagChanged("ldap-port") {
		cfg.LDAPPort = ldapPort
	}
	if flagChanged("ldap") {
		cfg.LDAP = ldap
	}
	if flagChanged("wildcard", "wc") {
		cfg.Wildcard = wildcard
	}
	if flagChanged("ftp") {
		cfg.FTP = ftp
	}
	if flagChanged("ftp-port") {
		cfg.FTPPort = ftpPort
	}
	if flagChanged("ftps-port") {
		cfg.FTPSPort = ftpsPort
	}
	if flagChanged("ftp-dir") {
		cfg.FTPDir = ftpDir
	}
	if flagChanged("debug") {
		cfg.Debug = debugFlag
	}
	if flagChanged("enable-pprof", "ep") {
		cfg.EnablePprof = enablePprof
	}
	if flagChanged("metrics") {
		cfg.Metrics = metrics
	}

	// Auto-enable auth
	if cfg.Auth || cfg.Token != "" || cfg.FTP || cfg.LDAP || cfg.Wildcard {
		cfg.Auth = true
		if cfg.Token == "" {
			tokenBytes := make([]byte, 32)
			if _, err := rand.Read(tokenBytes); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "[ERR] Could not generate auth token: %v\n", err)
				os.Exit(1)
			}
			cfg.Token = hex.EncodeToString(tokenBytes)
		}
	}

	// Expand resolvers (file path disambiguation)
	if len(cfg.Resolvers) > 0 {
		cfg.Resolvers, err = ExpandResolvers(cfg.Resolvers)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[ERR] Could not expand resolvers: %v\n", err)
			os.Exit(1)
		}
	}

	// Environment variable overrides
	if envMax := os.Getenv("INTERACTSH_MAX_SHARED_INTERACTIONS"); envMax != "" {
		if v, err := strconv.Atoi(envMax); err == nil && v > 0 {
			cfg.MaxSharedInteractions = v
		}
	}

	if err := cfg.Validate(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[ERR] %v\n", err)
		os.Exit(1)
	}

	cfg.Version = version

	// Set up logger
	logLevel := slog.LevelInfo
	if cfg.Debug || verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(&cleanHandler{level: logLevel, w: os.Stderr, mu: &sync.Mutex{}})

	if configUpdate {
		if err := SaveConfig(cfgPath, cfg); err != nil {
			logger.Error(fmt.Sprintf("Could not save config: %v", err))
			os.Exit(1)
		}
		logger.Info("Config written: " + cfgPath)
		os.Exit(0)
	}

	// Deprecation warnings
	if flagChanged("correlation-id-nonce-length", "cidn") {
		logger.Warn("--correlation-id-nonce-length is deprecated and ignored")
	}

	// Startup logging
	logger.Info("starting interactsh-srv",
		"version", version,
		"domains", cfg.Domains,
		"listen-ip", cfg.ListenIP,
		"http-port", cfg.HTTPPort,
		"dns-port", cfg.DNSPort,
	)
	if cfg.Auth {
		logger.Info("authentication enabled", "token", cfg.Token)
	}

	// Create and start server
	srv, err := oobsrv.New(cfg, logger)
	if err != nil {
		logger.Error(fmt.Sprintf("Could not create server: %v", err))
		os.Exit(1)
	}

	if err := srv.Start(context.Background()); err != nil {
		logger.Error(fmt.Sprintf("Could not start server: %v", err))
		os.Exit(1)
	}

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info(fmt.Sprintf("Received signal %s, shutting down", sig))

	srv.Shutdown()
}

// flagChanged returns true if any of the named flags were explicitly set.
func flagChanged(names ...string) bool {
	for _, n := range names {
		if f := pflag.Lookup(n); f != nil && f.Changed {
			return true
		}
	}
	return false
}

// runHealthCheck prints diagnostics and returns. The caller should exit after.
func runHealthCheck(w io.Writer, ver, configPath string, configExplicit bool) {
	_, _ = fmt.Fprintf(w, "interactsh-srv %s\n", ver)
	_, _ = fmt.Fprintf(w, "OS: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	_, _ = fmt.Fprintf(w, "Go: %s\n", runtime.Version())
	_, _ = fmt.Fprintln(w)

	// Config file readability
	if _, err := os.Stat(configPath); err != nil {
		if os.IsNotExist(err) && !configExplicit {
			_, _ = fmt.Fprintf(w, "Config: %s (not found)\n", configPath)
		} else {
			_, _ = fmt.Fprintf(w, "Config: %s (ERROR: %v)\n", configPath, err)
		}
	} else {
		if _, err := os.ReadFile(configPath); err != nil {
			_, _ = fmt.Fprintf(w, "Config: %s (ERROR: %v)\n", configPath, err)
		} else {
			_, _ = fmt.Fprintf(w, "Config: %s (readable)\n", configPath)
		}
	}
	_, _ = fmt.Fprintln(w)

	dialer := net.Dialer{Timeout: 5 * time.Second}
	ctx := context.Background()

	// UDP
	udpConn, err := dialer.DialContext(ctx, "udp", "scanme.sh:53")
	if err != nil {
		_, _ = fmt.Fprintf(w, "UDP  (scanme.sh:53): FAIL (%v)\n", err)
	} else {
		_ = udpConn.Close()
		_, _ = fmt.Fprintf(w, "UDP  (scanme.sh:53): OK\n")
	}

	// TCP IPv4
	tcpV4, err := dialer.DialContext(ctx, "tcp4", "scanme.sh:80")
	if err != nil {
		_, _ = fmt.Fprintf(w, "TCP4 (scanme.sh:80): FAIL (%v)\n", err)
	} else {
		_ = tcpV4.Close()
		_, _ = fmt.Fprintf(w, "TCP4 (scanme.sh:80): OK\n")
	}

	// TCP IPv6
	tcpV6, err := dialer.DialContext(ctx, "tcp6", "scanme.sh:80")
	if err != nil {
		_, _ = fmt.Fprintf(w, "TCP6 (scanme.sh:80): FAIL (%v)\n", err)
	} else {
		_ = tcpV6.Close()
		_, _ = fmt.Fprintf(w, "TCP6 (scanme.sh:80): OK\n")
	}
}

// cleanHandler outputs gologger-style log lines: [LVL] message key=value ...
type cleanHandler struct {
	level slog.Level
	w     io.Writer
	mu    *sync.Mutex
	attrs []slog.Attr
}

func (h *cleanHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level
}

func (h *cleanHandler) Handle(_ context.Context, r slog.Record) error {
	var tag string
	switch {
	case r.Level >= slog.LevelError:
		tag = "[ERR]"
	case r.Level >= slog.LevelWarn:
		tag = "[WRN]"
	case r.Level >= slog.LevelInfo:
		tag = "[INF]"
	default:
		tag = "[DBG]"
	}

	var b strings.Builder
	b.WriteString(tag)
	b.WriteByte(' ')
	b.WriteString(r.Message)
	for _, a := range h.attrs {
		fmt.Fprintf(&b, " %s=%s", a.Key, a.Value)
	}
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%s", a.Key, a.Value)
		return true
	})
	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *cleanHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs), len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	return &cleanHandler{level: h.level, w: h.w, mu: h.mu, attrs: append(newAttrs, attrs...)}
}

func (h *cleanHandler) WithGroup(_ string) slog.Handler {
	return h
}
