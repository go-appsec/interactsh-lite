package oobsrv

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/publicsuffix"
)

// certmagic certificate storage, relative to $HOME
const certmagicStoragePath = ".local/share/certmagic"

// ALPN list; non-h2 values are handled as HTTP/1.x by net/http, letting scanners
// with legacy ALPN offers complete the handshake so we can capture the interaction.
var serverNextProtos = []string{"h2", "http/1.1", "http/1.0", "spdy/3", "spdy/2", "spdy/1", "hq"}

type tlsErrorFilterHandler struct {
	slog.Handler
	verbose bool
}

func (h *tlsErrorFilterHandler) Handle(ctx context.Context, r slog.Record) error {
	if !h.verbose && strings.HasPrefix(r.Message, "http: TLS handshake error from ") {
		return nil // don't log handshake errors, frequent from scanners
	}
	return h.Handler.Handle(ctx, r)
}

func (h *tlsErrorFilterHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &tlsErrorFilterHandler{Handler: h.Handler.WithAttrs(attrs), verbose: h.verbose}
}

func (h *tlsErrorFilterHandler) WithGroup(name string) slog.Handler {
	return &tlsErrorFilterHandler{Handler: h.Handler.WithGroup(name), verbose: h.verbose}
}

// httpErrorLog builds http.Server.ErrorLog with TLS handshake noise filtered unless cfg.Debug is enabled.
func (s *Server) httpErrorLog() *log.Logger {
	h := &tlsErrorFilterHandler{Handler: s.logger.Handler(), verbose: s.cfg.Debug}
	return slog.NewLogLogger(h, slog.LevelError)
}

var defaultACMEResolvers = []string{
	"1.1.1.1:53",
	"1.0.0.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
}

// acmeProvider bridges certmagic's DNS-01 solver to the in-memory ACME challenge store.
// The DNS handler reads from the store (dns.go), no extra wiring needed.
type acmeProvider struct {
	store *acmeStore
}

// Compiler check that acmeProvider implements certmagic.DNSProvider.
var _ certmagic.DNSProvider = (*acmeProvider)(nil)

func (p *acmeProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	var appended []libdns.Record
	for _, rec := range recs {
		rr := rec.RR()
		if rr.Type != "TXT" {
			continue
		}
		fqdn := toFQDN(rr.Name, zone)
		p.store.Set(fqdn, rr.Data)
		appended = append(appended, rec)
	}
	return appended, nil
}

func (p *acmeProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	var deleted []libdns.Record
	for _, rec := range recs {
		rr := rec.RR()
		if rr.Type != "TXT" {
			continue
		}
		fqdn := toFQDN(rr.Name, zone)
		p.store.Delete(fqdn)
		deleted = append(deleted, rec)
	}
	return deleted, nil
}

// toFQDN builds an FQDN from relative name and zone, normalized via normalizeFQDN.
func toFQDN(name, zone string) string {
	return normalizeFQDN(libdns.AbsoluteName(name, zone))
}

// provisionTLS sets s.tlsConfig via custom certificates or ACME. Non-fatal on failure.
func (s *Server) provisionTLS(ctx context.Context) {
	if s.cfg.CertFile != "" && s.cfg.PrivKeyFile != "" {
		reloader, err := newCertReloader(s.cfg.CertFile, s.cfg.PrivKeyFile, s.logger)
		if err != nil {
			s.logger.Error("failed to load custom certificate", "error", err)
			return
		}
		if err := reloader.Start(); err != nil {
			s.logger.Error("failed to start cert reloader", "error", err)
			return
		}
		s.addService(reloader)
		s.tlsConfig = &tls.Config{
			GetCertificate: reloader.GetCertificate,
			NextProtos:     serverNextProtos,
		}
		s.logger.Info("TLS configured with custom certificate (auto-reload enabled)")
		return
	}

	if s.cfg.SkipACME {
		s.logger.Info("TLS disabled (--skip-acme)")
		return
	}

	tlsCfg, err := s.provisionACME(ctx)
	if err != nil {
		s.logger.Error("ACME provisioning failed, falling back to self-signed certificate", "error", err)

		tlsCfg, err = generateSelfSignedCert(s.cfg.Domains)
		if err != nil {
			s.logger.Error("self-signed certificate generation failed, continuing without TLS", "error", err)
			return
		}
		s.tlsConfig = tlsCfg
		s.logger.Warn("TLS configured with self-signed certificate (ACME unavailable)")
		return
	}
	s.tlsConfig = tlsCfg
	s.logger.Info("TLS configured via ACME")
}

// generateSelfSignedCert creates a self-signed certificate covering localhost
// and the configured domains (with wildcards). Fallback when ACME is unavailable.
func generateSelfSignedCert(domains []string) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	dnsNames := make([]string, 1, 1+len(domains)*2)
	dnsNames[0] = "localhost"
	for _, d := range domains {
		dnsNames = append(dnsNames, d, "*."+d)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
		NextProtos: serverNextProtos,
	}, nil
}

const defaultCertCheckInterval = 1 * time.Hour

// certReloader polls certificate files for changes and hot-swaps the active
// cert via GetCertificate. Implements Service for lifecycle management through
// Server.Shutdown - listeners close first (reverse order), then the reloader stops.
type certReloader struct {
	certPath  string
	keyPath   string
	cert      atomic.Pointer[tls.Certificate]
	modTimeNs atomic.Int64 // latest file mod time as unix nanos
	interval  time.Duration
	logger    *slog.Logger
	done      chan struct{}
	stopped   chan struct{} // closed when run exits
}

// Compiler check that certReloader implements Service.
var _ Service = (*certReloader)(nil)

func newCertReloader(certPath, keyPath string, logger *slog.Logger) (*certReloader, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("loading certificate: %w", err)
	}
	mt, err := latestModTime(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("stat certificate files: %w", err)
	}
	r := &certReloader{
		certPath: certPath,
		keyPath:  keyPath,
		interval: defaultCertCheckInterval,
		logger:   logger,
		done:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	r.cert.Store(&cert)
	r.modTimeNs.Store(mt.UnixNano())
	return r, nil
}

func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.cert.Load(), nil
}

func (r *certReloader) Name() string { return "cert-reloader" }
func (r *certReloader) Start() error { go r.run(); return nil }
func (r *certReloader) Close() error { close(r.done); <-r.stopped; return nil }

func (r *certReloader) run() {
	defer close(r.stopped)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.done:
			return
		case <-ticker.C:
			r.tryReload()
		}
	}
}

func (r *certReloader) tryReload() {
	mt, err := latestModTime(r.certPath, r.keyPath)
	if err != nil {
		r.logger.Warn("could not stat certificate files", "error", err)
		return
	}
	if mt.UnixNano() <= r.modTimeNs.Load() {
		return
	}
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		r.logger.Warn("could not reload certificate", "error", err)
		return
	}
	r.cert.Store(&cert)
	r.modTimeNs.Store(mt.UnixNano())
	r.logger.Info("reloaded TLS certificate", "cert", r.certPath)
}

// latestModTime returns the more recent modification time of two files.
func latestModTime(path1, path2 string) (time.Time, error) {
	info1, err := os.Stat(path1)
	if err != nil {
		return time.Time{}, err
	}
	info2, err := os.Stat(path2)
	if err != nil {
		return time.Time{}, err
	}
	if info2.ModTime().After(info1.ModTime()) {
		return info2.ModTime(), nil
	}
	return info1.ModTime(), nil
}

// provisionACME obtains wildcard certificates via Let's Encrypt DNS-01.
// A single certmagic.Config is shared across all domains so that one
// GetCertificate callback and one renewal loop covers everything.
func (s *Server) provisionACME(ctx context.Context) (*tls.Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("determining home directory: %w", err)
	}
	storagePath := filepath.Join(home, certmagicStoragePath)

	resolvers := s.cfg.Resolvers
	if len(resolvers) == 0 {
		resolvers = defaultACMEResolvers
	}

	provider := &acmeProvider{store: s.acmeStore}
	storage := &certmagic.FileStorage{Path: storagePath}

	// create a *zap.Logger for certmagic that demotes routine maintenance info messages to debug
	// while keeping actual certificate renewal/obtain success messages at info.
	level := zapcore.InfoLevel
	if s.cfg.Debug {
		level = zapcore.DebugLevel
	}
	cmLogger := zap.New(&certmagicFilterCore{
		Core: zapcore.NewCore(
			zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()),
			zapcore.AddSync(os.Stderr), level),
	})

	cfg := certmagic.NewDefault()
	cfg.Storage = storage
	cfg.Logger = cmLogger

	// Use the registerable domain (eTLD+1) for the ACME email
	emailDomain := s.cfg.Domains[0]
	if reg, err := publicsuffix.EffectiveTLDPlusOne(emailDomain); err == nil {
		emailDomain = reg
	}

	acmeIssuer := certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		Logger:                  cmLogger,
		CA:                      certmagic.LetsEncryptProductionCA,
		Email:                   "abuse@" + emailDomain,
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		DNS01Solver: &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: provider,
				Resolvers:   resolvers,
			},
		},
	})
	cfg.Issuers = []certmagic.Issuer{acmeIssuer}

	issuerKey := acmeIssuer.IssuerKey()
	var successCount int
	var errs []error

	for _, domain := range s.cfg.Domains {
		certKey := certmagic.StorageKeys.SiteCert(issuerKey, domain)
		cached := storage.Exists(ctx, certKey)

		if err := cfg.ManageSync(ctx, []string{domain, "*." + domain}); err != nil {
			errs = append(errs, fmt.Errorf("domain %s: %w", domain, err))
			s.logger.Error("ACME provisioning failed for domain", "domain", domain, "error", err)
			continue
		}

		if cached {
			s.logger.Info("ACME certificate loaded from disk", "domain", domain)
		} else {
			s.logger.Info("ACME certificate provisioned", "domain", domain)
		}
		successCount++
	}

	if successCount == 0 {
		return nil, fmt.Errorf("all domains failed: %w", errors.Join(errs...))
	}

	// certmagic's TLSConfig sets NextProtos for ACME TLS-ALPN; override
	// with the protocols we need for serving HTTP/2 and HTTP/1.1.
	tlsCfg := cfg.TLSConfig()
	tlsCfg.NextProtos = serverNextProtos

	// Wildcards match only one label, so deeper names (foo.cid.oscar.oastsrv.net) would fail the handshake.
	// Normalize the SNI to a single-label form under the best-matching configured domain so the *.<domain>
	// cert gets served. Clients see a cert name mismatch but the handshake completes and the interaction is captured.
	tlsCfg.GetCertificate = wildcardFallbackCertGetter(tlsCfg.GetCertificate, s.matchedDomain, s.cfg.Domains)

	return tlsCfg, nil
}

// wildcardFallbackCertGetter rewrites the SNI to wild.<domain> when the incoming name is
// deeper than a wildcard can match, then delegates to inner so certmagic serves the *.<domain> cert.
func wildcardFallbackCertGetter(inner func(*tls.ClientHelloInfo) (*tls.Certificate, error), match func(string) (string, bool), domains []string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := strings.ToLower(hello.ServerName)
		domain, ok := match(name)
		if ok && (name == domain || strings.Count(name, ".") <= strings.Count(domain, ".")+1) {
			return inner(hello) // exact domain or single label below it
		} else if !ok {
			if len(domains) == 0 {
				return inner(hello)
			}
			domain = domains[0] // empty or unrelated SNI, choose any domain
		}
		rewritten := *hello
		rewritten.ServerName = "wild." + domain
		return inner(&rewritten)
	}
}

// startHTTPS starts the HTTPS listener. Skipped if no TLS config.
func (s *Server) startHTTPS() error {
	if s.tlsConfig == nil {
		s.logger.Info("HTTPS disabled (no TLS config)")
		return nil
	}

	addr := net.JoinHostPort(s.cfg.ListenIP, strconv.Itoa(s.cfg.HTTPSPort))
	svc := &httpService{
		name:   "HTTPS",
		logger: s.logger,
		server: &http.Server{
			Addr:              addr,
			Handler:           s.handler,
			TLSConfig:         s.tlsConfig,
			ReadHeaderTimeout: 60 * time.Second,
			IdleTimeout:       2 * time.Minute,
			ErrorLog:          s.httpErrorLog(),
		},
	}
	if err := svc.Start(); err != nil {
		return fmt.Errorf("[HTTPS] bind %s: %w", addr, err)
	}
	s.addService(svc)
	return nil
}

// TLSConfig returns the shared TLS config, or nil. Used by SMTPS, FTPS, and LDAP StartTLS.
func (s *Server) TLSConfig() *tls.Config {
	return s.tlsConfig
}

// certmagicFilterCore demotes certmagic info messages to debug, except certificate renewal/obtain success messages.
type certmagicFilterCore struct {
	zapcore.Core
}

func (c *certmagicFilterCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if ent.Level == zapcore.InfoLevel &&
		// certificate renewal is logged at info
		!strings.Contains(ent.Message, "certificate renewed") &&
		!strings.Contains(ent.Message, "certificate obtained") {
		ent.Level = zapcore.DebugLevel
	}
	return c.Core.Check(ent, ce)
}

func (c *certmagicFilterCore) With(fields []zapcore.Field) zapcore.Core {
	return &certmagicFilterCore{Core: c.Core.With(fields)}
}
