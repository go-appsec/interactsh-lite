// Package oobsrv implements an interactsh-compatible OOB interaction server.
package oobsrv

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-appsec/interactsh-lite/oobclient"
)

// InteractionType is the canonical wire-format type from the client module.
type InteractionType = oobclient.Interaction

const (
	protocolDNS   = "dns"
	protocolFTP   = "ftp"
	protocolHTTP  = "http"
	protocolHTTPS = "https"
	protocolLDAP  = "ldap"
	protocolSMTP  = "smtp"
)

// Service is the lifecycle interface for protocol listeners and background services.
type Service interface {
	// Name returns the service identifier for logging.
	Name() string
	// Start begins listening. Returns an error if binding fails.
	Start() error
	// Close shuts down the service and releases bound ports.
	Close() error
}

// Server manages HTTP routing, middleware, and protocol service lifecycle.
type Server struct {
	cfg      Config
	logger   *slog.Logger
	handler  http.Handler
	svcMu    sync.Mutex // protects services during concurrent startup
	services []Service
	storage  Storage

	// per-protocol interaction counters (all requests)
	dnsCount  atomic.Uint64
	httpCount atomic.Uint64
	smtpCount atomic.Uint64
	ldapCount atomic.Uint64
	ftpCount  atomic.Uint64

	// per-protocol matched interaction counters (correlation ID matched).
	// FTP and LDAP are excluded: FTP uses a shared extra bucket with no correlation matching,
	// and LDAP matches per-search operation rather than per-connection so the count would not correspond to ldapCount.
	dnsMatched  atomic.Uint64
	httpMatched atomic.Uint64
	smtpMatched atomic.Uint64

	// Shared interaction buckets for poll response
	tldBuckets  map[string]*SharedBucket // keyed by domain, for --wildcard
	extraBucket *SharedBucket            // for token-scoped services (FTP, LDAP)

	// DNS subsystem
	ips           ServerIPs
	customRecords customRecords
	acmeStore     *acmeStore

	// TLS
	tlsConfig *tls.Config

	// HTTP response caching (loaded at startup)
	defaultHTTPResponse []byte // cached --default-http-response file content
	httpIndex           []byte // cached --http-index file content

	ftpTempDir string // auto-created FTP temp dir; empty if user-supplied
}

// New creates a Server and configures the HTTP handler chain.
func New(cfg Config, logger *slog.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	records, err := loadCustomRecords(cfg.CustomRecords)
	if err != nil {
		return nil, fmt.Errorf("custom records: %w", err)
	}

	// normalize domains for consistent matching
	for i, d := range cfg.Domains {
		cfg.Domains[i] = strings.ToLower(d)
	}

	// sort longest-first for most-specific suffix matching
	slices.SortFunc(cfg.Domains, func(a, b string) int {
		return len(b) - len(a)
	})

	s := &Server{
		cfg:           cfg,
		logger:        logger,
		customRecords: records,
		acmeStore:     newACMEStore(),
	}

	// setup storage
	if s.cfg.Disk {
		ds, err := NewDiskStorage(s.cfg, s.logger)
		if err != nil {
			return nil, fmt.Errorf("disk backend: %w", err)
		}
		s.storage = ds
		s.logger.Info("storage initialized", "backend", "disk", "path", ds.dbPath)
	} else {
		s.storage = NewMemoryStorage(s.cfg, s.logger)
		s.logger.Info("storage initialized", "backend", "memory")
	}

	evictionTTL := time.Duration(s.cfg.Eviction) * 24 * time.Hour

	if s.cfg.Wildcard {
		s.tldBuckets = make(map[string]*SharedBucket, len(s.cfg.Domains))
		for _, domain := range s.cfg.Domains {
			s.tldBuckets[domain] = NewSharedBucket(s.cfg.MaxSharedInteractions, evictionTTL)
		}
	}
	if s.cfg.Auth && (s.cfg.FTP || s.cfg.LDAP) {
		s.extraBucket = NewSharedBucket(s.cfg.MaxSharedInteractions, evictionTTL)
	}

	// Set up the HTTP mux and middleware chains
	mux := http.NewServeMux()

	serverHeader := s.cfg.Domains[0]
	if s.cfg.ServerHeader != "" {
		serverHeader = s.cfg.ServerHeader
	}

	// API middleware chain: handler -> auth -> CORS -> response headers
	wrapAPI := func(h http.Handler) http.Handler {
		h = AuthMiddleware(s.cfg.Auth, s.cfg.Token, h)
		h = CORSMiddleware(s.cfg.ACAOUrl, h)
		h = ResponseHeadersMiddleware(serverHeader, s.cfg.Version, s.cfg.DisableVersion, true, h)
		return h
	}

	mux.Handle("POST /register", wrapAPI(http.HandlerFunc(s.handleRegister)))
	mux.Handle("GET /poll", wrapAPI(http.HandlerFunc(s.handlePoll)))
	mux.Handle("POST /deregister", wrapAPI(http.HandlerFunc(s.handleDeregister)))

	if s.cfg.Metrics {
		mux.Handle("GET /metrics", wrapAPI(http.HandlerFunc(s.handleMetrics)))
	}

	// Default handler (HTTP interaction capture + response routing)
	// Middleware chain (outermost -> innermost): logger -> hostname -> response headers -> CORS -> handler
	// Response headers wrap outside CORS so OPTIONS short-circuits still
	// include Server and X-Interactsh-Version. hostname runs before both so
	// the recorder has hostname/domain populated for the logger callback.
	h := InteractionCORSMiddleware(http.HandlerFunc(s.serveDefault))
	h = ResponseHeadersMiddleware(serverHeader, s.cfg.Version, s.cfg.DisableVersion, false, h)
	h = s.hostnameMiddleware(h)
	h = LoggerMiddleware(s.cfg.OriginIPHeader, s.onHTTPInteraction, h)
	mux.Handle("/", h)

	// Top-level: max request size wraps the entire mux
	s.handler = MaxRequestSizeMiddleware(s.cfg.MaxRequestSize, mux)

	return s, nil
}

// Handler returns the HTTP handler for testing or custom setups.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// Start runs the service startup sequence in dependency order.
func (s *Server) Start(ctx context.Context) error {
	if s.cfg.EnablePprof {
		if err := s.startPprof(); err != nil {
			return fmt.Errorf("pprof: %w", err)
		}
	}

	if err := s.resolveIPs(); err != nil {
		return fmt.Errorf("ip resolution: %w", err)
	}

	if err := s.startDNS(); err != nil {
		return err
	}

	s.provisionTLS(ctx)

	if err := s.loadHTTPFiles(); err != nil {
		return fmt.Errorf("http files: %w", err)
	}

	if err := s.startHTTP(); err != nil {
		return err
	}

	// Non-fatal services: start concurrently
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.startHTTPS(); err != nil {
			s.logger.Warn("HTTPS start failed, skipping", "error", err)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.startSMTP()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.startLDAP()
	}()
	if s.cfg.FTP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.startFTP()
		}()
	}
	wg.Wait()

	return nil
}

// Shutdown closes all services concurrently in reverse startup order, waits for completion, then closes storage.
func (s *Server) Shutdown() {
	var wg sync.WaitGroup
	for i := len(s.services) - 1; i >= 0; i-- {
		svc := s.services[i]
		wg.Add(1)
		go func() {
			defer wg.Done()

			s.logger.Info("closing service", "name", svc.Name())
			if err := svc.Close(); err != nil {
				s.logger.Error("error closing service", "name", svc.Name(), "error", err)
			}
		}()
	}
	wg.Wait()
	s.closeStorage()
	if s.ftpTempDir != "" {
		_ = os.RemoveAll(s.ftpTempDir)
	}
}

func (s *Server) addService(svc Service) {
	s.svcMu.Lock()
	s.services = append(s.services, svc)
	s.svcMu.Unlock()
}

// loadHTTPFiles caches file content for --default-http-response and --http-index.
func (s *Server) loadHTTPFiles() error {
	if s.cfg.DefaultHTTPResponse != "" {
		data, err := os.ReadFile(s.cfg.DefaultHTTPResponse)
		if err != nil {
			return fmt.Errorf("--default-http-response: %w", err)
		}
		s.defaultHTTPResponse = data
	}
	if s.cfg.HTTPIndex != "" {
		data, err := os.ReadFile(s.cfg.HTTPIndex)
		if err != nil {
			return fmt.Errorf("--http-index: %w", err)
		}
		s.httpIndex = data
	}
	return nil
}

// storeMatchedInteractions stores an interaction for each correlation ID match.
// UniqueID and FullId are set from each match. Passed by value to avoid
// mutating the caller's copy.
func (s *Server) storeMatchedInteractions(matches []Match, interaction InteractionType) {
	for _, match := range matches {
		interaction.UniqueID = match.UniqueID
		interaction.FullId = match.FullID
		if data, err := json.Marshal(interaction); err != nil {
			s.logger.Error("failed to marshal interaction", "error", err)
		} else if err = s.storage.AppendInteraction(match.UniqueID, data); err != nil {
			s.logger.Error("failed to store interaction", "error", err, "correlation-id", match.UniqueID)
		}
	}
}

// captureWildcard stores an interaction in the TLD bucket for the domain. No-op when wildcard is disabled.
func (s *Server) captureWildcard(domain string, interaction InteractionType) {
	if !s.cfg.Wildcard || s.tldBuckets == nil {
		return
	}
	bucket, ok := s.tldBuckets[domain]
	if !ok {
		return
	}
	data, err := json.Marshal(interaction)
	if err != nil {
		return
	}
	bucket.Append(data)
}

// captureInteraction runs wildcard + correlation matching + store for DNS, HTTP,
// and SMTP. Pass scanInput="" to disable ScanEverywhere mode.
// Returns true if at least one correlation ID matched.
func (s *Server) captureInteraction(domain, matchInput, scanInput string, wildcardInteraction, storeInteraction InteractionType) bool {
	s.captureWildcard(domain, wildcardInteraction)

	var matches []Match
	if scanInput != "" && s.cfg.ScanEverywhere {
		matches = MatchCorrelationIDEverywhere(scanInput, s.cfg.CorrelationIdLength, s.storage.HasCorrelationID)
	} else {
		matches = MatchCorrelationID(matchInput, s.cfg.CorrelationIdLength, s.cfg.Domains, s.storage.HasCorrelationID)
	}
	s.storeMatchedInteractions(matches, storeInteraction)
	return len(matches) > 0
}

func (s *Server) closeStorage() {
	if err := s.storage.Close(); err != nil {
		s.logger.Error("error closing storage", "error", err)
	}
}

// pprofService runs a pprof HTTP server on 127.0.0.1:8086.
type pprofService struct {
	logger *slog.Logger
	server *http.Server
}

func newPprofService(logger *slog.Logger) *pprofService {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	return &pprofService{
		logger: logger,
		server: &http.Server{
			Addr:    "127.0.0.1:8086",
			Handler: mux,
		},
	}
}

func (p *pprofService) Name() string { return "pprof" }

func (p *pprofService) Start() error {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", p.server.Addr)
	if err != nil {
		return err
	}
	go func() {
		p.logger.Info("[PPROF] Listening on TCP " + ln.Addr().String())
		_ = p.server.Serve(ln)
	}()
	return nil
}

func (p *pprofService) Close() error {
	return p.server.Close()
}

func (s *Server) startPprof() error {
	svc := newPprofService(s.logger)
	if err := svc.Start(); err != nil {
		return err
	}
	s.addService(svc)
	return nil
}
