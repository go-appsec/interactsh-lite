package oobsrv

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const defaultBannerHTML = `<h1>Interactsh-lite Server</h1>

<a href='https://github.com/go-appsec/interactsh-lite'><b>Interactsh-lite</b></a> is an open-source tool for detecting out-of-band interactions. It is designed to detect vulnerabilities that cause external network interactions.<br><br>

If you notice interactions with <b>*.%s</b> in your logs, it's possible that someone (security engineers, pen-testers, bug-bounty hunters) has been testing your application.<br><br>

You should investigate the service that generated these interactions, examine the root cause, and if a vulnerability exists, take the necessary steps to mitigate the issue.`

// maxDynamicDelay caps the ?delay= query parameter to prevent goroutine exhaustion.
const maxDynamicDelay = 2 * time.Hour

// stripHostPort removes the port from a host:port string.
func stripHostPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return h
}

// matchDomain returns the configured domain matching host. Falls back to first domain.
func (s *Server) matchDomain(host string) string {
	if d, ok := s.matchedDomain(strings.ToLower(host)); ok {
		return d
	}
	return s.cfg.Domains[0]
}

// hostnameMiddleware populates hostname/domain on the response recorder before
// downstream middleware (e.g. CORS) can short-circuit the request.
func (s *Server) hostnameMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rec, ok := w.(*responseRecorder); ok {
			hostname := strings.ToLower(stripHostPort(r.Host))
			rec.hostname = hostname
			if d, ok := s.matchedDomain(hostname); ok {
				rec.domain = d
			}
		}
		next.ServeHTTP(w, r)
	})
}

// onHTTPInteraction captures HTTP interactions for the logger middleware callback.
func (s *Server) onHTTPInteraction(r *http.Request, rawReq, rawResp, remoteAddr, hostname, domain string) {
	s.httpCount.Add(1)

	if domain == "" && !s.cfg.ScanEverywhere {
		return
	}

	protocol := "http"
	if r.TLS != nil {
		protocol = "https"
	}

	now := time.Now().UTC()

	s.captureInteraction(domain, hostname, rawReq,
		InteractionType{
			Protocol:      protocol,
			UniqueID:      hostname,
			FullId:        hostname,
			RawRequest:    rawReq,
			RawResponse:   rawResp,
			RemoteAddress: remoteAddr,
			Timestamp:     now,
		}, InteractionType{
			Protocol:      protocol,
			RawRequest:    rawReq,
			RawResponse:   rawResp,
			RemoteAddress: remoteAddr,
			Timestamp:     now,
		})
}

// serveDefault handles non-API requests with priority-based response routing.
// hostname/domain are already set on the recorder by hostnameMiddleware.
func (s *Server) serveDefault(w http.ResponseWriter, r *http.Request) {
	hostname := strings.ToLower(stripHostPort(r.Host))
	domain := s.matchDomain(hostname)

	reflection := ReflectURL(hostname, s.cfg.CorrelationIdLength, s.storage.HasCorrelationID)

	// Priority 1: --default-http-response
	if s.defaultHTTPResponse != nil {
		body := strings.ReplaceAll(string(s.defaultHTTPResponse), "{DOMAIN}", domain)
		_, _ = io.WriteString(w, body)
		return
	}

	// Priority 2: /s/ static file serving
	if s.cfg.HTTPDirectory != "" && strings.HasPrefix(r.URL.Path, "/s/") {
		s.serveStaticFile(w, r)
		return
	}

	// Priority 3: default banner (root path, no reflection)
	if r.URL.Path == "/" && reflection == "" {
		s.serveBanner(w, domain)
		return
	}

	// Priority 4: content-type routing
	if s.serveContentTyped(w, r, reflection) {
		return
	}

	// Priority 5: dynamic response parameters
	if s.cfg.DynamicResp && s.serveDynamic(w, r) {
		return
	}

	// Priority 6: default HTML fallback
	w.Header().Set("Content-Type", "text/html")
	_, _ = fmt.Fprintf(w, "<html><head></head><body>%s</body></html>", reflection)
}

// serveBanner writes the custom index page or the built-in banner.
func (s *Server) serveBanner(w http.ResponseWriter, domain string) {
	w.Header().Set("Content-Type", "text/html")
	if s.httpIndex != nil {
		body := strings.ReplaceAll(string(s.httpIndex), "{DOMAIN}", domain)
		_, _ = io.WriteString(w, body)
		return
	}
	_, _ = fmt.Fprintf(w, defaultBannerHTML, domain)
}

// serveStaticFile serves files from --http-directory under /s/. No directory listing.
func (s *Server) serveStaticFile(w http.ResponseWriter, r *http.Request) {
	filePath, ok := strings.CutPrefix(r.URL.Path, "/s/")
	if !ok || filePath == "" {
		http.NotFound(w, r)
		return
	}

	// Sanitize path to prevent directory traversal
	cleaned := path.Clean("/" + filePath)
	if cleaned == "/" {
		http.NotFound(w, r)
		return
	}

	// Resolve symlinks and verify the path stays within the configured directory
	fullPath := filepath.Join(s.cfg.HTTPDirectory, filepath.FromSlash(cleaned))
	resolved, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	resolvedRoot, err := filepath.EvalSymlinks(s.cfg.HTTPDirectory)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if resolved != resolvedRoot && !strings.HasPrefix(resolved, resolvedRoot+string(filepath.Separator)) {
		http.NotFound(w, r)
		return
	}

	f, err := os.Open(resolved)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if stat.IsDir() { // No directory listing
		http.NotFound(w, r)
		return
	}

	// Apply dynamic params (header/delay/status only, not body/b64_body)
	if s.cfg.DynamicResp {
		applyDynamicParams(w, r)
	}

	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
}

// applyDynamicParams applies delay, header, and status query parameters.
func applyDynamicParams(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	if d := q.Get("delay"); d != "" {
		if secs, err := strconv.Atoi(d); err == nil && secs > 0 {
			delay := min(time.Duration(secs)*time.Second, maxDynamicDelay)
			t := time.NewTimer(delay)
			select {
			case <-t.C:
			case <-r.Context().Done():
			}
			t.Stop()
		}
	}

	for _, h := range q["header"] {
		if name, value, ok := strings.Cut(h, ":"); ok {
			w.Header().Set(strings.TrimSpace(name), strings.TrimSpace(value))
		}
	}

	if st := q.Get("status"); st != "" {
		if code, err := strconv.Atoi(st); err == nil && code > 0 {
			w.WriteHeader(code)
		}
	}
}

// serveContentTyped handles /robots.txt, *.json, and *.xml. Returns true if matched. Values are intentionally unescaped.
func (s *Server) serveContentTyped(w http.ResponseWriter, r *http.Request, reflection string) bool {
	switch {
	case r.URL.Path == "/robots.txt":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "User-agent: *\nDisallow: / # %s", reflection)
		return true

	case strings.HasSuffix(r.URL.Path, ".json"):
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":"%s"}`, reflection)
		return true

	case strings.HasSuffix(r.URL.Path, ".xml"):
		w.Header().Set("Content-Type", "application/xml")
		_, _ = fmt.Fprintf(w, "<data>%s</data>", reflection)
		return true
	}
	return false
}

// serveDynamic handles dynamic response parameters. Returns true if triggered.
func (s *Server) serveDynamic(w http.ResponseWriter, r *http.Request) bool {
	q := r.URL.Query()

	// Check for /b64_body: path form
	var pathBody []byte
	var hasPathBody bool
	if encoded, ok := strings.CutPrefix(r.URL.Path, "/b64_body:"); ok {
		encoded, _ = strings.CutSuffix(encoded, "/")
		if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
			pathBody = decoded
			hasPathBody = true
		}
	}

	hasBody := q.Has("body")
	hasB64Body := q.Has("b64_body")

	if !hasPathBody && !hasBody && !hasB64Body && !q.Has("header") && !q.Has("status") && !q.Has("delay") {
		return false // No dynamic params triggered
	}

	applyDynamicParams(w, r)

	// Body (path form takes priority, then b64_body, then body)
	switch {
	case hasPathBody:
		_, _ = w.Write(pathBody)
	case hasB64Body:
		if decoded, err := base64.StdEncoding.DecodeString(q.Get("b64_body")); err == nil {
			_, _ = w.Write(decoded)
		}
	case hasBody:
		_, _ = io.WriteString(w, q.Get("body"))
	}

	return true
}
