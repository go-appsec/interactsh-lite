package oobclient

import (
	"net"
	"net/http"
	"time"
)

const userAgent = "go-harden/interactsh-lite-v0.1"

// Options configures the client behavior.
type Options struct {
	// ServerURLs specifies interactsh servers to try.
	// The list is shuffled and tried in random order until one succeeds.
	// Default: public interactsh servers (oast.pro, oast.live, etc.)
	ServerURLs []string

	// Token is an optional authentication token for protected servers.
	// Leave empty for public servers that don't require authentication.
	Token string

	// HTTPClient is an optional custom HTTP client.
	// If provided, HTTPTimeout is ignored.
	// The client should be configured to NOT follow redirects for security.
	// Default: secure client with timeouts and no redirect following.
	HTTPClient *http.Client

	// HTTPTimeout is the timeout for HTTP requests when using the default client.
	// Ignored if HTTPClient is provided.
	// Default: 10 seconds
	HTTPTimeout time.Duration

	// KeepAliveInterval is how often to re-register to prevent session eviction.
	// Set to 0 to disable keep-alive.
	// Default: 60 seconds
	KeepAliveInterval time.Duration

	// DisableHTTPFallback prevents falling back to HTTP if HTTPS fails.
	// Default: false (fallback enabled)
	DisableHTTPFallback bool

	// CorrelationIdLength is the length of the correlation ID preamble.
	// Default: 20
	CorrelationIdLength int

	// CorrelationIdNonceLength is the length of the nonce suffix for unique URLs.
	// Default: 13
	CorrelationIdNonceLength int
}

// DefaultOptions provides sensible defaults for most use cases.
// These defaults connect to public interactsh servers with standard timeouts.
var DefaultOptions = Options{
	ServerURLs:               []string{"oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me"},
	HTTPTimeout:              10 * time.Second,
	KeepAliveInterval:        60 * time.Second,
	CorrelationIdLength:      20,
	CorrelationIdNonceLength: 13,
}

// newSecureHTTPClient creates an HTTP client with secure defaults:
// - Does NOT follow redirects (returns error on redirect)
// - Reasonable timeouts for connection, TLS handshake, and total request
// - Connection pooling with sensible limits
// - Custom User-Agent header on all requests
func newSecureHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &userAgentTransport{
			base: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   5 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: timeout,
				IdleConnTimeout:       90 * time.Second,
				MaxIdleConns:          10,
				MaxIdleConnsPerHost:   2,
			},
			userAgent: userAgent,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Do not follow redirects
		},
	}
}

// userAgentTransport wraps an http.RoundTripper to add a User-Agent header to all requests.
type userAgentTransport struct {
	base      http.RoundTripper
	userAgent string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", t.userAgent)
	return t.base.RoundTrip(req)
}
