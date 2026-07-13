package oobclient

import (
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

// ResponseConfig defines an HTTP response served for interactions matching a
// session's correlation ID. Supported only by the interactsh-lite server.
// On unauthenticated servers, only 302/307 redirects with a Location header are allowed.
type ResponseConfig struct {
	StatusCode int      `json:"status-code,omitempty" yaml:"status-code,omitempty"` // HTTP status code
	Headers    []string `json:"headers,omitempty" yaml:"headers,omitempty"`         // "Name: Value" format
	Body       string   `json:"body,omitempty" yaml:"body,omitempty"`               // response body
}

// IsAllowedUnauthenticated reports whether this config is valid for an unauthenticated server.
func (c *ResponseConfig) IsAllowedUnauthenticated() bool {
	if c == nil {
		return true
	}
	if c.StatusCode != 302 && c.StatusCode != 307 {
		return false
	} else if c.Body != "" {
		return false
	}
	var hasLocation bool
	for _, h := range c.Headers {
		name, _, ok := strings.Cut(h, ":")
		if !ok {
			return false
		} else if !strings.EqualFold(strings.TrimSpace(name), "location") {
			return false
		}
		hasLocation = true
	}
	return hasLocation
}

var Version = "dev"

func init() {
	if Version != "dev" {
		return
	} else if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		Version = info.Main.Version
	}
}

// Options configures the client behavior.
type Options struct {
	// ServerURLs specifies interactsh servers to try.
	// The list is tried starting at a random index, until one succeeds.
	// Default: public go-appsec servers (oscar.oastsrv.net, alpha.oastsrv.net, sierra.oastsrv.net, tango.oastsrv.net)
	ServerURLs []string

	// Token is an optional authentication token for protected servers.
	// Leave empty for public servers that don't require authentication.
	Token string

	// HTTPClient is an optional custom HTTP client. If provided, HTTPTimeout is ignored.
	HTTPClient *http.Client

	// HTTPTimeout is the timeout for HTTP requests when using the default client.
	// Ignored if HTTPClient is provided.
	// Default: 10 seconds
	HTTPTimeout time.Duration

	// KeepAliveInterval is how often to re-register to prevent session eviction.
	// Default: 60 seconds
	KeepAliveInterval time.Duration

	// DisableKeepAlive disables periodic re-registration.
	// When true, KeepAliveInterval is ignored.
	DisableKeepAlive bool

	// DisableHTTPFallback prevents falling back to HTTP if HTTPS fails.
	// Default: false (fallback enabled)
	DisableHTTPFallback bool

	// Response configures a stored HTTP response served for
	// interactions matching this session's correlation ID.
	// Supported only by the interactsh-lite server implementation.
	Response *ResponseConfig

	// CorrelationIdLength is the length of the correlation ID preamble.
	// Must match server configuration exactly. Cannot be customized with default servers.
	// Minimum: 4. Default: 16 for default servers, 20 for user-provided servers.
	CorrelationIdLength int

	// CorrelationIdNonceLength is the length of the nonce suffix for unique URLs.
	// Must be >= the server's configured cidn for interactions to be matched.
	// Minimum: 4. Default: 4 for default servers, 13 for user-provided servers.
	CorrelationIdNonceLength int
}

// DefaultOptions provides protocol-compatible defaults with go-appsec server URLs.
// CorrelationIdLength and CorrelationIdNonceLength use standard interactsh values
// safe for any server. When using the default server URLs, the client automatically
// applies optimized values (see defaultServer* constants).
var DefaultOptions = Options{
	ServerURLs:               []string{"oscar.oastsrv.net", "alpha.oastsrv.net", "sierra.oastsrv.net", "tango.oastsrv.net"},
	HTTPTimeout:              10 * time.Second,
	KeepAliveInterval:        60 * time.Second,
	CorrelationIdLength:      20,
	CorrelationIdNonceLength: 13,
}

// fallbackServerURLs are public interactsh servers tried when defaults all fail.
// Only used when the caller did not explicitly provide ServerURLs.
var fallbackServerURLs = []string{"oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me"}

// Optimized values for the default go-appsec servers (oastsrv.net).
// Applied automatically when using DefaultOptions.ServerURLs.
const (
	defaultServerCorrelationIdLength = 16
	defaultServerNonceLength         = 4
)

// Minimum values required by fallback servers (oast.*).
const (
	fallbackCorrelationIdLength = 20
	fallbackMinNonceLength      = 13
)

// newSecureHTTPClient creates an HTTP client with secure defaults.
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
			userAgent: "Mozilla/5.0 (compatible; go-appsec/interactsh-lite@" + Version + ")",
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Do not follow redirects
		},
	}
}

// userAgentTransport wraps an http.RoundTripper to add a User-Agent header.
type userAgentTransport struct {
	base      http.RoundTripper
	userAgent string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", t.userAgent)
	return t.base.RoundTrip(req)
}
