package oobclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResponseConfig_IsAllowedUnauthenticated(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  *ResponseConfig
		want bool
	}{
		{"nil_config", nil, true},
		{"valid_302_redirect", &ResponseConfig{StatusCode: 302, Headers: []string{"Location: https://example.com"}}, true},
		{"valid_307_redirect", &ResponseConfig{StatusCode: 307, Headers: []string{"Location: https://example.com"}}, true},
		{"wrong_status_200", &ResponseConfig{StatusCode: 200, Headers: []string{"Location: https://example.com"}}, false},
		{"wrong_status_301", &ResponseConfig{StatusCode: 301, Headers: []string{"Location: https://example.com"}}, false},
		{"no_location", &ResponseConfig{StatusCode: 302, Headers: []string{"Content-Type: text/html"}}, false},
		{"empty_headers", &ResponseConfig{StatusCode: 307}, false},
		{"zero_status", &ResponseConfig{Headers: []string{"Location: https://example.com"}}, false},
		{"case_insensitive", &ResponseConfig{StatusCode: 302, Headers: []string{"LOCATION: https://example.com"}}, true},
		{"extra_header_rejected", &ResponseConfig{StatusCode: 302, Headers: []string{"Location: https://example.com", "X-Extra: val"}}, false},
		{"malformed_header", &ResponseConfig{StatusCode: 302, Headers: []string{"no-colon"}}, false},
		{"redirect_with_body", &ResponseConfig{StatusCode: 302, Headers: []string{"Location: https://example.com"}, Body: "redirecting..."}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.cfg.IsAllowedUnauthenticated())
		})
	}
}

func TestDefaultOptions(t *testing.T) {
	t.Parallel()

	t.Run("has_server_urls", func(t *testing.T) {
		assert.NotEmpty(t, DefaultOptions.ServerURLs)
		assert.Contains(t, DefaultOptions.ServerURLs, "alpha.oastsrv.net")
	})

	t.Run("http_timeout_set", func(t *testing.T) {
		assert.Equal(t, 10*time.Second, DefaultOptions.HTTPTimeout)
	})

	t.Run("keep_alive_interval_set", func(t *testing.T) {
		assert.Equal(t, 60*time.Second, DefaultOptions.KeepAliveInterval)
	})

	t.Run("correlation_id_lengths", func(t *testing.T) {
		assert.Equal(t, 20, DefaultOptions.CorrelationIdLength)
		assert.Equal(t, 13, DefaultOptions.CorrelationIdNonceLength)
	})
}

func TestNewSecureHTTPClient(t *testing.T) {
	t.Parallel()

	t.Run("respects_timeout", func(t *testing.T) {
		client := newSecureHTTPClient(5 * time.Second)
		assert.Equal(t, 5*time.Second, client.Timeout)
	})

	t.Run("does_not_follow_redirects", func(t *testing.T) {
		redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/start" {
				http.Redirect(w, r, "/end", http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("reached redirect target"))
		}))
		t.Cleanup(redirectServer.Close)

		client := newSecureHTTPClient(5 * time.Second)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, redirectServer.URL+"/start", nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		// ErrUseLastResponse causes nil error with the redirect response returned
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })

		// Should get the redirect response, not follow it
		assert.Equal(t, http.StatusFound, resp.StatusCode)
		assert.Equal(t, "/end", resp.Header.Get("Location"))
	})

	t.Run("transport_configured", func(t *testing.T) {
		client := newSecureHTTPClient(10 * time.Second)
		uaTransport, ok := client.Transport.(*userAgentTransport)
		require.True(t, ok)
		assert.Equal(t, "Mozilla/5.0 (compatible; go-appsec/interactsh-lite@"+Version+")", uaTransport.userAgent)

		transport, ok := uaTransport.base.(*http.Transport)
		require.True(t, ok)
		assert.Equal(t, 5*time.Second, transport.TLSHandshakeTimeout)
	})

	t.Run("sets_user_agent_header", func(t *testing.T) {
		var receivedUA string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedUA = r.Header.Get("User-Agent")
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(server.Close)

		client := newSecureHTTPClient(5 * time.Second)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })

		assert.Equal(t, "Mozilla/5.0 (compatible; go-appsec/interactsh-lite@"+Version+")", receivedUA)
	})
}
