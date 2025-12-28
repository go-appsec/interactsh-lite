package oobclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultOptions(t *testing.T) {
	t.Parallel()

	t.Run("has_server_urls", func(t *testing.T) {
		assert.NotEmpty(t, DefaultOptions.ServerURLs)
		assert.Contains(t, DefaultOptions.ServerURLs, "oast.pro")
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
		resp, err := client.Get(redirectServer.URL + "/start")
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
		assert.Equal(t, userAgent, uaTransport.userAgent)

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
		resp, err := client.Get(server.URL)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })

		assert.Equal(t, userAgent, receivedUA)
	})
}
