package oobclient

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration tests that interact with our real Interactsh servers.
// These tests are skipped with -short flag to avoid external dependencies during CI.

// verifyHTTPInteraction triggers an HTTP request to the client's domain,
// polls for the interaction, and asserts it was received.
func verifyHTTPInteraction(t *testing.T, client *Client) {
	t.Helper()

	domain := client.Domain()

	httpClient := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+domain, nil) // https to verify tls cert
	require.NoError(t, err)
	resp, err := httpClient.Do(req)
	if err == nil {
		require.NoError(t, resp.Body.Close())
	}

	assertHTTPInteraction(t, client, domain)
}

func TestIntegration_SessionPersistence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	// Create client and save session
	client1, err := New(t.Context(), Options{
		ServerURLs:          DefaultOptions.ServerURLs[:2],
		DisableKeepAlive:    true,
		CorrelationIdLength: defaultServerCorrelationIdLength,
	})
	require.NoError(t, err)
	sessionPath := filepath.Join(t.TempDir(), "session.yaml")
	err = client1.SaveSession(sessionPath)
	require.NoError(t, err)

	// Close first client
	err = client1.Close()
	require.NoError(t, err)

	// Verify session file exists
	_, err = os.Stat(sessionPath)
	require.NoError(t, err)

	// Load session into new client
	client2, err := LoadSession(t.Context(), sessionPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client2.Close() })

	// Loaded session should preserve the correlation ID
	assert.Equal(t, client1.CorrelationID(), client2.CorrelationID())

	// Verify restored client can generate domains, trigger, and poll
	verifyHTTPInteraction(t, client2)
}

func TestIntegration_DefaultServers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	// Pure defaults: no ServerURLs, no cidl, no cidn overrides.
	// Exercises the default oastsrv.net path with cidl=16, cidn=4.
	client, err := New(t.Context(), Options{
		DisableKeepAlive: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	assert.Equal(t, defaultServerNonceLength, client.correlationIDNonceLength)
	assert.Len(t, client.CorrelationID(), defaultServerCorrelationIdLength)

	verifyHTTPInteraction(t, client)
}

func TestIntegration_ProjectDiscoveryServers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	client, err := New(t.Context(), Options{
		ServerURLs:       []string{"oast.me", "oast.pro"},
		DisableKeepAlive: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	assert.Equal(t, DefaultOptions.CorrelationIdNonceLength, client.correlationIDNonceLength)
	assert.Len(t, client.CorrelationID(), DefaultOptions.CorrelationIdLength)

	verifyHTTPInteraction(t, client)
}

func TestIntegration_FullLifecyclePerServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	for _, server := range DefaultOptions.ServerURLs {
		t.Run(server, func(t *testing.T) {
			t.Parallel()

			client, err := New(t.Context(), Options{
				ServerURLs:          []string{server},
				DisableKeepAlive:    true,
				CorrelationIdLength: defaultServerCorrelationIdLength,
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })

			verifyHTTPInteraction(t, client)
		})
	}
}

// assertHTTPInteraction polls the client until an interaction matching the
// given domain's full ID is found.
func assertHTTPInteraction(t *testing.T, client *Client, domain string) {
	t.Helper()

	fullId := strings.SplitN(domain, ".", 2)[0]
	var found bool
	var mu sync.Mutex
	done := make(chan struct{})

	err := client.StartPolling(10*time.Millisecond, func(i *Interaction) {
		mu.Lock()
		defer mu.Unlock()
		if !found && i.FullId == fullId && (i.Protocol == "http" || i.Protocol == "https") {
			found = true
			close(done)
		}
	})
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(60 * time.Second):
	}
	assert.NoError(t, client.StopPolling())

	mu.Lock()
	defer mu.Unlock()
	assert.True(t, found, "expected HTTP interaction for %s", domain)
}

func TestIntegration_RedirectToTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	httpClient := &http.Client{Timeout: 10 * time.Second}

	// Target client
	targetClient, err := New(t.Context(), Options{DisableKeepAlive: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = targetClient.Close() })

	targetDomain := targetClient.Domain()

	// Redirect client with session-stored 302 -> target
	redirectClient, err := New(t.Context(), Options{
		DisableKeepAlive: true,
		Response: &ResponseConfig{
			StatusCode: 302,
			Headers:    []string{"Location: https://" + targetDomain},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = redirectClient.Close() })

	// Hit redirect domain -> follows redirect to target
	redirectDomain := redirectClient.Domain()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+redirectDomain, nil)
	require.NoError(t, err)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	// After following redirect, final URL should be on the target domain
	assert.Contains(t, resp.Request.URL.Host, targetClient.CorrelationID())

	// Verify interactions on both clients
	assertHTTPInteraction(t, redirectClient, redirectDomain)
	assertHTTPInteraction(t, targetClient, targetDomain)

	// Param-encoded redirect to a different target subdomain (takes priority over session config)
	paramTargetDomain := targetClient.Domain()
	encodedURL := redirectClient.EncodedResponse(302, []string{"Location:https://" + paramTargetDomain}, "")
	req2, err := http.NewRequestWithContext(t.Context(), http.MethodGet, encodedURL, nil)
	require.NoError(t, err)
	resp2, err := httpClient.Do(req2)
	require.NoError(t, err)
	require.NoError(t, resp2.Body.Close())

	// Followed redirect should land on the param target, not the session-stored target
	assert.Contains(t, resp2.Request.URL.Host, targetClient.CorrelationID())
	assert.NotEqual(t, targetDomain, paramTargetDomain)

	// Verify param target interaction
	assertHTTPInteraction(t, targetClient, paramTargetDomain)
}
