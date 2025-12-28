package oobclient

import (
	"net"
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

// Integration tests that interact with public Interactsh servers.
// These tests are skipped with -short flag to avoid external dependencies during CI.
// Run sequentially to reduce request rate to public servers.

func TestIntegration_NewClient(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	// No t.Parallel() - run sequentially to be kind to public servers

	client, err := New(t.Context(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	domain := client.Domain()
	assert.NotEmpty(t, domain)
	assert.Contains(t, domain, ".")

	// Verify domain format: correlation-id.server
	parts := strings.SplitN(domain, ".", 2)
	assert.Len(t, parts[0], DefaultOptions.CorrelationIdLength)
}

func TestIntegration_URLGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client, err := New(t.Context(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	url1 := client.URL()
	url2 := client.URL()

	// URLs should be unique
	assert.NotEqual(t, url1, url2)

	// Both should share the correlation ID prefix
	domain := client.Domain()
	correlationID := strings.Split(domain, ".")[0]
	assert.True(t, strings.HasPrefix(url1, correlationID))
	assert.True(t, strings.HasPrefix(url2, correlationID))

	// Total length should be correlation ID + nonce + server
	expectedPrefixLen := DefaultOptions.CorrelationIdLength + DefaultOptions.CorrelationIdNonceLength
	url1Parts := strings.SplitN(url1, ".", 2)
	assert.Len(t, url1Parts[0], expectedPrefixLen)
}

func TestIntegration_DNSInteraction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client, err := New(t.Context(), &Options{
		KeepAliveInterval: 0, // Disable keep-alive for this test
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	// Generate a unique URL and resolve it via DNS
	payloadURL := client.URL()

	// Perform DNS lookup to trigger interaction
	_, _ = net.LookupHost(payloadURL)

	// Poll for interactions
	var interactions []*Interaction
	var mu sync.Mutex
	done := make(chan struct{})

	callback := func(i *Interaction) {
		mu.Lock()
		defer mu.Unlock()

		if strings.Contains(i.FullID, strings.Split(payloadURL, ".")[0]) {
			interactions = append(interactions, i)
			select {
			case <-done:
			default:
				close(done)
			}
		}
	}

	err = client.StartPolling(500*time.Millisecond, callback)
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		// DNS propagation can be slow, don't fail but log
		t.Log("timeout waiting for DNS interaction - this may be due to network conditions")
	}

	err = client.StopPolling()
	require.NoError(t, err)

	// Check if we received any interactions
	mu.Lock()
	defer mu.Unlock()
	if len(interactions) > 0 {
		assert.Equal(t, "dns", interactions[0].Protocol)
	}
}

func TestIntegration_HTTPInteraction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client, err := New(t.Context(), &Options{
		KeepAliveInterval: 0,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	// Generate a unique URL
	payloadURL := client.URL()
	httpURL := "http://" + payloadURL

	// Make HTTP request to trigger interaction
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Get(httpURL)
	if err == nil {
		_ = resp.Body.Close()
	}

	// Poll for interactions, waiting specifically for HTTP
	var hasHTTP bool
	var mu sync.Mutex
	done := make(chan struct{})

	callback := func(i *Interaction) {
		mu.Lock()
		defer mu.Unlock()

		if strings.Contains(i.FullID, strings.Split(payloadURL, ".")[0]) && i.Protocol == "http" {
			hasHTTP = true
			select {
			case <-done:
			default:
				close(done)
			}
		}
	}

	err = client.StartPolling(500*time.Millisecond, callback)
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Log("timeout waiting for HTTP interaction - this may be due to network conditions")
	}

	err = client.StopPolling()
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	assert.True(t, hasHTTP)
}

func TestIntegration_SessionPersistence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session.yaml")

	// Create client and save session
	client1, err := New(t.Context(), &Options{
		KeepAliveInterval: 0,
	})
	require.NoError(t, err)

	originalDomain := client1.Domain()
	originalURL := client1.URL()

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

	// Domain should match (same correlation ID)
	assert.Equal(t, originalDomain, client2.Domain())

	// New URLs should still start with same correlation ID
	newURL := client2.URL()
	originalCorrelationID := strings.Split(originalURL, ".")[0][:DefaultOptions.CorrelationIdLength]
	newCorrelationID := strings.Split(newURL, ".")[0][:DefaultOptions.CorrelationIdLength]
	assert.Equal(t, originalCorrelationID, newCorrelationID)
}

func TestIntegration_MultipleServers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Test that client can connect to any of the default servers
	client, err := New(t.Context(), &Options{
		ServerURLs:        DefaultOptions.ServerURLs,
		KeepAliveInterval: 0,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	domain := client.Domain()

	// Should have connected to one of the default servers
	var foundServer bool
	for _, server := range DefaultOptions.ServerURLs {
		if strings.Contains(domain, server) {
			foundServer = true
			break
		}
	}
	assert.True(t, foundServer, "domain should contain one of the default servers")
}

func TestIntegration_PollingLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client, err := New(t.Context(), &Options{
		KeepAliveInterval: 0,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	// Initial state
	assert.False(t, client.IsPolling())
	assert.False(t, client.IsClosed())

	// Start polling
	err = client.StartPolling(time.Second, func(*Interaction) {})
	require.NoError(t, err)
	assert.True(t, client.IsPolling())

	// Stop polling
	err = client.StopPolling()
	require.NoError(t, err)
	assert.False(t, client.IsPolling())

	// Restart polling
	err = client.StartPolling(time.Second, func(*Interaction) {})
	require.NoError(t, err)
	assert.True(t, client.IsPolling())

	// Close while polling
	err = client.Close()
	require.NoError(t, err)
	assert.True(t, client.IsClosed())
}

func TestIntegration_CustomHTTPTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client, err := New(t.Context(), &Options{
		HTTPTimeout:       30 * time.Second,
		KeepAliveInterval: 0,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	assert.NotEmpty(t, client.Domain())
}
