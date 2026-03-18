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
	resp, err := httpClient.Get("https://" + domain) // https to verify tls cert
	if err == nil {
		_ = resp.Body.Close()
	}

	var found bool
	var mu sync.Mutex
	done := make(chan struct{})
	nonce := strings.Split(domain, ".")[0]
	err = client.StartPolling(10*time.Millisecond, func(i *Interaction) {
		mu.Lock()
		defer mu.Unlock()

		if strings.Contains(i.FullId, nonce) && (i.Protocol == "http" || i.Protocol == "https") {
			found = true
			select {
			case <-done:
			default:
				close(done)
			}
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
	assert.True(t, found, "expected HTTP interaction on %s", client.ServerHost())
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
