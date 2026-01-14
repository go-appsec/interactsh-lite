package oobclient

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateUUID4(t *testing.T) {
	t.Parallel()

	uuidPattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	t.Run("valid_format", func(t *testing.T) {
		uuid := generateUUID4()
		assert.Regexp(t, uuidPattern, uuid)
	})

	t.Run("unique_values", func(t *testing.T) {
		seen := make(map[string]bool)
		for i := 0; i < 100; i++ {
			uuid := generateUUID4()
			assert.False(t, seen[uuid], "duplicate UUID generated")
			seen[uuid] = true
		}
	})

	t.Run("version_4_bits", func(t *testing.T) {
		uuid := generateUUID4()
		assert.Equal(t, "4", string(uuid[14]))
	})

	t.Run("variant_bits", func(t *testing.T) {
		uuid := generateUUID4()
		variantChar := uuid[19]
		assert.Contains(t, "89ab", string(variantChar))
	})
}

func TestShuffleStrings(t *testing.T) {
	t.Parallel()

	t.Run("empty_slice", func(t *testing.T) {
		var s []string
		shuffleStrings(s)
		assert.Empty(t, s)
	})

	t.Run("single_element", func(t *testing.T) {
		s := []string{"a"}
		shuffleStrings(s)
		assert.Equal(t, []string{"a"}, s)
	})

	t.Run("preserves_elements", func(t *testing.T) {
		original := []string{"a", "b", "c", "d", "e"}
		s := make([]string, len(original))
		copy(s, original)

		shuffleStrings(s)

		assert.ElementsMatch(t, original, s)
	})

	t.Run("changes_order", func(t *testing.T) {
		original := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
		var unchanged int
		for i := 0; i < 10; i++ {
			s := make([]string, len(original))
			copy(s, original)
			shuffleStrings(s)
			if strings.Join(s, "") == strings.Join(original, "") {
				unchanged++
			}
		}
		// Statistically unlikely to remain unchanged all 10 times
		assert.Less(t, unchanged, 10)
	})
}

func TestEncodeDecodePublicKey(t *testing.T) {
	t.Parallel()

	t.Run("round_trip", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		encoded, err := encodePublicKey(&privateKey.PublicKey)
		require.NoError(t, err)
		assert.NotEmpty(t, encoded)

		decoded, err := decodePublicKey(encoded)
		require.NoError(t, err)
		assert.Equal(t, privateKey.E, decoded.E)
		assert.Equal(t, privateKey.N, decoded.N)
	})

	t.Run("deterministic_encoding", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		encoded1, err := encodePublicKey(&privateKey.PublicKey)
		require.NoError(t, err)

		encoded2, err := encodePublicKey(&privateKey.PublicKey)
		require.NoError(t, err)

		assert.Equal(t, encoded1, encoded2)
	})
}

func TestDecodePublicKey(t *testing.T) {
	t.Parallel()

	t.Run("invalid_base64", func(t *testing.T) {
		_, err := decodePublicKey("not-valid-base64!!!")
		assert.Error(t, err)
	})

	t.Run("invalid_pem", func(t *testing.T) {
		_, err := decodePublicKey("aGVsbG8gd29ybGQ=") // "hello world" in base64
		assert.Error(t, err)
	})
}

func TestZbase32Encoding(t *testing.T) {
	t.Parallel()

	t.Run("encodes_bytes", func(t *testing.T) {
		data := []byte{0x00, 0x01, 0x02, 0x03}
		encoded := zbase32Encoding.EncodeToString(data)
		assert.NotEmpty(t, encoded)
	})

	t.Run("no_padding", func(t *testing.T) {
		data := []byte{0x00, 0x01, 0x02}
		encoded := zbase32Encoding.EncodeToString(data)
		assert.NotContains(t, encoded, "=")
	})

	t.Run("uses_zbase32_alphabet", func(t *testing.T) {
		validChars := "ybndrfg8ejkmcpqxot1uwisza345h769"
		data := make([]byte, 100)
		_, _ = rand.Read(data)
		encoded := zbase32Encoding.EncodeToString(data)
		for _, c := range encoded {
			assert.Contains(t, validChars, string(c))
		}
	})
}

func TestClientStateMachine(t *testing.T) {
	t.Parallel()

	newMockServer := func(t *testing.T) *httptest.Server {
		t.Helper()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/register"):
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"message":"registration successful"}`))
			case strings.HasSuffix(r.URL.Path, "/deregister"):
				w.WriteHeader(http.StatusOK)
			case strings.HasSuffix(r.URL.Path, "/poll"):
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":[],"extra":[],"aes_key":""}`))
			}
		}))
		t.Cleanup(server.Close)
		return server
	}

	t.Run("start_stop_polling", func(t *testing.T) {
		server := newMockServer(t)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		assert.False(t, client.IsPolling())

		err = client.StartPolling(time.Second, func(*Interaction) {})
		require.NoError(t, err)
		assert.True(t, client.IsPolling())

		err = client.StopPolling()
		require.NoError(t, err)
		assert.False(t, client.IsPolling())
	})

	t.Run("double_start_returns_error", func(t *testing.T) {
		server := newMockServer(t)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		err = client.StartPolling(time.Second, func(*Interaction) {})
		require.NoError(t, err)

		err = client.StartPolling(time.Second, func(*Interaction) {})
		require.ErrorIs(t, err, ErrAlreadyPolling)
	})

	t.Run("stop_without_start_returns_error", func(t *testing.T) {
		server := newMockServer(t)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		err = client.StopPolling()
		require.ErrorIs(t, err, ErrNotPolling)
	})

	t.Run("close_stops_polling", func(t *testing.T) {
		server := newMockServer(t)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)

		err = client.StartPolling(time.Second, func(*Interaction) {})
		require.NoError(t, err)
		assert.True(t, client.IsPolling())

		err = client.Close()
		require.NoError(t, err)
		assert.True(t, client.IsClosed())
	})

	t.Run("operations_on_closed_client", func(t *testing.T) {
		server := newMockServer(t)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)

		err = client.Close()
		require.NoError(t, err)

		err = client.StartPolling(time.Second, func(*Interaction) {})
		require.ErrorIs(t, err, ErrClientClosed)

		err = client.StopPolling()
		require.ErrorIs(t, err, ErrClientClosed)
	})

	t.Run("close_is_idempotent", func(t *testing.T) {
		server := newMockServer(t)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)

		require.NoError(t, client.Close())
		require.NoError(t, client.Close())
		require.NoError(t, client.Close())
	})
}

func TestClientDomain(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"registration successful"}`))
	}))
	t.Cleanup(server.Close)

	client, err := New(t.Context(), &Options{
		ServerURLs:        []string{server.URL},
		KeepAliveInterval: 0,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	domain := client.Domain()

	serverURL, _ := url.Parse(server.URL)
	assert.Contains(t, domain, serverURL.Host)
	assert.Len(t, strings.Split(domain, ".")[0], DefaultOptions.CorrelationIdLength)
}

func TestClientURL(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"registration successful"}`))
	}))
	t.Cleanup(server.Close)

	client, err := New(t.Context(), &Options{
		ServerURLs:        []string{server.URL},
		KeepAliveInterval: 0,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	t.Run("contains_server_host", func(t *testing.T) {
		u := client.URL()
		serverURL, _ := url.Parse(server.URL)
		assert.Contains(t, u, serverURL.Host)
	})

	t.Run("unique_per_call", func(t *testing.T) {
		seen := make(map[string]bool)
		for i := 0; i < 100; i++ {
			u := client.URL()
			assert.False(t, seen[u], "duplicate URL generated")
			seen[u] = true
		}
	})

	t.Run("starts_with_correlation_id", func(t *testing.T) {
		u := client.URL()
		domain := client.Domain()
		correlationID := strings.Split(domain, ".")[0]
		assert.True(t, strings.HasPrefix(u, correlationID))
	})

	t.Run("correct_total_length", func(t *testing.T) {
		u := client.URL()
		parts := strings.SplitN(u, ".", 2)
		expectedLen := DefaultOptions.CorrelationIdLength + DefaultOptions.CorrelationIdNonceLength
		assert.Len(t, parts[0], expectedLen)
	})

	t.Run("nonce_is_zbase32", func(t *testing.T) {
		u := client.URL()
		parts := strings.SplitN(u, ".", 2)
		nonce := parts[0][DefaultOptions.CorrelationIdLength:]

		validChars := "ybndrfg8ejkmcpqxot1uwisza345h769"
		for _, c := range nonce {
			assert.Contains(t, validChars, string(c))
		}
	})
}

func TestSaveLoadSession(t *testing.T) {
	t.Parallel()

	newMockServer := func(t *testing.T) *httptest.Server {
		t.Helper()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		}))
		t.Cleanup(server.Close)
		return server
	}

	t.Run("round_trip", func(t *testing.T) {
		server := newMockServer(t)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		originalDomain := client.Domain()

		tmpDir := t.TempDir()
		sessionPath := filepath.Join(tmpDir, "session.yaml")

		err = client.SaveSession(sessionPath)
		require.NoError(t, err)

		// Verify file was created with restricted permissions
		info, err := os.Stat(sessionPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

		// Load session and verify
		loaded, err := LoadSession(t.Context(), sessionPath)
		require.NoError(t, err)
		t.Cleanup(func() { _ = loaded.Close() })

		assert.Equal(t, originalDomain, loaded.Domain())
	})

	t.Run("file_not_found", func(t *testing.T) {
		_, err := LoadSession(t.Context(), "/nonexistent/path/session.yaml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read session file")
	})

	t.Run("invalid_yaml", func(t *testing.T) {
		tmpDir := t.TempDir()
		sessionPath := filepath.Join(tmpDir, "session.yaml")
		require.NoError(t, os.WriteFile(sessionPath, []byte("not: valid: yaml: ["), 0600))

		_, err := LoadSession(t.Context(), sessionPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse session file")
	})

	t.Run("invalid_private_key", func(t *testing.T) {
		tmpDir := t.TempDir()
		sessionPath := filepath.Join(tmpDir, "session.yaml")

		sessionContent := `server-url: "http://example.com"
server-token: ""
private-key: "not-a-valid-private-key"
correlation-id: "test123"
secret-key: "secret"
public-key: "dGVzdA=="`

		require.NoError(t, os.WriteFile(sessionPath, []byte(sessionContent), 0600))

		_, err := LoadSession(t.Context(), sessionPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse private key")
	})

	t.Run("invalid_public_key", func(t *testing.T) {
		// First create a valid session
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		}))
		t.Cleanup(server.Close)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)

		tmpDir := t.TempDir()
		sessionPath := filepath.Join(tmpDir, "session.yaml")
		require.NoError(t, client.SaveSession(sessionPath))
		require.NoError(t, client.Close())

		// Read and corrupt the public key
		data, err := os.ReadFile(sessionPath)
		require.NoError(t, err)
		corrupted := strings.Replace(string(data), "public-key:", "public-key: \"not-valid-base64!!!\" #", 1)
		require.NoError(t, os.WriteFile(sessionPath, []byte(corrupted), 0600))

		_, err = LoadSession(t.Context(), sessionPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode public key")
	})

	t.Run("reregistration_failure", func(t *testing.T) {
		// First create a valid session with a working server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		}))

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)

		tmpDir := t.TempDir()
		sessionPath := filepath.Join(tmpDir, "session.yaml")
		require.NoError(t, client.SaveSession(sessionPath))
		require.NoError(t, client.Close())
		server.Close()

		// Now try to load with server gone
		_, err = LoadSession(t.Context(), sessionPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to re-register session")
	})
}

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("uses_default_options", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		}))
		t.Cleanup(server.Close)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		domain := client.Domain()
		correlationID := strings.Split(domain, ".")[0]
		assert.Len(t, correlationID, DefaultOptions.CorrelationIdLength)
	})

	t.Run("respects_custom_correlation_id_length", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		}))
		t.Cleanup(server.Close)

		client, err := New(t.Context(), &Options{
			ServerURLs:          []string{server.URL},
			KeepAliveInterval:   0,
			CorrelationIdLength: 10,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		domain := client.Domain()
		correlationID := strings.Split(domain, ".")[0]
		assert.Len(t, correlationID, 10)
	})

	t.Run("handles_authorization_token", func(t *testing.T) {
		var receivedToken string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedToken = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		}))
		t.Cleanup(server.Close)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			Token:             "test-token",
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		assert.Equal(t, "test-token", receivedToken)
	})

	t.Run("fails_all_servers", func(t *testing.T) {
		_, err := New(t.Context(), &Options{
			ServerURLs:          []string{"http://invalid.local:9999"},
			HTTPTimeout:         20 * time.Millisecond,
			KeepAliveInterval:   0,
			DisableHTTPFallback: true,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to register with any server")
		assert.Contains(t, err.Error(), "invalid.local:9999")
	})

	t.Run("unauthorized_error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		t.Cleanup(server.Close)

		_, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.ErrorIs(t, err, ErrUnauthorized)
		assert.Contains(t, err.Error(), "failed to register with any server")
	})

	t.Run("sends_valid_registration_request", func(t *testing.T) {
		var receivedBody registerRequest
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &receivedBody)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		}))
		t.Cleanup(server.Close)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		assert.NotEmpty(t, receivedBody.PublicKey)
		assert.NotEmpty(t, receivedBody.SecretKey)
		assert.NotEmpty(t, receivedBody.CorrelationID)
	})

	t.Run("tries_https_first_then_http", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		}))
		t.Cleanup(server.Close)

		// Server URL without scheme - should try https then http
		serverHost := strings.TrimPrefix(server.URL, "http://")
		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{serverHost},
			HTTPTimeout:       500 * time.Millisecond,
			KeepAliveInterval: 0,
		})

		// The test server is HTTP only, so HTTPS will fail and HTTP will succeed
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })
	})

	t.Run("context_cancellation", func(t *testing.T) {
		// Server that delays response to allow cancellation to take effect
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(2 * time.Second)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		}))
		t.Cleanup(server.Close)

		// Create a context that will be cancelled quickly
		ctx, cancel := context.WithCancel(t.Context())

		// Cancel context after a short delay
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		_, err := New(ctx, &Options{
			ServerURLs:          []string{server.URL},
			KeepAliveInterval:   0,
			DisableHTTPFallback: true,
		})

		// Should fail due to context cancellation
		require.Error(t, err)
		require.ErrorIs(t, ctx.Err(), context.Canceled)
		assert.Contains(t, err.Error(), "context canceled")
	})

	t.Run("uses_custom_http_client", func(t *testing.T) {
		var customClientCalled bool
		customTransport := &testRoundTripper{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				customClientCalled = true
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"message":"registration successful"}`)),
					Header:     make(http.Header),
				}, nil
			},
		}

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{"http://test.example.com"},
			HTTPClient:        &http.Client{Transport: customTransport},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		assert.True(t, customClientCalled)
	})
}

func TestPolling(t *testing.T) {
	t.Parallel()

	t.Run("callback_receives_interactions", func(t *testing.T) {
		var pollCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/register"):
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"message":"registration successful"}`))
			case strings.HasSuffix(r.URL.Path, "/poll"):
				count := atomic.AddInt32(&pollCount, 1)
				w.WriteHeader(http.StatusOK)
				if count == 1 {
					// Return extra data on first poll (unencrypted for simplicity)
					_, _ = w.Write([]byte(`{"data":[],"extra":["{\"protocol\":\"dns\",\"unique-id\":\"test123\",\"full-id\":\"test123.example.com\",\"remote-address\":\"1.2.3.4\",\"timestamp\":\"2024-01-01T00:00:00Z\"}"],"aes_key":""}`))
				} else {
					_, _ = w.Write([]byte(`{"data":[],"extra":[],"aes_key":""}`))
				}
			case strings.HasSuffix(r.URL.Path, "/deregister"):
				w.WriteHeader(http.StatusOK)
			}
		}))
		t.Cleanup(server.Close)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		var received []*Interaction
		done := make(chan struct{})
		callback := func(i *Interaction) {
			received = append(received, i)
			close(done)
		}

		err = client.StartPolling(50*time.Millisecond, callback)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for interaction")
		}

		require.NoError(t, client.StopPolling())

		require.Len(t, received, 1)
		assert.Equal(t, "dns", received[0].Protocol)
		assert.Equal(t, "test123", received[0].UniqueID)
	})

	t.Run("handles_session_eviction", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping slow test in short mode")
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/register"):
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"message":"registration successful"}`))
			case strings.HasSuffix(r.URL.Path, "/poll"):
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"correlation-id not found"}`))
			case strings.HasSuffix(r.URL.Path, "/deregister"):
				w.WriteHeader(http.StatusOK)
			}
		}))
		t.Cleanup(server.Close)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		// Start polling - should handle eviction gracefully (not crash)
		err = client.StartPolling(50*time.Millisecond, func(*Interaction) {})
		require.NoError(t, err)

		// Wait for at least one poll cycle
		time.Sleep(100 * time.Millisecond)

		// Client should still be running
		assert.True(t, client.IsPolling())
		require.NoError(t, client.StopPolling())
	})
}

func TestDeregistration(t *testing.T) {
	t.Parallel()

	t.Run("sends_deregister_on_close", func(t *testing.T) {
		var deregisterCalled bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/register"):
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"message":"registration successful"}`))
			case strings.HasSuffix(r.URL.Path, "/deregister"):
				deregisterCalled = true
				w.WriteHeader(http.StatusOK)
			}
		}))
		t.Cleanup(server.Close)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)

		err = client.Close()
		require.NoError(t, err)

		assert.True(t, deregisterCalled)
	})

	t.Run("deregister_request_format", func(t *testing.T) {
		var receivedBody deregisterRequest
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/register"):
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"message":"registration successful"}`))
			case strings.HasSuffix(r.URL.Path, "/deregister"):
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &receivedBody)
				w.WriteHeader(http.StatusOK)
			}
		}))
		t.Cleanup(server.Close)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)

		domain := client.Domain()
		correlationID := strings.Split(domain, ".")[0]

		err = client.Close()
		require.NoError(t, err)

		assert.Equal(t, correlationID, receivedBody.CorrelationID)
		assert.NotEmpty(t, receivedBody.SecretKey)
	})
}

func TestKeepAlive(t *testing.T) {
	t.Parallel()

	t.Run("re_registers_periodically", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping slow test in short mode")
		}

		var registerCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/register"):
				atomic.AddInt32(&registerCount, 1)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"message":"registration successful"}`))
			case strings.HasSuffix(r.URL.Path, "/deregister"):
				w.WriteHeader(http.StatusOK)
			}
		}))
		t.Cleanup(server.Close)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 50 * time.Millisecond,
		})
		require.NoError(t, err)

		// Wait for keep-alive to fire
		time.Sleep(150 * time.Millisecond)

		err = client.Close()
		require.NoError(t, err)

		// Should have initial registration + at least 1 keep-alive
		assert.GreaterOrEqual(t, atomic.LoadInt32(&registerCount), int32(2))
	})

	t.Run("disabled_when_interval_zero", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping slow test in short mode")
		}

		var registerCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/register"):
				atomic.AddInt32(&registerCount, 1)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"message":"registration successful"}`))
			case strings.HasSuffix(r.URL.Path, "/deregister"):
				w.WriteHeader(http.StatusOK)
			}
		}))
		t.Cleanup(server.Close)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		err = client.Close()
		require.NoError(t, err)

		// Should only have initial registration
		assert.Equal(t, int32(1), atomic.LoadInt32(&registerCount))
	})
}

func TestConcurrentAccess(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/register"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		case strings.HasSuffix(r.URL.Path, "/poll"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":[],"extra":[],"aes_key":""}`))
		case strings.HasSuffix(r.URL.Path, "/deregister"):
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(server.Close)

	t.Run("concurrent_url_generation", func(t *testing.T) {
		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		const goroutines = 10
		const urlsPerGoroutine = 100

		urlChan := make(chan string, goroutines*urlsPerGoroutine)
		var wg sync.WaitGroup

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < urlsPerGoroutine; j++ {
					urlChan <- client.URL()
				}
			}()
		}

		wg.Wait()
		close(urlChan)

		// Collect all URLs and verify uniqueness
		seen := make(map[string]bool)
		for u := range urlChan {
			assert.False(t, seen[u], "duplicate URL generated concurrently")
			seen[u] = true
		}
		assert.Len(t, seen, goroutines*urlsPerGoroutine)
	})

	t.Run("concurrent_state_checks", func(t *testing.T) {
		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		err = client.StartPolling(100*time.Millisecond, func(*Interaction) {})
		require.NoError(t, err)

		const goroutines = 10
		const checksPerGoroutine = 100

		var wg sync.WaitGroup
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < checksPerGoroutine; j++ {
					_ = client.IsPolling()
					_ = client.IsClosed()
					_ = client.Domain()
				}
			}()
		}

		wg.Wait()
		require.NoError(t, client.StopPolling())
	})

	t.Run("concurrent_polling_operations", func(t *testing.T) {
		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		// Try concurrent start/stop - only one should succeed
		const goroutines = 5
		startErrors := make(chan error, goroutines)
		stopErrors := make(chan error, goroutines)

		// First start polling
		err = client.StartPolling(100*time.Millisecond, func(*Interaction) {})
		require.NoError(t, err)

		// Concurrent attempts to start (should all fail)
		var wg sync.WaitGroup
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				startErrors <- client.StartPolling(100*time.Millisecond, func(*Interaction) {})
			}()
		}
		wg.Wait()
		close(startErrors)

		for err := range startErrors {
			require.ErrorIs(t, err, ErrAlreadyPolling)
		}

		// Stop polling
		require.NoError(t, client.StopPolling())

		// Concurrent attempts to stop (should all fail)
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				stopErrors <- client.StopPolling()
			}()
		}
		wg.Wait()
		close(stopErrors)

		for err := range stopErrors {
			assert.ErrorIs(t, err, ErrNotPolling)
		}
	})
}

func TestDecryptInteraction(t *testing.T) {
	t.Parallel()

	// Create a client with known keys for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	client := &Client{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}

	t.Run("decrypts_valid_data", func(t *testing.T) {
		// Create test interaction data
		interaction := Interaction{
			Protocol:      "http",
			UniqueID:      "test123",
			FullId:        "test123.example.com",
			RemoteAddress: "1.2.3.4",
		}
		plaintext, err := json.Marshal(interaction)
		require.NoError(t, err)

		// Encrypt with AES-256-CFB (matching the implementation)
		aesKey := make([]byte, 32)
		_, err = rand.Read(aesKey)
		require.NoError(t, err)

		iv := make([]byte, aes.BlockSize)
		_, err = rand.Read(iv)
		require.NoError(t, err)

		block, err := aes.NewCipher(aesKey)
		require.NoError(t, err)

		ciphertext := make([]byte, len(plaintext))
		stream := cipher.NewCFBEncrypter(block, iv) //nolint:staticcheck // CFB required for interactsh protocol
		stream.XORKeyStream(ciphertext, plaintext)

		// Prepend IV to ciphertext
		fullCiphertext := append(iv, ciphertext...)

		// Encrypt AES key with RSA-OAEP
		encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKey.PublicKey, aesKey, nil)
		require.NoError(t, err)

		// Base64 encode
		aesKeyB64 := base64.StdEncoding.EncodeToString(encryptedKey)
		ciphertextB64 := base64.StdEncoding.EncodeToString(fullCiphertext)

		// Decrypt
		result, err := client.decryptInteraction(aesKeyB64, ciphertextB64)
		require.NoError(t, err)

		var decoded Interaction
		require.NoError(t, json.Unmarshal(result, &decoded))
		assert.Equal(t, "http", decoded.Protocol)
		assert.Equal(t, "test123", decoded.UniqueID)
	})

	t.Run("fails_invalid_aes_key_base64", func(t *testing.T) {
		_, err := client.decryptInteraction("not-valid-base64!!!", "validbase64==")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode AES key")
	})

	t.Run("fails_invalid_ciphertext_base64", func(t *testing.T) {
		// Valid base64 for AES key but wrong content - will fail RSA decrypt
		_, err := client.decryptInteraction("dGVzdA==", "not-valid-base64!!!")
		require.Error(t, err)
	})

	t.Run("fails_ciphertext_too_short", func(t *testing.T) {
		// Create valid encrypted AES key
		aesKey := make([]byte, 32)
		_, _ = rand.Read(aesKey)
		encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKey.PublicKey, aesKey, nil)
		require.NoError(t, err)
		aesKeyB64 := base64.StdEncoding.EncodeToString(encryptedKey)

		// Ciphertext shorter than IV (16 bytes)
		shortCiphertext := base64.StdEncoding.EncodeToString([]byte("short"))

		_, err = client.decryptInteraction(aesKeyB64, shortCiphertext)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext too short")
	})

	t.Run("fails_wrong_rsa_key", func(t *testing.T) {
		// Encrypt with different key
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		aesKey := make([]byte, 32)
		_, _ = rand.Read(aesKey)
		encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &otherKey.PublicKey, aesKey, nil)
		require.NoError(t, err)

		aesKeyB64 := base64.StdEncoding.EncodeToString(encryptedKey)
		ciphertextB64 := base64.StdEncoding.EncodeToString(make([]byte, 32))

		_, err = client.decryptInteraction(aesKeyB64, ciphertextB64)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt AES key")
	})
}

func TestPollingWithEncryptedData(t *testing.T) {
	t.Parallel()

	t.Run("decrypts_encrypted_interactions", func(t *testing.T) {
		var clientPublicKeyB64 string
		var mu sync.Mutex
		var interactions []*Interaction

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/register"):
				// Capture public key from registration
				var req registerRequest
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &req)
				mu.Lock()
				clientPublicKeyB64 = req.PublicKey
				mu.Unlock()

				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"message":"registration successful"}`))

			case strings.HasSuffix(r.URL.Path, "/poll"):
				mu.Lock()
				pubKeyB64 := clientPublicKeyB64
				mu.Unlock()

				if pubKeyB64 == "" {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"data":[],"extra":[],"aes_key":""}`))
					return
				}

				// Decode client's public key
				pubKey, err := decodePublicKey(pubKeyB64)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				// Create test interaction
				interaction := Interaction{
					Protocol:      "http",
					UniqueID:      "encrypted123",
					FullId:        "encrypted123.example.com",
					RemoteAddress: "5.6.7.8",
				}
				plaintext, _ := json.Marshal(interaction)

				// Encrypt with AES-256-CFB
				aesKey := make([]byte, 32)
				_, _ = rand.Read(aesKey)

				iv := make([]byte, aes.BlockSize)
				_, _ = rand.Read(iv)

				block, _ := aes.NewCipher(aesKey)
				ciphertext := make([]byte, len(plaintext))
				stream := cipher.NewCFBEncrypter(block, iv) //nolint:staticcheck // CFB required for interactsh protocol
				stream.XORKeyStream(ciphertext, plaintext)

				fullCiphertext := append(iv, ciphertext...)

				// Encrypt AES key with client's RSA public key
				encryptedKey, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)

				aesKeyB64 := base64.StdEncoding.EncodeToString(encryptedKey)
				ciphertextB64 := base64.StdEncoding.EncodeToString(fullCiphertext)

				resp := map[string]interface{}{
					"data":    []string{ciphertextB64},
					"extra":   []string{},
					"aes_key": aesKeyB64,
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)

			case strings.HasSuffix(r.URL.Path, "/deregister"):
				w.WriteHeader(http.StatusOK)
			}
		}))
		t.Cleanup(server.Close)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		done := make(chan struct{})
		callback := func(i *Interaction) {
			mu.Lock()
			defer mu.Unlock()
			interactions = append(interactions, i)
			select {
			case <-done:
			default:
				close(done)
			}
		}

		err = client.StartPolling(50*time.Millisecond, callback)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for encrypted interaction")
		}

		require.NoError(t, client.StopPolling())

		mu.Lock()
		defer mu.Unlock()
		require.Len(t, interactions, 1)
		assert.Equal(t, "http", interactions[0].Protocol)
		assert.Equal(t, "encrypted123", interactions[0].UniqueID)
	})

	t.Run("processes_tlddata", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/register"):
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"message":"registration successful"}`))
			case strings.HasSuffix(r.URL.Path, "/poll"):
				w.WriteHeader(http.StatusOK)
				resp := map[string]interface{}{
					"data":    []string{},
					"extra":   []string{},
					"aes_key": "",
					"tlddata": []string{`{"protocol":"dns","unique-id":"tld123","full-id":"tld123.example.com","remote-address":"9.10.11.12"}`},
				}
				_ = json.NewEncoder(w).Encode(resp)
			case strings.HasSuffix(r.URL.Path, "/deregister"):
				w.WriteHeader(http.StatusOK)
			}
		}))
		t.Cleanup(server.Close)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		var received []*Interaction
		var mu sync.Mutex
		done := make(chan struct{})

		callback := func(i *Interaction) {
			mu.Lock()
			defer mu.Unlock()
			received = append(received, i)
			select {
			case <-done:
			default:
				close(done)
			}
		}

		err = client.StartPolling(50*time.Millisecond, callback)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for TLD interaction")
		}

		require.NoError(t, client.StopPolling())

		mu.Lock()
		defer mu.Unlock()
		require.Len(t, received, 1)
		assert.Equal(t, "dns", received[0].Protocol)
		assert.Equal(t, "tld123", received[0].UniqueID)
	})

	t.Run("skips_malformed_encrypted_data", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/register"):
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"message":"registration successful"}`))
			case strings.HasSuffix(r.URL.Path, "/poll"):
				w.WriteHeader(http.StatusOK)
				resp := map[string]interface{}{
					"data":    []string{"invalid-base64!!!"},
					"extra":   []string{`{"protocol":"http","unique-id":"valid123","full-id":"valid123.example.com","remote-address":"1.1.1.1"}`},
					"aes_key": "also-invalid!!!",
				}
				_ = json.NewEncoder(w).Encode(resp)
			case strings.HasSuffix(r.URL.Path, "/deregister"):
				w.WriteHeader(http.StatusOK)
			}
		}))
		t.Cleanup(server.Close)

		client, err := New(t.Context(), &Options{
			ServerURLs:        []string{server.URL},
			KeepAliveInterval: 0,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		var received []*Interaction
		var mu sync.Mutex
		done := make(chan struct{})

		callback := func(i *Interaction) {
			mu.Lock()
			defer mu.Unlock()
			received = append(received, i)
			select {
			case <-done:
			default:
				close(done)
			}
		}

		err = client.StartPolling(50*time.Millisecond, callback)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for valid interaction")
		}

		require.NoError(t, client.StopPolling())

		mu.Lock()
		defer mu.Unlock()
		// Should only receive the valid extra data, not the malformed encrypted data
		require.Len(t, received, 1)
		assert.Equal(t, "valid123", received[0].UniqueID)
	})
}

// testRoundTripper is a test helper that implements http.RoundTripper.
type testRoundTripper struct {
	roundTrip func(*http.Request) (*http.Response, error)
}

func (t *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.roundTrip(req)
}
