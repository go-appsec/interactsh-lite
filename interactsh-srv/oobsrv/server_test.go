package oobsrv

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func validTestConfig() Config {
	cfg := DefaultConfig()
	cfg.Domains = []string{"test.com"}
	cfg.Version = "test"
	return cfg
}

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("valid_config", func(t *testing.T) {
		srv, err := New(validTestConfig(), testLogger())
		require.NoError(t, err)
		assert.NotNil(t, srv)
		assert.NotNil(t, srv.Handler())
	})

	t.Run("invalid_config_no_domain", func(t *testing.T) {
		cfg := DefaultConfig()
		_, err := New(cfg, testLogger())
		assert.Error(t, err)
	})

	t.Run("domains_normalized_and_sorted", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Domains = []string{"b.com", "sub.b.com", "A.COM"}
		cfg.Version = "test"
		srv, err := New(cfg, testLogger())
		require.NoError(t, err)

		// Lowercased and sorted longest-first (equal-length order is stable)
		assert.Equal(t, []string{"sub.b.com", "b.com", "a.com"}, srv.cfg.Domains)
	})
}

func TestHandler(t *testing.T) {
	t.Parallel()

	t.Run("default_response_headers", func(t *testing.T) {
		srv, err := New(validTestConfig(), testLogger())
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/foo", nil)
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "test.com", rec.Header().Get("Server"))
		assert.Equal(t, "test", rec.Header().Get("X-Interactsh-Version"))
		assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Empty(t, rec.Header().Get("X-Content-Type-Options"))
	})

	t.Run("custom_server_header", func(t *testing.T) {
		cfg := validTestConfig()
		cfg.ServerHeader = "custom-srv"
		srv, err := New(cfg, testLogger())
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, "custom-srv", rec.Header().Get("Server"))
	})

	t.Run("disable_version", func(t *testing.T) {
		cfg := validTestConfig()
		cfg.DisableVersion = true
		srv, err := New(cfg, testLogger())
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		srv.Handler().ServeHTTP(rec, req)

		assert.Empty(t, rec.Header().Get("X-Interactsh-Version"))
	})
}

func TestShutdown(t *testing.T) {
	t.Parallel()

	t.Run("closes_all_services", func(t *testing.T) {
		srv, err := New(validTestConfig(), testLogger())
		require.NoError(t, err)

		var count atomic.Int32
		for _, name := range []string{"first", "second", "third"} {
			srv.services = append(srv.services, &mockService{
				name:    name,
				onClose: func() { count.Add(1) },
			})
		}

		srv.Shutdown()

		assert.Equal(t, int32(3), count.Load())
	})
}

func TestInitStorage(t *testing.T) {
	t.Parallel()

	t.Run("memory_backend_default", func(t *testing.T) {
		srv, err := New(validTestConfig(), testLogger())
		require.NoError(t, err)

		assert.NotNil(t, srv.storage)
		assert.IsType(t, &memoryStorage{}, srv.storage)
	})

	t.Run("wildcard_creates_tld_buckets", func(t *testing.T) {
		cfg := validTestConfig()
		cfg.Domains = []string{"a.com", "b.com"}
		cfg.Wildcard = true
		cfg.Auth = true
		cfg.Token = "tok"
		srv, err := New(cfg, testLogger())
		require.NoError(t, err)

		require.Len(t, srv.tldBuckets, 2)
		assert.Contains(t, srv.tldBuckets, "a.com")
		assert.Contains(t, srv.tldBuckets, "b.com")
	})

	t.Run("extra_bucket_with_auth_and_ftp", func(t *testing.T) {
		cfg := validTestConfig()
		cfg.Auth = true
		cfg.Token = "tok"
		cfg.FTP = true
		srv, err := New(cfg, testLogger())
		require.NoError(t, err)

		assert.NotNil(t, srv.extraBucket)
	})

	t.Run("extra_bucket_with_auth_and_ldap", func(t *testing.T) {
		cfg := validTestConfig()
		cfg.Auth = true
		cfg.Token = "tok"
		cfg.LDAP = true
		srv, err := New(cfg, testLogger())
		require.NoError(t, err)

		assert.NotNil(t, srv.extraBucket)
	})

	t.Run("no_extra_bucket_without_ftp_or_ldap", func(t *testing.T) {
		cfg := validTestConfig()
		cfg.Auth = true
		cfg.Token = "tok"
		srv, err := New(cfg, testLogger())
		require.NoError(t, err)

		assert.Nil(t, srv.extraBucket)
	})

	t.Run("no_tld_buckets_without_wildcard", func(t *testing.T) {
		srv, err := New(validTestConfig(), testLogger())
		require.NoError(t, err)

		assert.Nil(t, srv.tldBuckets)
	})
}

func TestLoadHTTPFiles(t *testing.T) {
	t.Parallel()

	t.Run("loads_default_response", func(t *testing.T) {
		dir := t.TempDir()
		filePath := filepath.Join(dir, "response.html")
		require.NoError(t, os.WriteFile(filePath, []byte("custom"), 0644))

		srv, err := New(validTestConfig(), testLogger())
		require.NoError(t, err)
		srv.cfg.DefaultHTTPResponse = filePath

		require.NoError(t, srv.loadHTTPFiles())
		assert.Equal(t, []byte("custom"), srv.defaultHTTPResponse)
	})

	t.Run("loads_http_index", func(t *testing.T) {
		dir := t.TempDir()
		filePath := filepath.Join(dir, "index.html")
		require.NoError(t, os.WriteFile(filePath, []byte("index"), 0644))

		srv, err := New(validTestConfig(), testLogger())
		require.NoError(t, err)
		srv.cfg.HTTPIndex = filePath

		require.NoError(t, srv.loadHTTPFiles())
		assert.Equal(t, []byte("index"), srv.httpIndex)
	})

	t.Run("error_missing_file", func(t *testing.T) {
		srv, err := New(validTestConfig(), testLogger())
		require.NoError(t, err)
		srv.cfg.DefaultHTTPResponse = "/nonexistent/file.html"

		assert.Error(t, srv.loadHTTPFiles())
	})

	t.Run("noop_when_unset", func(t *testing.T) {
		srv, err := New(validTestConfig(), testLogger())
		require.NoError(t, err)

		require.NoError(t, srv.loadHTTPFiles())
		assert.Nil(t, srv.defaultHTTPResponse)
		assert.Nil(t, srv.httpIndex)
	})
}

func TestCaptureInteraction(t *testing.T) {
	t.Parallel()

	t.Run("scan_everywhere_mode", func(t *testing.T) {
		cfg := validTestConfig()
		cfg.ScanEverywhere = true
		srv, err := New(cfg, testLogger())
		require.NoError(t, err)

		pubKey := &sharedRSAKey.PublicKey
		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		// CID embedded in HTTP-style text (not DNS labels)
		scanInput := "GET / HTTP/1.1\r\nHost: " + testCorrelationID + "nop.test.com\r\n"
		interaction := InteractionType{Protocol: "http"}
		assert.True(t, srv.captureInteraction("test.com", "", scanInput, interaction, interaction))

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)

		decrypted := decryptTestInteraction(t, interactions[0], aesKey)
		var got InteractionType
		require.NoError(t, json.Unmarshal([]byte(decrypted), &got))
		assert.Equal(t, testCorrelationID, got.UniqueID)
	})

	t.Run("wildcard_disabled_noop", func(t *testing.T) {
		srv, err := New(validTestConfig(), testLogger())
		require.NoError(t, err)

		interaction := InteractionType{Protocol: "http"}
		// captureInteraction with wildcard disabled should not store wildcard data
		srv.captureInteraction("test.com", "unregistered.test.com", "", interaction, interaction)

		// No tldBuckets exist
		assert.Nil(t, srv.tldBuckets)
	})

	t.Run("wildcard_unknown_domain", func(t *testing.T) {
		cfg := validTestConfig()
		cfg.Wildcard = true
		cfg.Auth = true
		cfg.Token = "tok"
		srv, err := New(cfg, testLogger())
		require.NoError(t, err)

		interaction := InteractionType{Protocol: "http"}
		// captureWildcard with a domain not in tldBuckets should not store
		srv.captureWildcard("unknown.com", interaction)

		bucket, ok := srv.tldBuckets["unknown.com"]
		assert.False(t, ok)
		assert.Nil(t, bucket)
	})

	t.Run("no_match_no_storage", func(t *testing.T) {
		srv, err := New(validTestConfig(), testLogger())
		require.NoError(t, err)

		interaction := InteractionType{Protocol: "dns"}
		assert.False(t, srv.captureInteraction("test.com", "unregistered.test.com", "", interaction, interaction))

		// Nothing stored since no CID is registered
		assert.Equal(t, uint64(0), srv.storage.SessionCount())
	})

	t.Run("multiple_cid_matches", func(t *testing.T) {
		cfg := validTestConfig()
		srv, err := New(cfg, testLogger())
		require.NoError(t, err)

		pubKey := &sharedRSAKey.PublicKey

		_, err = srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)
		_, err = srv.storage.Register(t.Context(), testCorrelationID2, pubKey, "secret", nil)
		require.NoError(t, err)

		matchInput := testCorrelationID + "nop." + testCorrelationID2 + "abc.test.com"
		interaction := InteractionType{Protocol: "dns"}
		assert.True(t, srv.captureInteraction("test.com", matchInput, "", interaction, interaction))

		i1, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		assert.Len(t, i1, 1)

		i2, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID2, "secret")
		require.NoError(t, err)
		assert.Len(t, i2, 1)
	})
}

type mockService struct {
	name    string
	onClose func()
}

func (m *mockService) Name() string                    { return m.name }
func (m *mockService) Start(ctx context.Context) error { return nil }
func (m *mockService) Close() error {
	if m.onClose != nil {
		m.onClose()
	}
	return nil
}
