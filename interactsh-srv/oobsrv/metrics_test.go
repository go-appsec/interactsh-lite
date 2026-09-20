package oobsrv

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleMetrics(t *testing.T) {
	t.Parallel()

	t.Run("response_structure", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Metrics = true
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp metricsResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

		// Memory fields not tested elsewhere
		assert.NotEmpty(t, resp.Memory.TotalAlloc)
		assert.NotEmpty(t, resp.Memory.HeapSys)
		assert.NotEmpty(t, resp.Memory.HeapInUse)
		assert.NotEmpty(t, resp.Memory.StackInUse)
	})

	t.Run("session_counters", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Metrics = true
		})
		key := sharedRSAKey

		// Register 3 sessions
		ids := []string{
			"aaaabbbbccccddddeeee",
			"ffffgggghhhhiiiijjjj",
			"kkkkllllmmmmnnnnooooo",
		}
		for _, id := range ids {
			_, err := srv.storage.Register(t.Context(), id, &key.PublicKey, "secret", nil)
			require.NoError(t, err)
		}

		resp := getMetrics(t, srv)
		assert.Equal(t, uint64(3), resp.Sessions)
		assert.Equal(t, uint64(3), resp.SessionsTotal)

		// Deregister one
		require.NoError(t, srv.storage.Delete(ids[0], "secret"))

		resp = getMetrics(t, srv)
		assert.Equal(t, uint64(2), resp.Sessions)
		assert.Equal(t, uint64(3), resp.SessionsTotal)
	})

	t.Run("cache_statistics", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Metrics = true
		})
		key := sharedRSAKey
		const id = "abcdefghij0123456789"

		_, err := srv.storage.Register(t.Context(), id, &key.PublicKey, "secret", nil)
		require.NoError(t, err)

		// Hit: valid lookup
		_, err = srv.storage.GetSession(id, "secret")
		require.NoError(t, err)

		// Miss: unknown ID
		_, err = srv.storage.GetSession("nonexistent0123456789", "secret")
		require.Error(t, err)

		resp := getMetrics(t, srv)
		assert.GreaterOrEqual(t, resp.Cache.HitCount, uint64(1))
		assert.GreaterOrEqual(t, resp.Cache.MissCount, uint64(1))
	})

	t.Run("human_readable_format", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Metrics = true
		})

		resp := getMetrics(t, srv)

		// Decimal SI format: digits + optional decimal + unit suffix (no space)
		siPattern := regexp.MustCompile(`^\d+(\.\d+)?(B|kB|MB|GB|TB|PB)$`)
		assert.Regexp(t, siPattern, resp.Memory.Alloc)
		assert.Regexp(t, siPattern, resp.Memory.HeapAlloc)
		assert.Regexp(t, siPattern, resp.Memory.HeapIdle)
		assert.Regexp(t, siPattern, resp.Memory.Sys)
		assert.Regexp(t, siPattern, resp.Network.Received)
		assert.Regexp(t, siPattern, resp.Network.Transmitted)
	})

	t.Run("protocol_counters_reflected", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Metrics = true
		})

		srv.dnsCount.Store(10)
		srv.httpCount.Store(20)
		srv.smtpCount.Store(30)
		srv.ldapCount.Store(40)
		srv.ftpCount.Store(50)

		srv.dnsMatched.Store(5)
		srv.httpMatched.Store(12)
		srv.smtpMatched.Store(8)

		resp := getMetrics(t, srv)
		assert.Equal(t, uint64(10), resp.DNS)
		assert.Equal(t, uint64(20), resp.HTTP)
		assert.Equal(t, uint64(30), resp.SMTP)
		assert.Equal(t, uint64(40), resp.LDAP)
		assert.Equal(t, uint64(50), resp.FTP)

		assert.Equal(t, uint64(5), resp.DNSMatched)
		assert.Equal(t, uint64(12), resp.HTTPMatched)
		assert.Equal(t, uint64(8), resp.SMTPMatched)
	})

	t.Run("metrics_disabled", func(t *testing.T) {
		srv := testServerWithStorage(t)

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
		srv.Handler().ServeHTTP(rec, req)

		// Falls through to the default handler, not the metrics handler
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp metricsResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		assert.Error(t, err, "default handler should not return metrics JSON")
	})

	t.Run("auth_required", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Metrics = true
			c.Auth = true
			c.Token = "test-token"
		})

		// Without token: 401
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
		srv.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)

		// With correct token: 200
		rec = httptest.NewRecorder()
		req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
		req.Header.Set("Authorization", "test-token")
		srv.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp metricsResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	})

	t.Run("eviction_count_reflected", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Metrics = true
		})
		pubKey := &sharedRSAKey.PublicKey

		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		// Force eviction via internal API
		ms := srv.storage.(*memoryStorage)
		ms.mu.Lock()
		ms.evictLRU()
		ms.mu.Unlock()

		resp := getMetrics(t, srv)
		assert.GreaterOrEqual(t, resp.Cache.EvictionCount, uint64(1))
	})
}

// getMetrics is a helper that hits GET /metrics and returns the decoded response.
func getMetrics(t *testing.T, srv *Server) metricsResponse {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
	srv.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp metricsResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	return resp
}
