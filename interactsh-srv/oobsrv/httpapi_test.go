package oobsrv

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-appsec/interactsh-lite/oobclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStripHostPort(t *testing.T) {
	t.Parallel()

	t.Run("without_port", func(t *testing.T) {
		assert.Equal(t, "example.com", stripHostPort("example.com"))
	})

	t.Run("with_port", func(t *testing.T) {
		assert.Equal(t, "example.com", stripHostPort("example.com:8080"))
	})

	t.Run("ipv6_with_port", func(t *testing.T) {
		assert.Equal(t, "::1", stripHostPort("[::1]:8080"))
	})

	t.Run("bare_ipv4", func(t *testing.T) {
		assert.Equal(t, "1.2.3.4", stripHostPort("1.2.3.4"))
	})
}

func TestMatchDomain(t *testing.T) {
	t.Parallel()

	srv, err := New(validTestConfig(), testLogger())
	require.NoError(t, err)

	t.Run("exact_match", func(t *testing.T) {
		assert.Equal(t, testDomain, srv.matchDomain(testDomain))
	})

	t.Run("subdomain_match", func(t *testing.T) {
		assert.Equal(t, testDomain, srv.matchDomain("sub.test.com"))
	})

	t.Run("no_match_fallback", func(t *testing.T) {
		assert.Equal(t, testDomain, srv.matchDomain("other.org"))
	})

	t.Run("longest_match_first", func(t *testing.T) {
		cfg := validTestConfig()
		cfg.Domains = []string{testDomain, "a.test.com"}
		s, err := New(cfg, testLogger())
		require.NoError(t, err)

		assert.Equal(t, "a.test.com", s.matchDomain("sub.a.test.com"))
	})

	t.Run("case_insensitive", func(t *testing.T) {
		assert.Equal(t, testDomain, srv.matchDomain("SUB.TEST.COM"))
	})
}

const (
	testNonce    = "nop"
	testDomain   = "test.com"
	testToken    = "testtoken"
	testListenIP = "127.0.0.1"
)

// registerTestSession registers a session for testCorrelationID so that
// scanLabels can match it in the request host.
func registerTestSession(t *testing.T, srv *Server) string {
	t.Helper()
	pubKey := &sharedRSAKey.PublicKey
	_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
	require.NoError(t, err)
	return testCorrelationID
}

func TestOnHTTPInteraction(t *testing.T) {
	t.Parallel()

	t.Run("increments_http_count", func(t *testing.T) {
		srv := testServerWithStorage(t)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = testDomain

		srv.onHTTPInteraction(req, "GET / HTTP/1.1\r\n", "HTTP/1.1 200 OK\r\n", "1.2.3.4", testDomain, testDomain)

		assert.Equal(t, uint64(1), srv.httpCount.Load())
	})

	t.Run("unconfigured_domain", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = testCorrelationID + testNonce + ".other.org"

		srv.onHTTPInteraction(req, "req", "resp", "1.2.3.4", "", "")

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		assert.Empty(t, interactions)
	})

	t.Run("stores_correlation_match", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		host := testCorrelationID + testNonce + ".test.com"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host

		rawReq := "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
		const rawResp = "HTTP/1.1 200 OK\r\n\r\n"

		srv.onHTTPInteraction(req, rawReq, rawResp, "10.0.0.1", host, testDomain)

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)

		decrypted := decryptTestInteraction(t, interactions[0], aesKey)
		var interaction InteractionType
		require.NoError(t, json.Unmarshal([]byte(decrypted), &interaction))

		assert.Equal(t, "http", interaction.Protocol)
		assert.Equal(t, testCorrelationID, interaction.UniqueID)
		assert.Equal(t, testCorrelationID+testNonce, interaction.FullId)
		assert.Equal(t, rawReq, interaction.RawRequest)
		assert.Equal(t, rawResp, interaction.RawResponse)
		assert.Equal(t, "10.0.0.1", interaction.RemoteAddress)
		assert.False(t, interaction.Timestamp.IsZero())
	})

	t.Run("protocol_https", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		host := testCorrelationID + testNonce + ".test.com"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		req.TLS = &tls.ConnectionState{}

		srv.onHTTPInteraction(req, "req", "resp", "1.2.3.4", host, testDomain)

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)

		decrypted := decryptTestInteraction(t, interactions[0], aesKey)
		var interaction InteractionType
		require.NoError(t, json.Unmarshal([]byte(decrypted), &interaction))

		assert.Equal(t, "https", interaction.Protocol)
	})

	t.Run("wildcard_capture", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Wildcard = true
			c.Auth = true
			c.Token = "tok"
		})

		const host = "anything.test.com"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host

		srv.onHTTPInteraction(req, "req", "resp", "10.0.0.1", host, testDomain)

		data := srv.tldBuckets[testDomain].ReadFrom("consumer1")
		require.Len(t, data, 1)

		var interaction InteractionType
		require.NoError(t, json.Unmarshal(data[0], &interaction))
		assert.Equal(t, "http", interaction.Protocol)
		assert.Equal(t, "anything.test.com", interaction.UniqueID)
		assert.Equal(t, "anything.test.com", interaction.FullId)
		assert.Equal(t, "req", interaction.RawRequest)
		assert.Equal(t, "resp", interaction.RawResponse)
		assert.Equal(t, "10.0.0.1", interaction.RemoteAddress)
		assert.False(t, interaction.Timestamp.IsZero())
	})

	t.Run("scan_everywhere", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.ScanEverywhere = true
		})
		pubKey := &sharedRSAKey.PublicKey
		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		// CID appears in request body, not the host
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Host = testDomain

		rawReq := "POST / HTTP/1.1\r\nHost: test.com\r\n\r\nbody=" + testCorrelationID + testNonce

		srv.onHTTPInteraction(req, rawReq, "resp", "1.2.3.4", testDomain, testDomain)

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)

		decrypted := decryptTestInteraction(t, interactions[0], aesKey)
		var interaction InteractionType
		require.NoError(t, json.Unmarshal([]byte(decrypted), &interaction))
		assert.Equal(t, testCorrelationID, interaction.UniqueID)
	})

	t.Run("scan_everywhere_no_domain", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.ScanEverywhere = true
		})
		pubKey := &sharedRSAKey.PublicKey
		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		// Host does not match any configured domain, but CID is in raw request
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "unknown.example.org"

		rawReq := "GET / HTTP/1.1\r\nHost: unknown.example.org\r\n\r\n" + testCorrelationID + testNonce

		srv.onHTTPInteraction(req, rawReq, "resp", "1.2.3.4", "unknown.example.org", "")

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)

		decrypted := decryptTestInteraction(t, interactions[0], aesKey)
		var interaction InteractionType
		require.NoError(t, json.Unmarshal([]byte(decrypted), &interaction))
		assert.Equal(t, testCorrelationID, interaction.UniqueID)
	})

	t.Run("host_with_port", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = testCorrelationID + testNonce + ".test.com:8080"

		hostname := testCorrelationID + testNonce + ".test.com"
		srv.onHTTPInteraction(req, "req", "resp", "1.2.3.4", hostname, testDomain)

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		assert.Len(t, interactions, 1)
	})

	t.Run("multiple_cids_in_host", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey

		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret1", nil)
		require.NoError(t, err)
		_, err = srv.storage.Register(t.Context(), testCorrelationID2, pubKey, "secret2", nil)
		require.NoError(t, err)

		// Two CIDs as separate labels in hostname
		host := testCorrelationID + testNonce + "." + testCorrelationID2 + testNonce + "." + testDomain
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		srv.Handler().ServeHTTP(rec, req)

		// Interaction recording is async; wait for each independently
		require.Eventually(t, func() bool {
			i, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret1")
			require.NoError(t, err)
			return len(i) == 1
		}, time.Second, 5*time.Millisecond)
		require.Eventually(t, func() bool {
			i, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID2, "secret2")
			require.NoError(t, err)
			return len(i) == 1
		}, time.Second, 5*time.Millisecond)
	})
}

func TestServeDefault(t *testing.T) {
	t.Parallel()

	t.Run("default_response_domain_replacement", func(t *testing.T) {
		srv := testServerWithStorage(t)
		srv.defaultHTTPResponse = []byte("hello {DOMAIN}")

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "sub.test.com"

		srv.serveDefault(rec, req)

		assert.Equal(t, "hello test.com", rec.Body.String())
	})

	t.Run("static_file_served", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "file.txt"), []byte("static content"), 0644))

		srv := testServerWithStorage(t, func(c *Config) {
			c.HTTPDirectory = dir
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/s/file.txt", nil)
		req.Host = testDomain

		srv.serveDefault(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "static content", rec.Body.String())
	})

	t.Run("static_dir_listing_404", func(t *testing.T) {
		dir := t.TempDir()
		srv := testServerWithStorage(t, func(c *Config) {
			c.HTTPDirectory = dir
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/s/", nil)
		req.Host = testDomain

		srv.serveDefault(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("static_traversal_blocked", func(t *testing.T) {
		dir := t.TempDir()
		srv := testServerWithStorage(t, func(c *Config) {
			c.HTTPDirectory = dir
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/s/../../../etc/passwd", nil)
		req.Host = testDomain

		srv.serveDefault(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("static_subdir_listing_blocked", func(t *testing.T) {
		dir := t.TempDir()
		subdir := filepath.Join(dir, "sub")
		require.NoError(t, os.Mkdir(subdir, 0755))

		srv := testServerWithStorage(t, func(c *Config) {
			c.HTTPDirectory = dir
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/s/sub", nil)
		req.Host = testDomain

		srv.serveDefault(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("static_with_dynamic_header", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "file.txt"), []byte("content"), 0644))

		srv := testServerWithStorage(t, func(c *Config) {
			c.HTTPDirectory = dir
			c.DynamicResp = true
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/s/file.txt?header=X-Custom:test-val", nil)
		req.Host = testDomain

		srv.serveDefault(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "test-val", rec.Header().Get("X-Custom"))
		assert.Equal(t, "content", rec.Body.String())
	})

	t.Run("static_body_param_ignored", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "file.txt"), []byte("file content"), 0644))

		srv := testServerWithStorage(t, func(c *Config) {
			c.HTTPDirectory = dir
			c.DynamicResp = true
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/s/file.txt?body=override", nil)
		req.Host = testDomain

		srv.serveDefault(rec, req)

		assert.Equal(t, "file content", rec.Body.String())
	})

	t.Run("root_returns_banner", func(t *testing.T) {
		srv := testServerWithStorage(t)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = testDomain

		srv.serveDefault(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "Interactsh-lite Server")
		assert.Contains(t, rec.Body.String(), "*.test.com")
		assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	})

	t.Run("index_domain_replacement", func(t *testing.T) {
		srv := testServerWithStorage(t)
		srv.httpIndex = []byte("welcome to {DOMAIN}")

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "sub.test.com"

		srv.serveDefault(rec, req)

		assert.Equal(t, "welcome to test.com", rec.Body.String())
	})

	t.Run("root_with_reflection_skips_banner", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"

		srv.serveDefault(rec, req)

		body := rec.Body.String()
		assert.NotContains(t, body, "Interactsh-lite Server")
		assert.Contains(t, body, "<html>")
	})

	t.Run("xml_path", func(t *testing.T) {
		srv := testServerWithStorage(t)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/data.xml", nil)
		req.Host = testDomain

		srv.serveDefault(rec, req)

		assert.Equal(t, "application/xml", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Body.String(), "<data>")
	})

	t.Run("dynamic_body", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
			c.Auth = true
			c.Token = testToken
		})
		cid := registerTestSession(t, srv)
		host := cid + testNonce + "." + testDomain

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test?body=hello+world", nil)
		req.Host = host

		srv.serveDefault(rec, req)

		assert.Equal(t, "hello world", rec.Body.String())
	})

	t.Run("dynamic_b64_body", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
			c.Auth = true
			c.Token = testToken
		})
		cid := registerTestSession(t, srv)
		host := cid + testNonce + "." + testDomain

		encoded := base64.StdEncoding.EncodeToString([]byte("decoded content"))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test?b64_body="+encoded, nil)
		req.Host = host

		srv.serveDefault(rec, req)

		assert.Equal(t, "decoded content", rec.Body.String())
	})

	t.Run("dynamic_b64_path", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
			c.Auth = true
			c.Token = testToken
		})
		cid := registerTestSession(t, srv)
		host := cid + testNonce + "." + testDomain

		encoded := base64.StdEncoding.EncodeToString([]byte("path body"))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/b64_body:"+encoded+"/", nil)
		req.Host = host

		srv.serveDefault(rec, req)

		assert.Equal(t, "path body", rec.Body.String())
	})

	t.Run("dynamic_header", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
			c.Auth = true
			c.Token = testToken
		})
		cid := registerTestSession(t, srv)
		host := cid + testNonce + "." + testDomain

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test?header=X-Foo:bar&body=ok", nil)
		req.Host = host

		srv.serveDefault(rec, req)

		assert.Equal(t, "bar", rec.Header().Get("X-Foo"))
	})

	t.Run("dynamic_status", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
			c.Auth = true
			c.Token = testToken
		})
		cid := registerTestSession(t, srv)
		host := cid + testNonce + "." + testDomain

		// Valid status code
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test?status=201&body=created", nil)
		req.Host = host
		srv.serveDefault(rec, req)
		assert.Equal(t, 201, rec.Code)

		// Invalid status code falls back to 200
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/test?status=abc&body=ok", nil)
		req.Host = host
		srv.serveDefault(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		// Positive out-of-range codes clamp to [100,999]; non-positive fall back to 200
		for status, want := range map[string]int{"-5": http.StatusOK, "0": http.StatusOK, "1": 100, "1000": 999} {
			rec = httptest.NewRecorder()
			req = httptest.NewRequest(http.MethodGet, "/test?status="+status+"&body=ok", nil)
			req.Host = host
			srv.serveDefault(rec, req)
			assert.Equal(t, want, rec.Code, "status=%s", status)
		}
	})

	t.Run("dynamic_invalid_b64", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
			c.Auth = true
			c.Token = testToken
		})
		cid := registerTestSession(t, srv)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test?b64_body=!!invalid!!", nil)
		req.Host = cid + testNonce + "." + testDomain

		srv.serveDefault(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, rec.Body.String())
	})

	t.Run("dynamic_disabled_fallthrough", func(t *testing.T) {
		srv := testServerWithStorage(t)
		// DynamicResp is false by default

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test?body=should-not-appear", nil)
		req.Host = testDomain

		srv.serveDefault(rec, req)

		assert.Contains(t, rec.Body.String(), "Interactsh-lite Server")
		assert.NotContains(t, rec.Body.String(), "should-not-appear")
	})

	t.Run("default_html_with_reflection", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/somepath", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"

		srv.serveDefault(rec, req)

		body := rec.Body.String()
		assert.Contains(t, body, "<html><head></head><body>")
		assert.Contains(t, body, "</body></html>")
		// Reflection is the reversed label
		reversed := reverseString(testCorrelationID + testNonce)
		assert.Contains(t, body, reversed)
	})

	t.Run("default_html_empty_reflection", func(t *testing.T) {
		srv := testServerWithStorage(t)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/somepath", nil)
		req.Host = testDomain

		srv.serveDefault(rec, req)

		assert.Contains(t, rec.Body.String(), "Interactsh-lite Server")
		assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	})

	t.Run("robots_txt_with_reflection", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"

		srv.serveDefault(rec, req)

		reversed := reverseString(testCorrelationID + testNonce)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/plain", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Body.String(), "User-agent: *")
		assert.Contains(t, rec.Body.String(), "Disallow: /")
		assert.Contains(t, rec.Body.String(), reversed)
	})

	t.Run("multiple_header_params", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
			c.Auth = true
			c.Token = testToken
		})
		cid := registerTestSession(t, srv)
		host := cid + testNonce + "." + testDomain

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test?header=X-A:1&header=X-B:2&body=ok", nil)
		req.Host = host

		srv.serveDefault(rec, req)

		assert.Equal(t, "1", rec.Header().Get("X-A"))
		assert.Equal(t, "2", rec.Header().Get("X-B"))
	})

	t.Run("malformed_header_ignored", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
			c.Auth = true
			c.Token = testToken
		})
		cid := registerTestSession(t, srv)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test?header=nocolon&header=X-Good:ok&body=x", nil)
		req.Host = cid + testNonce + "." + testDomain

		srv.serveDefault(rec, req)

		assert.Equal(t, "ok", rec.Header().Get("X-Good"))
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("path_body_priority_over_query", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
			c.Auth = true
			c.Token = testToken
		})
		cid := registerTestSession(t, srv)
		host := cid + testNonce + "." + testDomain

		encoded := base64.StdEncoding.EncodeToString([]byte("path wins"))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/b64_body:"+encoded+"/?body=query+loses", nil)
		req.Host = host

		srv.serveDefault(rec, req)

		assert.Equal(t, "path wins", rec.Body.String())
	})

	t.Run("invalid_b64_path_falls_through", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
			c.Auth = true
			c.Token = testToken
		})
		cid := registerTestSession(t, srv)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/b64_body:!!!invalid/?body=fallback", nil)
		req.Host = cid + testNonce + "." + testDomain

		srv.serveDefault(rec, req)

		assert.Equal(t, "fallback", rec.Body.String())
	})

	t.Run("json_with_reflection", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/data.json", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"

		srv.serveDefault(rec, req)

		reversed := reverseString(testCorrelationID + testNonce)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Body.String(), `{"data":"`)
		assert.Contains(t, rec.Body.String(), reversed)
	})

	t.Run("json_path_empty_reflection", func(t *testing.T) {
		srv := testServerWithStorage(t)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test.json", nil)
		req.Host = "unknown." + testDomain
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Body.String(), `"data":""`)
	})

	t.Run("content_type_ignores_dynamic_params", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
			c.Auth = true
			c.Token = testToken
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/robots.txt?status=404&body=override", nil)
		req.Host = testDomain

		srv.serveDefault(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "User-agent: *")
		assert.NotContains(t, rec.Body.String(), "override")
	})

	t.Run("dynamic_delay_zero", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
			c.Auth = true
			c.Token = testToken
		})
		cid := registerTestSession(t, srv)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test?delay=0&body=delayed", nil)
		req.Host = cid + testNonce + "." + testDomain

		srv.serveDefault(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "delayed", rec.Body.String())
	})

	t.Run("static_nonexistent_file_404", func(t *testing.T) {
		dir := t.TempDir()
		srv := testServerWithStorage(t, func(c *Config) {
			c.HTTPDirectory = dir
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/s/missing.txt", nil)
		req.Host = testDomain

		srv.serveDefault(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("static_hidden_file_served", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".hidden"), []byte("secret-content"), 0644))

		srv := testServerWithStorage(t, func(c *Config) {
			c.HTTPDirectory = dir
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/s/.hidden", nil)
		req.Host = "sub." + testDomain
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "secret-content", rec.Body.String())
	})

	t.Run("session_stored_redirect", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
		})
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", &oobclient.ResponseConfig{
			StatusCode: 302,
			Headers:    []string{"Location: https://target.com"},
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"
		srv.serveDefault(rec, req)

		assert.Equal(t, 302, rec.Code)
		assert.Equal(t, "https://target.com", rec.Header().Get("Location"))
		// Body should contain the reversed label (reflection)
		assert.Contains(t, rec.Body.String(), reverseString(testCorrelationID+testNonce))
	})

	t.Run("session_stored_with_body", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Auth = true
			c.Token = testToken
			c.DynamicResp = true
		})
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", &oobclient.ResponseConfig{
			StatusCode: 200,
			Headers:    []string{"Content-Type: text/plain"},
			Body:       "custom body",
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/somepath", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"
		srv.serveDefault(rec, req)

		assert.Equal(t, 200, rec.Code)
		assert.Equal(t, "custom body", rec.Body.String())
	})

	t.Run("param_takes_precedence", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
			c.Auth = true
			c.Token = testToken
		})
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", &oobclient.ResponseConfig{
			StatusCode: 200,
			Body:       "session body",
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/?status=201&header=X-Source:param&body=param+body", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"
		srv.serveDefault(rec, req)

		assert.Equal(t, 201, rec.Code)
		assert.Equal(t, "param", rec.Header().Get("X-Source"))
		assert.Equal(t, "param body", rec.Body.String())
	})

	t.Run("param_unauth_redirect_allowed", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
		})
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/?status=302&header=Location:https://target.com", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"
		srv.serveDefault(rec, req)

		assert.Equal(t, 302, rec.Code)
		assert.Equal(t, "https://target.com", rec.Header().Get("Location"))
	})

	t.Run("param_unauth_non_redirect_rejected", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
		})
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test?status=200&header=Content-Type:text/plain&body=hello", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"
		srv.serveDefault(rec, req)

		// Falls through to HTML fallback, dynamic params not served
		assert.Contains(t, rec.Body.String(), "<html>")
		assert.NotContains(t, rec.Body.String(), "hello")
	})

	t.Run("scheme_no_scheme_http", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
		})
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", &oobclient.ResponseConfig{
			StatusCode: 302,
			Headers:    []string{"Location: target.com/path"},
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"
		srv.serveDefault(rec, req)

		assert.Equal(t, 302, rec.Code)
		assert.Equal(t, "http://target.com/path", rec.Header().Get("Location"))
	})

	t.Run("scheme_explicit_https_preserved", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
		})
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", &oobclient.ResponseConfig{
			StatusCode: 307,
			Headers:    []string{"Location: https://explicit.com"},
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"
		srv.serveDefault(rec, req)

		assert.Equal(t, 307, rec.Code)
		assert.Equal(t, "https://explicit.com", rec.Header().Get("Location"))
	})

	t.Run("scheme_tls_request", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
		})
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", &oobclient.ResponseConfig{
			StatusCode: 302,
			Headers:    []string{"Location: target.com"},
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"
		req.TLS = &tls.ConnectionState{}
		srv.serveDefault(rec, req)

		assert.Equal(t, 302, rec.Code)
		assert.Equal(t, "https://target.com", rec.Header().Get("Location"))
	})

	t.Run("scheme_protocol_relative", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
		})
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", &oobclient.ResponseConfig{
			StatusCode: 302,
			Headers:    []string{"Location: //target.com/path"},
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"
		srv.serveDefault(rec, req)

		assert.Equal(t, 302, rec.Code)
		assert.Equal(t, "//target.com/path", rec.Header().Get("Location"))
	})

	t.Run("no_stored_response_fallthrough", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/somepath", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"
		srv.serveDefault(rec, req)

		assert.Contains(t, rec.Body.String(), "<html>")
	})

	t.Run("param_unauth_redirect_body_rejected", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
		})
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/?status=302&header=Location:https://target.com&body=evil", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"
		srv.serveDefault(rec, req)

		assert.Contains(t, rec.Body.String(), "<html>")
		assert.NotContains(t, rec.Body.String(), "evil")
	})

	t.Run("param_unauth_redirect_b64body_rejected", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
		})
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		encoded := base64.StdEncoding.EncodeToString([]byte("evil"))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/?status=302&header=Location:https://target.com&b64_body="+encoded, nil)
		req.Host = testCorrelationID + testNonce + ".test.com"
		srv.serveDefault(rec, req)

		assert.Contains(t, rec.Body.String(), "<html>")
		assert.NotContains(t, rec.Body.String(), "evil")
	})

	t.Run("param_unauth_delay_only", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
		})
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/?delay=0", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"
		srv.serveDefault(rec, req)

		reversed := reverseString(testCorrelationID + testNonce)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, reversed, rec.Body.String())
	})

	t.Run("duplicate_headers_preserved", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
			c.Auth = true
			c.Token = testToken
		})
		cid := registerTestSession(t, srv)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test?header=Set-Cookie:a=1&header=Set-Cookie:b=2&body=ok", nil)
		req.Host = cid + testNonce + "." + testDomain
		srv.serveDefault(rec, req)

		cookies := rec.Header().Values("Set-Cookie")
		assert.Len(t, cookies, 2)
		assert.Contains(t, cookies, "a=1")
		assert.Contains(t, cookies, "b=2")
	})

	t.Run("stored_duplicate_headers", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Auth = true
			c.Token = testToken
			c.DynamicResp = true
		})
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", &oobclient.ResponseConfig{
			StatusCode: 200,
			Headers:    []string{"Set-Cookie: a=1", "Set-Cookie: b=2"},
			Body:       "ok",
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"
		srv.serveDefault(rec, req)

		cookies := rec.Header().Values("Set-Cookie")
		assert.Len(t, cookies, 2)
		assert.Contains(t, cookies, "a=1")
		assert.Contains(t, cookies, "b=2")
	})

	t.Run("param_redirect_scheme", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
			c.Auth = true
			c.Token = testToken
		})
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		cases := []struct {
			name     string
			location string
			status   string
			tls      bool
			expected string
			expCode  int
		}{
			{"bare_host_http", "target.com/path", "302", false, "http://target.com/path", 302},
			{"bare_host_https", "target.com", "302", true, "https://target.com", 302},
			{"explicit_scheme", "https://explicit.com", "307", false, "https://explicit.com", 307},
			{"protocol_relative", "//target.com/path", "302", false, "//target.com/path", 302},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/?status="+tc.status+"&header=Location:"+tc.location, nil)
				req.Host = testCorrelationID + testNonce + ".test.com"
				if tc.tls {
					req.TLS = &tls.ConnectionState{}
				}
				srv.serveDefault(rec, req)

				assert.Equal(t, tc.expCode, rec.Code)
				assert.Equal(t, tc.expected, rec.Header().Get("Location"))
			})
		}
	})

	t.Run("param_non_redirect_no_scheme", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
			c.Auth = true
			c.Token = testToken
		})
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/?status=200&header=Location:target.com&body=ok", nil)
		req.Host = testCorrelationID + testNonce + ".test.com"
		srv.serveDefault(rec, req)

		assert.Equal(t, 200, rec.Code)
		assert.Equal(t, "target.com", rec.Header().Get("Location"))
	})
}
