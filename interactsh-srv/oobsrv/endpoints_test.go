package oobsrv

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/interactsh-lite/oobclient"
)

// testServerWithStorage creates a Server without starting network services.
func testServerWithStorage(t *testing.T, opts ...func(*Config)) *Server {
	t.Helper()

	cfg := validTestConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	logger := slog.New(slog.DiscardHandler)
	srv, err := New(cfg, logger)
	require.NoError(t, err)
	return srv
}

var sharedRSAKey *rsa.PrivateKey

func init() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("test RSA key generation: " + err.Error())
	}
	sharedRSAKey = key
}

// registerJSON builds the POST /register request body.
func registerJSON(t *testing.T, pubKey *rsa.PublicKey, correlationID, secretKey string) []byte {
	t.Helper()

	b64Key := encodeTestPublicKey(t, pubKey)
	body, err := json.Marshal(registerRequest{
		PublicKey:     b64Key,
		SecretKey:     secretKey,
		CorrelationID: correlationID,
	})
	require.NoError(t, err)
	return body
}

// deregisterJSON builds the POST /deregister request body.
func deregisterJSON(correlationID, secretKey string) []byte {
	body, _ := json.Marshal(deregisterRequest{
		CorrelationID: correlationID,
		SecretKey:     secretKey,
	})
	return body
}

// decryptPollData base64-decodes and decrypts a poll response interaction string.
func decryptPollData(t *testing.T, encrypted string, aesKey []byte) []byte {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(encrypted)
	require.NoError(t, err)
	return []byte(decryptTestInteraction(t, raw, aesKey))
}

// decryptAESKey decrypts the RSA-OAEP encrypted AES key from a poll response.
func decryptAESKey(t *testing.T, encAESKey string, privKey *rsa.PrivateKey) []byte {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(encAESKey)
	require.NoError(t, err)

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, raw, nil)
	require.NoError(t, err)
	return aesKey
}

func TestHandleRegister(t *testing.T) {
	t.Parallel()

	t.Run("successful_registration", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		body := registerJSON(t, &key.PublicKey, testCorrelationID, "secret-123")
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
		assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "test.com", rec.Header().Get("Server"))

		var resp map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, "registration successful", resp["message"])
	})

	t.Run("short_correlation_id", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		body := registerJSON(t, &key.PublicKey, "tooshort", "secret-123")
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var resp map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Contains(t, resp["error"], "correlation-id must be at least")
	})

	t.Run("long_id_truncated", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		const longID = "abcdefghijklmnopqrstuvwxyz123456"
		body := registerJSON(t, &key.PublicKey, longID, "secret-123")
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, srv.storage.HasCorrelationID(longID[:20]))
	})

	t.Run("keep_alive_duplicate", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		body := registerJSON(t, &key.PublicKey, testCorrelationID, "secret-123")

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		rec = httptest.NewRecorder()
		req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		assert.Equal(t, uint64(1), srv.storage.SessionCount())
		assert.Equal(t, uint64(1), srv.storage.SessionsTotal())
	})

	t.Run("duplicate_wrong_secret", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		body1 := registerJSON(t, &key.PublicKey, testCorrelationID, "secret-1")
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(body1))
		srv.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		body2 := registerJSON(t, &key.PublicKey, testCorrelationID, "secret-2")
		rec = httptest.NewRecorder()
		req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(body2))
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, "correlation-id provided already exists", resp["error"])
	})

	t.Run("malformed_json", func(t *testing.T) {
		srv := testServerWithStorage(t)

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", strings.NewReader("{bad json"))
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Contains(t, resp["error"], "could not decode json body")
	})

	t.Run("empty_secret_rejected", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		body := registerJSON(t, &key.PublicKey, testCorrelationID, "")
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Contains(t, resp["error"], "secret-key must not be empty")
	})

	t.Run("invalid_public_key", func(t *testing.T) {
		srv := testServerWithStorage(t)

		body, err := json.Marshal(registerRequest{
			PublicKey:     "bm90LWEta2V5",
			SecretKey:     "secret",
			CorrelationID: testCorrelationID,
		})
		require.NoError(t, err)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Contains(t, resp["error"], "could not decode public key")
	})

	t.Run("session_counter_increments", func(t *testing.T) {
		srv := testServerWithStorage(t)

		for i, id := range []string{"aaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbb"} {
			key := sharedRSAKey
			body := registerJSON(t, &key.PublicKey, id, "secret")
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(body))
			srv.Handler().ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, uint64(i+1), srv.storage.SessionCount())
			assert.Equal(t, uint64(i+1), srv.storage.SessionsTotal())
		}
	})

	t.Run("concurrent_registrations", func(t *testing.T) {
		srv := testServerWithStorage(t)

		bodies := make([][]byte, 20)
		for i := range 20 {
			key := sharedRSAKey
			cid := fmt.Sprintf("concurr%013d", i)
			bodies[i] = registerJSON(t, &key.PublicKey, cid, fmt.Sprintf("secret-%d", i))
		}

		var wg sync.WaitGroup
		for i := range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()

				rec := httptest.NewRecorder()
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(bodies[i]))
				srv.Handler().ServeHTTP(rec, req)
				assert.Equal(t, http.StatusOK, rec.Code)
			}()
		}
		wg.Wait()

		assert.Equal(t, uint64(20), srv.storage.SessionCount())
	})

	t.Run("response_auth_server", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Auth = true
			c.Token = testToken
			c.DynamicResp = true
		})
		key := sharedRSAKey

		b64Key := encodeTestPublicKey(t, &key.PublicKey)
		body, err := json.Marshal(map[string]any{
			"public-key":     b64Key,
			"secret-key":     "secret",
			"correlation-id": testCorrelationID,
			"response": map[string]any{
				"status-code": 200,
				"headers":     []string{"Content-Type: text/plain"},
				"body":        "custom",
			},
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(body))
		req.Header.Set("Authorization", testToken)
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("response_unauth_redirect_allowed", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
		})
		key := sharedRSAKey

		b64Key := encodeTestPublicKey(t, &key.PublicKey)
		body, err := json.Marshal(map[string]any{
			"public-key":     b64Key,
			"secret-key":     "secret",
			"correlation-id": testCorrelationID,
			"response": map[string]any{
				"status-code": 302,
				"headers":     []string{"Location: https://example.com"},
			},
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("response_unauth_non_redirect_rejected", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.DynamicResp = true
		})
		key := sharedRSAKey

		b64Key := encodeTestPublicKey(t, &key.PublicKey)
		body, err := json.Marshal(map[string]any{
			"public-key":     b64Key,
			"secret-key":     "secret",
			"correlation-id": testCorrelationID,
			"response": map[string]any{
				"status-code": 200,
				"body":        "not allowed",
			},
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Contains(t, resp["error"], "unauthenticated")
	})

	t.Run("response_dynamic_resp_disabled", func(t *testing.T) {
		srv := testServerWithStorage(t) // DynamicResp false by default
		key := sharedRSAKey

		b64Key := encodeTestPublicKey(t, &key.PublicKey)
		body, err := json.Marshal(map[string]any{
			"public-key":     b64Key,
			"secret-key":     "secret",
			"correlation-id": testCorrelationID,
			"response": map[string]any{
				"status-code": 302,
				"headers":     []string{"Location: https://example.com"},
			},
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Contains(t, resp["error"], "dynamic-resp")
	})
}

func TestHandlePoll(t *testing.T) {
	t.Parallel()

	t.Run("poll_with_interactions", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
		require.NoError(t, err)

		interaction := oobclient.Interaction{
			Protocol:      "http",
			UniqueID:      testCorrelationID,
			FullId:        testCorrelationID + "nop",
			RemoteAddress: "1.2.3.4",
			Timestamp:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		}
		data, err := json.Marshal(interaction)
		require.NoError(t, err)
		require.NoError(t, srv.storage.AppendInteraction(testCorrelationID, data))

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+testCorrelationID+"&secret=secret", nil)
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp pollResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		require.Len(t, resp.Data, 1)
		assert.NotEmpty(t, resp.AESKey)

		recoveredAESKey := decryptAESKey(t, resp.AESKey, key)
		assert.Equal(t, aesKey, recoveredAESKey)

		decrypted := decryptPollData(t, resp.Data[0], recoveredAESKey)

		var recovered oobclient.Interaction
		require.NoError(t, json.Unmarshal(decrypted, &recovered))
		assert.Equal(t, interaction, recovered)
	})

	t.Run("poll_empty", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		_, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+testCorrelationID+"&secret=secret", nil)
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp pollResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Empty(t, resp.Data)
		assert.Empty(t, resp.AESKey)
		assert.Empty(t, resp.Extra)
	})

	t.Run("destructive_read", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		_, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
		require.NoError(t, err)
		require.NoError(t, srv.storage.AppendInteraction(testCorrelationID, []byte(`{"protocol":"dns"}`)))

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+testCorrelationID+"&secret=secret", nil)
		srv.Handler().ServeHTTP(rec, req)

		var resp1 pollResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp1))
		assert.Len(t, resp1.Data, 1)

		rec = httptest.NewRecorder()
		req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+testCorrelationID+"&secret=secret", nil)
		srv.Handler().ServeHTTP(rec, req)

		var resp2 pollResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp2))
		assert.Empty(t, resp2.Data)
	})

	t.Run("fifo_ordering", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
		require.NoError(t, err)

		for _, proto := range []string{"dns", "http", "smtp"} {
			data, err := json.Marshal(oobclient.Interaction{Protocol: proto, UniqueID: testCorrelationID, RemoteAddress: "1.2.3.4", Timestamp: time.Now()})
			require.NoError(t, err)
			require.NoError(t, srv.storage.AppendInteraction(testCorrelationID, data))
		}

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+testCorrelationID+"&secret=secret", nil)
		srv.Handler().ServeHTTP(rec, req)

		var resp pollResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		require.Len(t, resp.Data, 3)

		for i, proto := range []string{"dns", "http", "smtp"} {
			decrypted := decryptPollData(t, resp.Data[i], aesKey)
			var inter oobclient.Interaction
			require.NoError(t, json.Unmarshal(decrypted, &inter))
			assert.Equal(t, proto, inter.Protocol)
		}
	})

	t.Run("missing_session", func(t *testing.T) {
		srv := testServerWithStorage(t)

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id=nonexistent0000000000&secret=s", nil)
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Contains(t, resp["error"], "could not get correlation-id")
	})

	t.Run("wrong_secret", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		_, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "correct", nil)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+testCorrelationID+"&secret=wrong", nil)
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, "invalid secret key passed for user", resp["error"])
	})

	t.Run("id_truncation", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		_, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+testCorrelationID+"extrachars&secret=secret", nil)
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("tlddata_omitempty", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		_, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+testCorrelationID+"&secret=secret", nil)
		srv.Handler().ServeHTTP(rec, req)

		var raw map[string]json.RawMessage
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&raw))
		_, hasTLDData := raw["tlddata"]
		assert.False(t, hasTLDData)

		extraVal, hasExtra := raw["extra"]
		assert.True(t, hasExtra)
		assert.Equal(t, "null", string(extraVal))
	})

	t.Run("data_extra_and_tlddata_combined", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Wildcard = true
			c.Auth = true
			c.Token = "tok"
			c.FTP = true
		})
		key := sharedRSAKey

		_, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
		require.NoError(t, err)

		// Populate all three buckets
		require.NoError(t, srv.storage.AppendInteraction(testCorrelationID, []byte(`{"protocol":"http"}`)))
		srv.extraBucket.Append([]byte(`{"protocol":"ftp"}`))
		srv.tldBuckets["test.com"].Append([]byte(`{"protocol":"dns"}`))

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+testCorrelationID+"&secret=secret", nil)
		req.Header.Set("Authorization", "tok")
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		var resp pollResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Len(t, resp.Data, 1)
		assert.Len(t, resp.Extra, 1)
		assert.Len(t, resp.TLDData, 1)
		assert.NotEmpty(t, resp.AESKey)
	})

	t.Run("tlddata_multiple_domains", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Domains = []string{"a.com", "b.com"}
			c.Wildcard = true
			c.Auth = true
			c.Token = "tok"
		})
		key := sharedRSAKey

		_, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
		require.NoError(t, err)

		srv.tldBuckets["a.com"].Append([]byte(`{"domain":"a.com"}`))
		srv.tldBuckets["b.com"].Append([]byte(`{"domain":"b.com"}`))

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+testCorrelationID+"&secret=secret", nil)
		req.Header.Set("Authorization", "tok")
		srv.Handler().ServeHTTP(rec, req)

		var resp pollResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		require.Len(t, resp.TLDData, 2)
		combined := strings.Join(resp.TLDData, " ")
		assert.Contains(t, combined, "a.com")
		assert.Contains(t, combined, "b.com")
	})

	t.Run("shared_bucket_per_consumer", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Wildcard = true
			c.Auth = true
			c.Token = "tok"
		})

		key1 := sharedRSAKey
		key2 := sharedRSAKey
		const id1 = "aaaaaaaaaaaaaaaaaaaa"
		const id2 = "bbbbbbbbbbbbbbbbbbbb"

		_, err := srv.storage.Register(t.Context(), id1, &key1.PublicKey, "s1", nil)
		require.NoError(t, err)
		_, err = srv.storage.Register(t.Context(), id2, &key2.PublicKey, "s2", nil)
		require.NoError(t, err)

		srv.tldBuckets["test.com"].Append([]byte(`{"protocol":"http","unique-id":"shared1"}`))

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+id1+"&secret=s1", nil)
		req.Header.Set("Authorization", "tok")
		srv.Handler().ServeHTTP(rec, req)
		var resp1 pollResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp1))
		assert.Len(t, resp1.TLDData, 1)

		rec = httptest.NewRecorder()
		req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+id2+"&secret=s2", nil)
		req.Header.Set("Authorization", "tok")
		srv.Handler().ServeHTTP(rec, req)
		var resp2 pollResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp2))
		assert.Len(t, resp2.TLDData, 1)

		srv.tldBuckets["test.com"].Append([]byte(`{"protocol":"dns","unique-id":"shared2"}`))

		for _, pair := range []struct {
			id, secret string
		}{{id1, "s1"}, {id2, "s2"}} {
			rec = httptest.NewRecorder()
			req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+pair.id+"&secret="+pair.secret, nil)
			req.Header.Set("Authorization", "tok")
			srv.Handler().ServeHTTP(rec, req)
			var resp pollResponse
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
			assert.Len(t, resp.TLDData, 1)
			assert.Contains(t, resp.TLDData[0], "shared2")
		}
	})

	t.Run("aes_key_encrypted_freshly", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		body := registerJSON(t, &key.PublicKey, testCorrelationID, "secret")
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)

		// Append and poll twice
		err := srv.storage.AppendInteraction(testCorrelationID, []byte(`{"protocol":"http"}`))
		require.NoError(t, err)
		rec1 := httptest.NewRecorder()
		req1 := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+testCorrelationID+"&secret=secret", nil)
		srv.Handler().ServeHTTP(rec1, req1)
		require.Equal(t, http.StatusOK, rec1.Code)

		var resp1 pollResponse
		require.NoError(t, json.NewDecoder(rec1.Body).Decode(&resp1))

		err = srv.storage.AppendInteraction(testCorrelationID, []byte(`{"protocol":"dns"}`))
		require.NoError(t, err)
		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+testCorrelationID+"&secret=secret", nil)
		srv.Handler().ServeHTTP(rec2, req2)
		require.Equal(t, http.StatusOK, rec2.Code)

		var resp2 pollResponse
		require.NoError(t, json.NewDecoder(rec2.Body).Decode(&resp2))

		// RSA-OAEP uses random padding: encrypted keys differ
		assert.NotEqual(t, resp1.AESKey, resp2.AESKey)
		// But they decrypt to the same underlying AES key
		decKey1 := decryptAESKey(t, resp1.AESKey, key)
		decKey2 := decryptAESKey(t, resp2.AESKey, key)
		assert.Equal(t, decKey1, decKey2)
	})

	t.Run("short_correlation_id", func(t *testing.T) {
		srv := testServerWithStorage(t)

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id=tooshort&secret=s", nil)
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Contains(t, resp["error"], "correlation-id must be at least")
	})

	t.Run("empty_secret_rejected", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		body := registerJSON(t, &key.PublicKey, testCorrelationID, "mysecret")
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)

		// Poll with empty secret
		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+testCorrelationID+"&secret=", nil)
		srv.Handler().ServeHTTP(rec2, req2)
		assert.Equal(t, http.StatusBadRequest, rec2.Code)
	})
}

func TestHandleDeregister(t *testing.T) {
	t.Parallel()

	t.Run("successful_deregister", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		_, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
		require.NoError(t, err)

		body := deregisterJSON(testCorrelationID, "secret")
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/deregister", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, "deregistration successful", resp["message"])
		assert.False(t, srv.storage.HasCorrelationID(testCorrelationID))
	})

	t.Run("missing_session", func(t *testing.T) {
		srv := testServerWithStorage(t)

		body := deregisterJSON("nonexistent0000000000", "secret")
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/deregister", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Contains(t, resp["error"], "could not get correlation-id")
	})

	t.Run("wrong_secret", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		_, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "correct", nil)
		require.NoError(t, err)

		body := deregisterJSON(testCorrelationID, "wrong")
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/deregister", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, "invalid secret key passed for user", resp["error"])
	})

	t.Run("session_counter_decrements", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		_, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
		require.NoError(t, err)
		assert.Equal(t, uint64(1), srv.storage.SessionCount())

		body := deregisterJSON(testCorrelationID, "secret")
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/deregister", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		assert.Equal(t, uint64(0), srv.storage.SessionCount())
		assert.Equal(t, uint64(1), srv.storage.SessionsTotal())
	})

	t.Run("id_truncation", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		_, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
		require.NoError(t, err)

		body := deregisterJSON(testCorrelationID+"extrachars", "secret")
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/deregister", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.False(t, srv.storage.HasCorrelationID(testCorrelationID))
	})

	t.Run("malformed_json", func(t *testing.T) {
		srv := testServerWithStorage(t)

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/deregister", strings.NewReader("not json"))
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Contains(t, resp["error"], "could not decode json body")
	})

	t.Run("short_correlation_id", func(t *testing.T) {
		srv := testServerWithStorage(t)

		body := deregisterJSON("tooshort", "secret")
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/deregister", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Contains(t, resp["error"], "correlation-id must be at least")
	})

	t.Run("second_deregister_fails", func(t *testing.T) {
		srv := testServerWithStorage(t)
		key := sharedRSAKey

		regBody := registerJSON(t, &key.PublicKey, testCorrelationID, "secret")
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(regBody))
		srv.Handler().ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)

		// First deregister succeeds
		deregBody := deregisterJSON(testCorrelationID, "secret")
		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/deregister", bytes.NewReader(deregBody))
		srv.Handler().ServeHTTP(rec2, req2)
		assert.Equal(t, http.StatusOK, rec2.Code)

		// Second deregister fails
		rec3 := httptest.NewRecorder()
		req3 := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/deregister", bytes.NewReader(deregBody))
		srv.Handler().ServeHTTP(rec3, req3)
		assert.Equal(t, http.StatusBadRequest, rec3.Code)

		var errResp map[string]string
		require.NoError(t, json.NewDecoder(rec3.Body).Decode(&errResp))
		assert.Contains(t, errResp["error"], "could not get correlation-id")
	})
}

func TestEndToEndLifecycle(t *testing.T) {
	t.Parallel()

	srv := testServerWithStorage(t)
	key := sharedRSAKey

	// 1. Register
	regBody := registerJSON(t, &key.PublicKey, testCorrelationID, "my-secret")
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(regBody))
	srv.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// 2. Store an interaction
	interaction := oobclient.Interaction{
		Protocol:      "dns",
		UniqueID:      testCorrelationID,
		FullId:        testCorrelationID + "abc",
		QType:         "A",
		RawRequest:    "query data",
		RemoteAddress: "10.0.0.1",
		Timestamp:     time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
	}
	data, err := json.Marshal(interaction)
	require.NoError(t, err)
	require.NoError(t, srv.storage.AppendInteraction(testCorrelationID, data))

	// 3. Poll - decrypt and verify
	rec = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+testCorrelationID+"&secret=my-secret", nil)
	srv.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var pollResp pollResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&pollResp))
	require.Len(t, pollResp.Data, 1)

	aesKey := decryptAESKey(t, pollResp.AESKey, key)
	decrypted := decryptPollData(t, pollResp.Data[0], aesKey)

	var recovered oobclient.Interaction
	require.NoError(t, json.Unmarshal(decrypted, &recovered))
	assert.Equal(t, interaction, recovered)

	// 4. Poll again - empty
	rec = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+testCorrelationID+"&secret=my-secret", nil)
	srv.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var emptyResp pollResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&emptyResp))
	assert.Empty(t, emptyResp.Data)

	// 5. Deregister
	deregBody := deregisterJSON(testCorrelationID, "my-secret")
	rec = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/deregister", bytes.NewReader(deregBody))
	srv.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// 6. Poll after deregister - error
	rec = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+testCorrelationID+"&secret=my-secret", nil)
	srv.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestEndpointsAuthIntegration(t *testing.T) {
	t.Parallel()

	srv := testServerWithStorage(t, func(c *Config) {
		c.Auth = true
		c.Token = "valid-token"
	})
	key := sharedRSAKey

	regBody := registerJSON(t, &key.PublicKey, testCorrelationID, "secret")

	t.Run("correct_token_passes", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(regBody))
		req.Header.Set("Authorization", "valid-token")
		srv.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("unauthorized_requests", func(t *testing.T) {
		// Wrong token
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(regBody))
		req.Header.Set("Authorization", "wrong-token")
		srv.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Empty(t, rec.Body.String())

		// Missing token
		rec = httptest.NewRecorder()
		req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(regBody))
		srv.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("poll_requires_auth", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/poll?id="+testCorrelationID+"&secret=secret", nil)
		srv.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("deregister_requires_auth", func(t *testing.T) {
		body := deregisterJSON(testCorrelationID, "secret")
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/deregister", bytes.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("default_route_no_auth", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		req.Host = "test.com"
		srv.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
