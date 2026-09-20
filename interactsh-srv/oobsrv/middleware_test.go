package oobsrv

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCORSMiddleware(t *testing.T) {
	t.Parallel()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	t.Run("options_returns_204", func(t *testing.T) {
		h := CORSMiddleware("*", inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/", nil)
		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "GET, POST, OPTIONS", rec.Header().Get("Access-Control-Allow-Methods"))
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
		assert.Equal(t, "Content-Type, Authorization", rec.Header().Get("Access-Control-Allow-Headers"))
		assert.Empty(t, rec.Body.String())
	})

	t.Run("get_passes_through", func(t *testing.T) {
		h := CORSMiddleware("*", inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "ok", rec.Body.String())
	})

	t.Run("custom_acao_url", func(t *testing.T) {
		h := CORSMiddleware("https://example.com", inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		h.ServeHTTP(rec, req)

		assert.Equal(t, "https://example.com", rec.Header().Get("Access-Control-Allow-Origin"))
	})
}

func TestInteractionCORSMiddleware(t *testing.T) {
	t.Parallel()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	t.Run("reflects_origin", func(t *testing.T) {
		h := InteractionCORSMiddleware(inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "https://evil.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", rec.Header().Get("Access-Control-Allow-Credentials"))
		assert.Equal(t, "cross-origin", rec.Header().Get("Cross-Origin-Resource-Policy"))
		assert.Equal(t, "unsafe-url", rec.Header().Get("Referrer-Policy"))
		assert.Equal(t, standardCORSExposeHeaders, rec.Header().Get("Access-Control-Expose-Headers"))
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Methods"))
		assert.Empty(t, rec.Header().Get("Allow"))
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Headers"))
		assert.Equal(t, "Origin, Access-Control-Request-Method, Access-Control-Request-Headers", rec.Header().Get("Vary"))
	})

	t.Run("wildcard_without_origin", func(t *testing.T) {
		h := InteractionCORSMiddleware(inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		h.ServeHTTP(rec, req)

		assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", rec.Header().Get("Access-Control-Allow-Credentials"))
	})

	t.Run("options_reflects_preflight", func(t *testing.T) {
		h := InteractionCORSMiddleware(inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/", nil)
		req.Header.Set("Origin", "https://attacker.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "https://attacker.com", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", rec.Header().Get("Access-Control-Allow-Credentials"))
		assert.Equal(t, "cross-origin", rec.Header().Get("Cross-Origin-Resource-Policy"))
		assert.Equal(t, "unsafe-url", rec.Header().Get("Referrer-Policy"))
		assert.Equal(t, standardCORSExposeHeaders, rec.Header().Get("Access-Control-Expose-Headers"))
		assert.Equal(t, "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS", rec.Header().Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS", rec.Header().Get("Allow"))
		assert.Equal(t, "authorization, content-type", rec.Header().Get("Access-Control-Allow-Headers"))
		assert.Equal(t, "Origin, Access-Control-Request-Method, Access-Control-Request-Headers", rec.Header().Get("Vary"))
		assert.Empty(t, rec.Body.String())
	})

	t.Run("options_without_request_headers", func(t *testing.T) {
		h := InteractionCORSMiddleware(inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/", nil)
		req.Header.Set("Origin", "https://attacker.com")
		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS", rec.Header().Get("Access-Control-Allow-Methods"))
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Headers"))
	})

	t.Run("options_reflects_nonstandard_method", func(t *testing.T) {
		h := InteractionCORSMiddleware(inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/", nil)
		req.Header.Set("Access-Control-Request-Method", "PROPFIND")
		h.ServeHTTP(rec, req)

		assert.Equal(t, "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, PROPFIND", rec.Header().Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, PROPFIND", rec.Header().Get("Allow"))
	})

	t.Run("options_reflects_lowercase_method", func(t *testing.T) {
		h := InteractionCORSMiddleware(inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/", nil)
		req.Header.Set("Access-Control-Request-Method", "mkcol")
		h.ServeHTTP(rec, req)

		assert.Equal(t, "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, MKCOL", rec.Header().Get("Access-Control-Allow-Methods"))
	})

	t.Run("options_standard_method_unchanged", func(t *testing.T) {
		h := InteractionCORSMiddleware(inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/", nil)
		req.Header.Set("Access-Control-Request-Method", "POST")
		h.ServeHTTP(rec, req)

		assert.Equal(t, "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS", rec.Header().Get("Access-Control-Allow-Methods"))
	})

	t.Run("options_private_network_reflected", func(t *testing.T) {
		h := InteractionCORSMiddleware(inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/", nil)
		req.Header.Set("Access-Control-Request-Private-Network", "true")
		h.ServeHTTP(rec, req)

		assert.Equal(t, "true", rec.Header().Get("Access-Control-Allow-Private-Network"))
	})

	t.Run("options_private_network_absent", func(t *testing.T) {
		h := InteractionCORSMiddleware(inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/", nil)
		h.ServeHTTP(rec, req)

		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Private-Network"))
	})

	t.Run("options_private_network_non_true", func(t *testing.T) {
		h := InteractionCORSMiddleware(inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/", nil)
		req.Header.Set("Access-Control-Request-Private-Network", "false")
		h.ServeHTTP(rec, req)

		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Private-Network"))
	})

	t.Run("corp_set_on_get", func(t *testing.T) {
		h := InteractionCORSMiddleware(inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		h.ServeHTTP(rec, req)

		assert.Equal(t, "cross-origin", rec.Header().Get("Cross-Origin-Resource-Policy"))
	})

	t.Run("corp_set_on_options", func(t *testing.T) {
		h := InteractionCORSMiddleware(inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/", nil)
		h.ServeHTTP(rec, req)

		assert.Equal(t, "cross-origin", rec.Header().Get("Cross-Origin-Resource-Policy"))
	})
}

func TestAuthMiddleware(t *testing.T) {
	t.Parallel()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("authorized"))
	})

	tests := []struct {
		name     string
		authHdr  string
		wantCode int
		wantBody string
	}{
		{"correct_token_passes", "secret", http.StatusOK, "authorized"},
		{"wrong_token_401", "wrong", http.StatusUnauthorized, ""},
		{"missing_header_401", "", http.StatusUnauthorized, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := AuthMiddleware(true, "secret", inner)
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			if tt.authHdr != "" {
				req.Header.Set("Authorization", tt.authHdr)
			}
			h.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)
			assert.Equal(t, tt.wantBody, rec.Body.String())
		})
	}

	t.Run("disabled_passes_all", func(t *testing.T) {
		h := AuthMiddleware(false, "", inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("empty_token_accepts_no_header", func(t *testing.T) {
		var called bool
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})

		h := AuthMiddleware(true, "", inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		// No Authorization header - Get returns "" which matches empty token
		h.ServeHTTP(rec, req)

		assert.True(t, called)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("empty_token_rejects_with_header", func(t *testing.T) {
		var called bool
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		h := AuthMiddleware(true, "", inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "anything")
		h.ServeHTTP(rec, req)

		assert.False(t, called)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestLoggerMiddleware(t *testing.T) {
	t.Parallel()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "value")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("response body"))
	})

	t.Run("captures_request_response", func(t *testing.T) {
		type capture struct {
			req, resp string
			addr      string
		}
		ch := make(chan capture, 1)
		callback := func(_ *http.Request, rawReq, rawResp, remoteAddr, _, _ string) {
			ch <- capture{rawReq, rawResp, remoteAddr}
		}

		h := LoggerMiddleware("", callback, inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/test", strings.NewReader("request body"))
		req.RemoteAddr = "192.168.1.1:12345"
		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code)
		assert.Equal(t, "response body", rec.Body.String())
		assert.Equal(t, "value", rec.Header().Get("X-Test"))

		select {
		case got := <-ch:
			assert.Contains(t, got.req, "POST /test")
			assert.Contains(t, got.req, "request body")
			assert.Contains(t, got.resp, "201")
			assert.Contains(t, got.resp, "response body")
			assert.Equal(t, "192.168.1.1", got.addr)
		case <-time.After(time.Second):
			t.Fatal("callback not called")
		}
	})

	t.Run("origin_ip_header", func(t *testing.T) {
		ch := make(chan string, 1)
		callback := func(_ *http.Request, _, _, remoteAddr, _, _ string) {
			ch <- remoteAddr
		}

		h := LoggerMiddleware("X-Real-IP", callback, inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		req.Header.Set("X-Real-IP", "203.0.113.1")
		h.ServeHTTP(rec, req)

		select {
		case addr := <-ch:
			assert.Equal(t, "203.0.113.1", addr)
		case <-time.After(time.Second):
			t.Fatal("callback not called")
		}
	})

	t.Run("options_captured_with_cors", func(t *testing.T) {
		var captured atomic.Bool
		callback := func(_ *http.Request, _, _, _, _, _ string) {
			captured.Store(true)
		}

		corsInner := InteractionCORSMiddleware(inner)
		h := LoggerMiddleware("", callback, corsInner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/test", nil)
		req.RemoteAddr = "1.2.3.4:5"
		h.ServeHTTP(rec, req)

		require.Eventually(t, captured.Load, time.Second, 5*time.Millisecond)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("nil_callback", func(t *testing.T) {
		h := LoggerMiddleware("", nil, inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code)
		assert.Equal(t, "response body", rec.Body.String())
	})

	t.Run("implicit_writeheader_on_write", func(t *testing.T) {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Write body first (implicit 200), then try to set 201
			_, _ = w.Write([]byte("body"))
			w.WriteHeader(http.StatusCreated) // no-op: wroteHeader already true
		})

		h := LoggerMiddleware("", nil, inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		h.ServeHTTP(rec, req)

		// Implicit WriteHeader(200) from Write wins
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "body", rec.Body.String())
	})
}

func TestMaxRequestSizeMiddleware(t *testing.T) {
	t.Parallel()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	t.Run("truncates_at_limit", func(t *testing.T) {
		h := MaxRequestSizeMiddleware(1, inner) // 1 MB
		largeBody := strings.Repeat("x", 2*1024*1024)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(largeBody))
		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, 1*1024*1024, rec.Body.Len())
	})

	t.Run("small_body_passes", func(t *testing.T) {
		h := MaxRequestSizeMiddleware(1, inner)
		const body = "small body"
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(body))
		h.ServeHTTP(rec, req)

		assert.Equal(t, body, rec.Body.String())
	})

	t.Run("exact_boundary_no_truncation", func(t *testing.T) {
		var receivedLen int
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, _ := io.ReadAll(r.Body)
			receivedLen = len(data)
			w.WriteHeader(http.StatusOK)
		})

		bodySize := 1 * 1024 * 1024 // exactly 1 MiB
		h := MaxRequestSizeMiddleware(1, inner)
		body := strings.NewReader(strings.Repeat("x", bodySize))
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", body)
		h.ServeHTTP(rec, req)

		assert.Equal(t, bodySize, receivedLen)
	})
}

func TestExtractRemoteAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		remoteAddr     string
		originIPHeader string
		headerValue    string
		want           string
	}{
		{"ip_from_remote_addr", "192.168.1.1:12345", "", "", "192.168.1.1"},
		{"ipv6_from_remote_addr", "[::1]:12345", "", "", "::1"},
		{"header_override", "10.0.0.1:1234", "X-Forwarded-For", "203.0.113.1", "203.0.113.1"},
		{"header_absent_fallback", "10.0.0.1:1234", "X-Forwarded-For", "", "10.0.0.1"},
		{"no_port_in_remote_addr", "192.168.1.1", "", "", "192.168.1.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.headerValue != "" {
				req.Header.Set(tt.originIPHeader, tt.headerValue)
			}
			assert.Equal(t, tt.want, ExtractRemoteAddr(req, tt.originIPHeader))
		})
	}
}

func TestResponseHeadersMiddleware(t *testing.T) {
	t.Parallel()

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("sets_server_header", func(t *testing.T) {
		h := ResponseHeadersMiddleware("myserver", "v1.0", false, false, inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		h.ServeHTTP(rec, req)

		assert.Equal(t, "myserver", rec.Header().Get("Server"))
		assert.Equal(t, "v1.0", rec.Header().Get("X-Interactsh-Version"))
	})

	t.Run("version_header_disabled", func(t *testing.T) {
		h := ResponseHeadersMiddleware("srv", "v1.0", true, false, inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		h.ServeHTTP(rec, req)

		assert.Equal(t, "srv", rec.Header().Get("Server"))
		assert.Empty(t, rec.Header().Get("X-Interactsh-Version"))
	})

	t.Run("api_content_headers", func(t *testing.T) {
		h := ResponseHeadersMiddleware("srv", "v1", false, true, inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api", nil)
		h.ServeHTTP(rec, req)

		assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
		assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	})

	t.Run("non_api_no_content_headers", func(t *testing.T) {
		h := ResponseHeadersMiddleware("srv", "v1", false, false, inner)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		h.ServeHTTP(rec, req)

		assert.Empty(t, rec.Header().Get("X-Content-Type-Options"))
	})
}
