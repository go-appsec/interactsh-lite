package oobsrv

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/go-appsec/interactsh-lite/oobclient"
)

const httpBenchmarkStorageMem = true

// --- HTTP Endpoint Benchmarks ---

func BenchmarkHTTPRegister(b *testing.B) {
	srv := benchServerWithStorage(b, httpBenchmarkStorageMem)
	key := benchRSAKeyPair(b)

	// Pre-build request bodies with unique CIDs
	bodies := make([][]byte, b.N)
	for i := range bodies {
		bodies[i] = benchRegisterJSON(b, &key.PublicKey, uniqueCID(i), "secret")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequestWithContext(b.Context(), http.MethodPost, "/register", bytes.NewReader(bodies[i]))
		srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}
}

func BenchmarkHTTPRegisterKeepAlive(b *testing.B) {
	srv := benchServerWithStorage(b, httpBenchmarkStorageMem)
	key := benchRSAKeyPair(b)

	const cid = "benchkeepalive000000"
	body := benchRegisterJSON(b, &key.PublicKey, cid, "secret")

	// Initial registration
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(b.Context(), http.MethodPost, "/register", bytes.NewReader(body)))
	require.Equal(b, http.StatusOK, rec.Code)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequestWithContext(b.Context(), http.MethodPost, "/register", bytes.NewReader(body))
		srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}
}

func BenchmarkHTTPPollEmpty(b *testing.B) {
	srv := benchServerWithStorage(b, httpBenchmarkStorageMem)
	key := benchRSAKeyPair(b)

	const cid = "benchpollempty000000"
	_, err := srv.storage.Register(b.Context(), cid, &key.PublicKey, "secret", nil)
	require.NoError(b, err)
	const pollURL = "/poll?id=" + cid + "&secret=secret"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, pollURL, nil)
		srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}
}

func BenchmarkMemHTTPPollWithEvents(b *testing.B) {
	for _, count := range []int{1, 10, 100, 1000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			srv := benchServerWithStorage(b, true)
			key := benchRSAKeyPair(b)

			const cid = "benchpollwithevents0"
			aesKey, err := srv.storage.Register(b.Context(), cid, &key.PublicKey, "secret", nil)
			require.NoError(b, err)

			// Pre-encrypt interactions once, then clone into session each iteration
			template := preEncryptedInteractions(b, count, aesKey)
			ms := srv.storage.(*memoryStorage)
			const pollURL = "/poll?id=" + cid + "&secret=secret"

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Repopulation included in measurement (consistent overhead)
				data := slices.Clone(template)
				fillSessionInteractions(ms, cid, data)

				req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, pollURL, nil)
				srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
			}
		})
	}
}

func BenchmarkHTTPDeregister(b *testing.B) {
	srv := benchServerWithStorage(b, httpBenchmarkStorageMem)
	key := benchRSAKeyPair(b)

	// Pre-register all sessions and pre-build request bodies
	bodies := make([][]byte, b.N)
	for i := range bodies {
		cid := uniqueCID(i)
		_, err := srv.storage.Register(b.Context(), cid, &key.PublicKey, "secret", nil)
		require.NoError(b, err)
		bodies[i], err = json.Marshal(deregisterRequest{CorrelationID: cid, SecretKey: "secret"})
		require.NoError(b, err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequestWithContext(b.Context(), http.MethodPost, "/deregister", bytes.NewReader(bodies[i]))
		srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}
}

func BenchmarkHTTPCaptureAndPoll(b *testing.B) {
	srv := benchServerWithStorage(b, httpBenchmarkStorageMem)
	key := benchRSAKeyPair(b)

	const cid = "benchcapturepoll0000"
	_, err := srv.storage.Register(b.Context(), cid, &key.PublicKey, "secret", nil)
	require.NoError(b, err)

	const host = cid + "nop." + testDomain
	const pollURL = "/poll?id=" + cid + "&secret=secret"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Capture: HTTP request to default handler
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "/", nil)
		req.Host = host
		srv.Handler().ServeHTTP(rec, req)

		// Poll: retrieve captured interaction
		rec = httptest.NewRecorder()
		req = httptest.NewRequestWithContext(b.Context(), http.MethodGet, pollURL, nil)
		srv.Handler().ServeHTTP(rec, req)
	}
}

// --- Direct Storage Benchmarks ---

func BenchmarkStorageRegister(b *testing.B) {
	key := benchRSAKeyPair(b)
	bench := func(b *testing.B, memStorage bool) {
		b.Helper()

		ms := benchStorage(b, memStorage)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ms.Register(b.Context(), uniqueCID(i), &key.PublicKey, "secret", nil)
		}
	}

	b.Run("mem", func(b *testing.B) {
		bench(b, true)
	})

	b.Run("disk", func(b *testing.B) {
		bench(b, false)
	})
}

func BenchmarkStorageRegisterKeepAlive(b *testing.B) {
	key := benchRSAKeyPair(b)
	bench := func(b *testing.B, memStorage bool) {
		b.Helper()

		ms := benchStorage(b, memStorage)

		const cid = "benchstorekeepalive0"
		_, err := ms.Register(b.Context(), cid, &key.PublicKey, "secret", nil)
		require.NoError(b, err)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ms.Register(b.Context(), cid, &key.PublicKey, "secret", nil)
		}
	}

	b.Run("mem", func(b *testing.B) {
		bench(b, true)
	})

	b.Run("disk", func(b *testing.B) {
		bench(b, false)
	})
}

func BenchmarkMemStorageGetAndClearInteractions(b *testing.B) {
	for _, count := range []int{1, 10, 100, 1000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			key := benchRSAKeyPair(b)
			ms := benchMemoryStorage(b)

			const cid = "benchstoreclear00000"
			aesKey, err := ms.Register(b.Context(), cid, &key.PublicKey, "secret", nil)
			require.NoError(b, err)

			// Pre-encrypt once, clone each iteration
			template := preEncryptedInteractions(b, count, aesKey)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Repopulation included in measurement (consistent overhead)
				data := slices.Clone(template)
				fillSessionInteractions(ms, cid, data)

				_, _ = testGetAndClearInteractions(b, ms, cid, "secret")
			}
		})
	}
}

func BenchmarkStorageHasCorrelationID(b *testing.B) {
	key := benchRSAKeyPair(b)
	s := benchStorage(b, true) // just memstorage tested since disk defers to mem

	const cid = "benchstorehas0000000"
	_, err := s.Register(b.Context(), cid, &key.PublicKey, "secret", nil)
	require.NoError(b, err)

	b.Run("hit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			s.HasCorrelationID(cid)
		}
	})

	b.Run("miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			s.HasCorrelationID("nonexistent0000000000")
		}
	})
}

func BenchmarkStorageDelete(b *testing.B) {
	key := benchRSAKeyPair(b)
	bench := func(b *testing.B, memStorage bool) {
		b.Helper()

		s := benchStorage(b, memStorage)

		// Pre-register all sessions before measuring deletion
		for i := 0; i < b.N; i++ {
			_, err := s.Register(b.Context(), uniqueCID(i), &key.PublicKey, "secret", nil)
			require.NoError(b, err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = s.Delete(uniqueCID(i), "secret")
		}
	}

	b.Run("mem", func(b *testing.B) {
		bench(b, true)
	})

	b.Run("disk", func(b *testing.B) {
		bench(b, false)
	})
}

// --- Correlation Matching Benchmarks ---

func BenchmarkMatchCorrelationID(b *testing.B) {
	const cidLength = 20
	domains := []string{"test.com"}
	lookup := lookupSet(testCorrelationID)

	b.Run("single_label", func(b *testing.B) {
		const input = testCorrelationID + "nop.test.com"
		for i := 0; i < b.N; i++ {
			MatchCorrelationID(input, cidLength, domains, lookup)
		}
	})

	b.Run("deep_subdomain", func(b *testing.B) {
		const input = "prefix." + testCorrelationID + "nop.sub.test.com"
		for i := 0; i < b.N; i++ {
			MatchCorrelationID(input, cidLength, domains, lookup)
		}
	})

	b.Run("bare_id_fallback", func(b *testing.B) {
		const input = testCorrelationID + ".test.com"
		for i := 0; i < b.N; i++ {
			MatchCorrelationID(input, cidLength, domains, lookup)
		}
	})

	b.Run("no_match", func(b *testing.B) {
		const input = "unregistered00000nop.test.com"
		for i := 0; i < b.N; i++ {
			MatchCorrelationID(input, cidLength, domains, lookup)
		}
	})
}

func BenchmarkMatchCorrelationIDEverywhere(b *testing.B) {
	const cidLength = 20
	lookup := lookupSet(testCorrelationID)

	b.Run("short", func(b *testing.B) {
		const input = "GET / HTTP/1.1\nHost: " + testCorrelationID + "nop.test.com\n"
		for i := 0; i < b.N; i++ {
			MatchCorrelationIDEverywhere(input, cidLength, lookup)
		}
	})

	b.Run("long", func(b *testing.B) {
		// ~1KB input with CID embedded in the middle
		padding := strings.Repeat("X-Header: value\n", 30)
		input := padding + "Host: " + testCorrelationID + "nop.test.com\n" + padding
		for i := 0; i < b.N; i++ {
			MatchCorrelationIDEverywhere(input, cidLength, lookup)
		}
	})
}

func BenchmarkMatchLDAPCorrelationID(b *testing.B) {
	const cidLength = 20
	domains := []string{"test.com"}
	lookup := lookupSet(testCorrelationID)

	const baseDN = "dc=" + testCorrelationID + "nop,dc=test,dc=com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MatchLDAPCorrelationID(baseDN, cidLength, domains, lookup)
	}
}

// --- SharedBucket Benchmarks ---

func BenchmarkSharedBucketAppend(b *testing.B) {
	bucket := NewSharedBucket(100_000, 24*time.Hour)
	data := []byte("interaction-data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bucket.Append(data)
	}
}

func BenchmarkSharedBucketReadFrom(b *testing.B) {
	for _, count := range []int{0, 100, 1000} {
		name := "empty"
		if count > 0 {
			name = strconv.Itoa(count)
		}
		b.Run(name, func(b *testing.B) {
			bucket := NewSharedBucket(100_000, 24*time.Hour)
			for j := 0; j < count; j++ {
				bucket.Append([]byte(fmt.Sprintf("interaction-%d", j)))
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Use unique consumer per iteration so offset doesn't advance to end
				bucket.ReadFrom(fmt.Sprintf("consumer-%d", i))
			}
		})
	}
}

// --- Concurrent Benchmarks ---

// BenchmarkConcurrentCaptureAndPoll runs 15 goroutines each performing 1000
// HTTP interactions against dedicated sessions, while a separate goroutine
// polls all sessions every 20ms.
func BenchmarkConcurrentCaptureAndPoll(b *testing.B) {
	const (
		numWorkers       = 15
		interactionsEach = 2000
		pollInterval     = 20 * time.Millisecond
	)

	bench := func(b *testing.B, memStorage bool) {
		b.Helper()

		srv := benchServerWithStorage(b, memStorage)

		type workerSession struct {
			cid     string
			host    string
			pollURL string
		}
		sessions := make([]workerSession, numWorkers)
		for i := range sessions {
			cid := fmt.Sprintf("benchconc%011d", i)
			key := benchRSAKeyPair(b)
			_, err := srv.storage.Register(b.Context(), cid, &key.PublicKey, "secret", nil)
			require.NoError(b, err)
			sessions[i] = workerSession{
				cid:     cid,
				host:    cid + "nop." + testDomain,
				pollURL: "/poll?id=" + cid + "&secret=secret",
			}
		}

		handler := srv.Handler()

		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			var workerWg sync.WaitGroup
			stopPoller := make(chan struct{})

			// Poller goroutine: polls all sessions every 20ms
			var pollerWg sync.WaitGroup
			pollerWg.Add(1)
			go func() {
				defer pollerWg.Done()

				ticker := time.NewTicker(pollInterval)
				defer ticker.Stop()

				for {
					select {
					case <-stopPoller:
						return
					case <-ticker.C:
						for i := range sessions {
							req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, sessions[i].pollURL, nil)
							handler.ServeHTTP(httptest.NewRecorder(), req)
						}
					}
				}
			}()

			workerWg.Add(numWorkers)
			for w := 0; w < numWorkers; w++ {
				go func(s workerSession) {
					defer workerWg.Done()

					for j := 0; j < interactionsEach; j++ {
						req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "/", nil)
						req.Host = s.host
						handler.ServeHTTP(httptest.NewRecorder(), req)
					}
				}(sessions[w])
			}

			workerWg.Wait()
			close(stopPoller)
			pollerWg.Wait()
		}
	}

	b.Run("mem", func(b *testing.B) {
		bench(b, true)
	})

	b.Run("disk", func(b *testing.B) {
		bench(b, false)
	})
}

func BenchmarkSharedBucketAppendAtCapacity(b *testing.B) {
	const capacity = 10_000
	bucket := NewSharedBucket(capacity, 24*time.Hour)

	// Fill to capacity
	for j := 0; j < capacity; j++ {
		bucket.Append([]byte(fmt.Sprintf("interaction-%d", j)))
	}
	// Add some consumers with offsets so eviction adjusts them
	for j := 0; j < 10; j++ {
		bucket.ReadFrom(fmt.Sprintf("consumer-%d", j))
	}

	data := []byte("new-interaction")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bucket.Append(data)
	}
}

// --- Micro Benchmarks ---

func BenchmarkIsBase32(b *testing.B) {
	b.Run("hit_28", func(b *testing.B) {
		const input = "0a1b2c3d4e5f6g7h8i9jklmnopqr"
		for i := 0; i < b.N; i++ {
			isCIDBase32(input)
		}
	})

	b.Run("miss_late", func(b *testing.B) {
		const input = "0a1b2c3d4e5f6g7h8i9lmnoZ"
		for i := 0; i < b.N; i++ {
			isCIDBase32(input)
		}
	})
}

// --- Helpers ---

func benchRSAKeyPair(b *testing.B) *rsa.PrivateKey {
	b.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(b, err)
	return key
}

func benchEncodePublicKey(b *testing.B, pub *rsa.PublicKey) string {
	b.Helper()

	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(b, err)
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: der,
	})
	return base64.StdEncoding.EncodeToString(pemBlock)
}

func benchRegisterJSON(b *testing.B, pubKey *rsa.PublicKey, correlationID, secretKey string) []byte {
	b.Helper()

	body, err := json.Marshal(registerRequest{
		PublicKey:     benchEncodePublicKey(b, pubKey),
		SecretKey:     secretKey,
		CorrelationID: correlationID,
	})
	require.NoError(b, err)
	return body
}

func benchServerWithStorage(b *testing.B, memStorage bool) *Server {
	b.Helper()

	cfg := validTestConfig()
	if !memStorage {
		cfg.Disk = true
		cfg.DiskPath = filepath.Join(b.TempDir(), "storage")
	}
	logger := slog.New(slog.DiscardHandler)
	srv, err := New(cfg, logger)
	require.NoError(b, err)
	b.Cleanup(srv.closeStorage)
	return srv
}

func benchStorage(b *testing.B, memStorage bool) Storage {
	b.Helper()

	if memStorage {
		return benchMemoryStorage(b)
	}
	cfg := validTestConfig()
	cfg.Disk = true
	cfg.DiskPath = filepath.Join(b.TempDir(), "storage")
	s, err := NewDiskStorage(cfg, slog.New(slog.DiscardHandler))
	require.NoError(b, err)
	b.Cleanup(func() { _ = s.Close() })
	return s
}

func benchMemoryStorage(b *testing.B) *memoryStorage {
	b.Helper()

	s := NewMemoryStorage(validTestConfig(), slog.New(slog.DiscardHandler))
	b.Cleanup(func() { _ = s.Close() })
	return s
}

// uniqueCID returns a 20-character correlation ID unique to i.
func uniqueCID(i int) string {
	return fmt.Sprintf("b%019d", i)
}

func sampleInteractionJSON(cid string) []byte {
	data, _ := json.Marshal(oobclient.Interaction{
		Protocol:      "http",
		UniqueID:      cid,
		FullId:        cid + "nop",
		RawRequest:    "GET / HTTP/1.1\r\nHost: " + cid + "nop.test.com\r\nUser-Agent: bench\r\n\r\n",
		RawResponse:   "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body></body></html>",
		RemoteAddress: "1.2.3.4",
		Timestamp:     time.Now().UTC(),
	})
	return data
}

// fillSessionInteractions directly sets a session's interaction slice,
// bypassing encryption. Use this for benchmarks that measure retrieval/clear
// paths to avoid expensive AES encryption in the repopulation step.
func fillSessionInteractions(ms *memoryStorage, cid string, data [][]byte) {
	ms.mu.RLock()
	session := ms.sessions[cid]
	ms.mu.RUnlock()

	session.mu.Lock()
	session.interactions = data
	session.mu.Unlock()
}

// preEncryptedInteractions returns n pre-encrypted interactions.
func preEncryptedInteractions(b *testing.B, n int, aesKey []byte) [][]byte {
	b.Helper()

	interaction := sampleInteractionJSON("benchpreencrypted000")
	out := make([][]byte, n)
	for i := range out {
		encrypted, err := EncryptInteraction(interaction, aesKey)
		require.NoError(b, err)
		out[i] = encrypted
	}
	return out
}
