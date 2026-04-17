package oobsrv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCert creates a self-signed certificate and key in dir, returning the file paths.
func generateTestCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certFile, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	require.NoError(t, certFile.Close())

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyFile, err := os.Create(keyPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	require.NoError(t, keyFile.Close())

	return certPath, keyPath
}

func testServer(t *testing.T, cfg Config) *Server {
	t.Helper()

	if len(cfg.Domains) == 0 {
		cfg.Domains = []string{"test.example.com"}
	}
	if cfg.CorrelationIdLength == 0 {
		cfg.CorrelationIdLength = 20
	}
	if cfg.EvictionStrategy == "" {
		cfg.EvictionStrategy = EvictionSliding
	}
	srv, err := New(cfg, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)
	return srv
}

func TestACMEProviderAppendRecords(t *testing.T) {
	t.Parallel()

	t.Run("sets_record", func(t *testing.T) {
		store := newACMEStore()
		provider := &acmeProvider{store: store}

		recs := []libdns.Record{
			libdns.TXT{Name: "_acme-challenge", Text: "token123"},
		}
		result, err := provider.AppendRecords(t.Context(), "example.com.", recs)
		require.NoError(t, err)
		assert.Len(t, result, 1)

		v, ok := store.Get("_acme-challenge.example.com")
		assert.True(t, ok)
		assert.Equal(t, "token123", v)
	})

	t.Run("ignores_non_txt", func(t *testing.T) {
		store := newACMEStore()
		provider := &acmeProvider{store: store}

		recs := []libdns.Record{
			libdns.RR{Name: "sub", Type: "A", Data: "1.2.3.4"},
		}
		result, err := provider.AppendRecords(t.Context(), "example.com.", recs)
		require.NoError(t, err)
		assert.Empty(t, result)
	})
}

func TestACMEProviderDeleteRecords(t *testing.T) {
	t.Parallel()

	t.Run("removes_record", func(t *testing.T) {
		store := newACMEStore()
		store.Set("_acme-challenge.example.com", "token123")
		provider := &acmeProvider{store: store}

		recs := []libdns.Record{
			libdns.TXT{Name: "_acme-challenge", Text: "token123"},
		}
		result, err := provider.DeleteRecords(t.Context(), "example.com.", recs)
		require.NoError(t, err)
		assert.Len(t, result, 1)

		_, ok := store.Get("_acme-challenge.example.com")
		assert.False(t, ok)
	})

	t.Run("ignores_non_txt_on_delete", func(t *testing.T) {
		store := newACMEStore()
		p := &acmeProvider{store: store}

		// Store a TXT record first
		store.Set("_acme-challenge.example.com", "token123")

		// Delete with mix of TXT and non-TXT records
		recs := []libdns.Record{
			libdns.TXT{Name: "_acme-challenge", Text: "token123"},
			libdns.RR{Name: "_acme-challenge", Type: "A", Data: "1.2.3.4"},
		}
		deleted, err := p.DeleteRecords(t.Context(), "example.com.", recs)
		require.NoError(t, err)

		// Only TXT record should be in deleted list
		require.Len(t, deleted, 1)
		assert.Equal(t, "TXT", deleted[0].RR().Type)

		// Store should be empty for the key
		_, ok := store.Get("_acme-challenge.example.com")
		assert.False(t, ok)
	})
}

func TestToFQDN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		rName string
		zone  string
		want  string
	}{
		{"simple", "_acme-challenge", "example.com.", "_acme-challenge.example.com"},
		{"nested", "_acme-challenge.sub", "example.com.", "_acme-challenge.sub.example.com"},
		{"uppercase_zone", "_acme-challenge", "Example.COM.", "_acme-challenge.example.com"},
		{"empty_name", "", "example.com.", "example.com"},
		{"name_trailing_dot", "_acme-challenge.", "example.com.", "_acme-challenge"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, toFQDN(tt.rName, tt.zone))
		})
	}
}

func closeServices(t *testing.T, srv *Server) {
	t.Helper()

	for i := len(srv.services) - 1; i >= 0; i-- {
		assert.NoError(t, srv.services[i].Close())
	}
}

func TestCertReloader(t *testing.T) {
	t.Parallel()

	t.Run("loads_initial_cert", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateTestCert(t, dir)

		r, err := newCertReloader(certPath, keyPath, testLogger())
		require.NoError(t, err)

		cert, err := r.GetCertificate(nil)
		require.NoError(t, err)
		assert.NotNil(t, cert)
	})

	t.Run("rejects_missing_file", func(t *testing.T) {
		dir := t.TempDir()
		_, err := newCertReloader(filepath.Join(dir, "bad.pem"), filepath.Join(dir, "bad-key.pem"), testLogger())
		assert.Error(t, err)
	})

	t.Run("reloads_on_change", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateTestCert(t, dir)

		// Backdate so regenerated files are clearly newer
		past := time.Now().Add(-time.Hour)
		require.NoError(t, os.Chtimes(certPath, past, past))
		require.NoError(t, os.Chtimes(keyPath, past, past))

		r, err := newCertReloader(certPath, keyPath, testLogger())
		require.NoError(t, err)
		r.interval = 10 * time.Millisecond

		require.NoError(t, r.Start())
		t.Cleanup(func() { _ = r.Close() })

		origCert, err := r.GetCertificate(nil)
		require.NoError(t, err)
		origDER := origCert.Certificate[0]

		generateTestCert(t, dir) // Overwrite with a new cert (new random key = different DER)

		assert.Eventually(t, func() bool {
			cert, _ := r.GetCertificate(nil)
			return !assert.ObjectsAreEqual(origDER, cert.Certificate[0])
		}, time.Second, 10*time.Millisecond)
	})

	t.Run("ignores_unchanged_files", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateTestCert(t, dir)

		r, err := newCertReloader(certPath, keyPath, testLogger())
		require.NoError(t, err)
		r.interval = 10 * time.Millisecond

		require.NoError(t, r.Start())
		t.Cleanup(func() { _ = r.Close() })

		origCert, err := r.GetCertificate(nil)
		require.NoError(t, err)

		time.Sleep(50 * time.Millisecond) // Wait for several tick cycles

		curr, err := r.GetCertificate(nil)
		require.NoError(t, err)
		assert.Same(t, origCert, curr)
	})

	t.Run("service_lifecycle", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateTestCert(t, dir)

		r, err := newCertReloader(certPath, keyPath, testLogger())
		require.NoError(t, err)

		assert.Equal(t, "cert-reloader", r.Name())
		require.NoError(t, r.Start())

		// Close should return promptly without hanging
		done := make(chan struct{})
		go func() { _ = r.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("Close did not return in time")
		}
	})
}

func TestLatestModTime(t *testing.T) {
	t.Parallel()

	t.Run("returns_latest", func(t *testing.T) {
		dir := t.TempDir()
		older := filepath.Join(dir, "older.pem")
		newer := filepath.Join(dir, "newer.pem")

		require.NoError(t, os.WriteFile(older, []byte("old"), 0o600))
		require.NoError(t, os.WriteFile(newer, []byte("new"), 0o600))
		require.NoError(t, os.Chtimes(older, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour)))

		mt, err := latestModTime(older, newer)
		require.NoError(t, err)

		newerInfo, err := os.Stat(newer)
		require.NoError(t, err)
		assert.Equal(t, newerInfo.ModTime(), mt)
	})

	t.Run("missing_file", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "exists.pem")
		require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))

		_, err := latestModTime(f, filepath.Join(dir, "missing.pem"))
		assert.Error(t, err)
	})
}

func TestGenerateSelfSignedCert(t *testing.T) {
	t.Parallel()

	t.Run("returns_valid_config", func(t *testing.T) {
		tlsCfg, err := generateSelfSignedCert(nil)
		require.NoError(t, err)
		require.NotNil(t, tlsCfg)
		assert.Len(t, tlsCfg.Certificates, 1)
		assert.Equal(t, serverNextProtos, tlsCfg.NextProtos)
	})

	t.Run("cert_properties", func(t *testing.T) {
		domains := []string{"oast.example.com", "oast2.example.com"}
		tlsCfg, err := generateSelfSignedCert(domains)
		require.NoError(t, err)

		cert, err := x509.ParseCertificate(tlsCfg.Certificates[0].Certificate[0])
		require.NoError(t, err)

		// SANs include localhost, configured domains, and wildcards
		assert.Contains(t, cert.DNSNames, "localhost")
		assert.Contains(t, cert.DNSNames, "oast.example.com")
		assert.Contains(t, cert.DNSNames, "*.oast.example.com")
		assert.Contains(t, cert.DNSNames, "oast2.example.com")
		assert.Contains(t, cert.DNSNames, "*.oast2.example.com")
		assert.True(t, cert.IPAddresses[0].Equal(net.IPv4(127, 0, 0, 1)))
		assert.True(t, cert.IPAddresses[1].Equal(net.IPv6loopback))

		// Validity (~10 years)
		expectedValidity := 10 * 365 * 24 * time.Hour
		actualValidity := cert.NotAfter.Sub(cert.NotBefore)
		tolerance := 2 * 24 * time.Hour
		assert.InDelta(t, expectedValidity.Seconds(), actualValidity.Seconds(), tolerance.Seconds())

		// Key usage
		assert.NotZero(t, cert.KeyUsage&x509.KeyUsageDigitalSignature)
		assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	})
}

func TestWildcardFallbackCertGetter(t *testing.T) {
	t.Parallel()

	// Build a matcher that mirrors Server.matchedDomain against a fixed domain list.
	newMatch := func(domains []string) func(string) (string, bool) {
		return func(name string) (string, bool) {
			for _, d := range domains {
				if name == d || strings.HasSuffix(name, "."+d) {
					return d, true
				}
			}
			return "", false
		}
	}

	tests := []struct {
		name       string
		domains    []string // longest-first, lowercased
		sni        string
		wantSNI    string // SNI passed to inner
		wantNoCall bool   // inner expected to return an error when false is false? (unused here)
		innerErr   error
		wantErr    bool
	}{
		{"exact_domain_passthrough", []string{"oscar.oastsrv.net"}, "oscar.oastsrv.net", "oscar.oastsrv.net", false, nil, false},
		{"single_label_passthrough", []string{"oscar.oastsrv.net"}, "cid.oscar.oastsrv.net", "cid.oscar.oastsrv.net", false, nil, false},
		{"deep_subdomain_rewritten", []string{"oscar.oastsrv.net"}, "foo.cid.oscar.oastsrv.net", "wild.oscar.oastsrv.net", false, nil, false},
		{"very_deep_subdomain_rewritten", []string{"oscar.oastsrv.net"}, "foo.bar.cid.oscar.oastsrv.net", "wild.oscar.oastsrv.net", false, nil, false},
		{"uppercase_sni_lowercased", []string{"oscar.oastsrv.net"}, "FOO.CID.Oscar.OASTSRV.NET", "wild.oscar.oastsrv.net", false, nil, false},
		{"most_specific_domain_wins", []string{"oscar.oastsrv.net", "oastsrv.net"}, "foo.cid.oscar.oastsrv.net", "wild.oscar.oastsrv.net", false, nil, false},
		{"empty_sni_uses_first_domain", []string{"oscar.oastsrv.net", "alpha.oastsrv.net"}, "", "wild.oscar.oastsrv.net", false, nil, false},
		{"unrelated_sni_uses_first_domain", []string{"oscar.oastsrv.net"}, "evil.example.com", "wild.oscar.oastsrv.net", false, nil, false},
		{"no_domains_configured_passthrough", nil, "anything.example.com", "anything.example.com", false, errors.New("no cert"), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var seenSNI string
			inner := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				seenSNI = hello.ServerName
				if tc.innerErr != nil {
					return nil, tc.innerErr
				}
				return &tls.Certificate{}, nil
			}
			get := wildcardFallbackCertGetter(inner, newMatch(tc.domains), tc.domains)
			_, err := get(&tls.ClientHelloInfo{ServerName: tc.sni})
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.wantSNI, seenSNI)
		})
	}

	t.Run("preserves_hello_fields", func(t *testing.T) {
		var received *tls.ClientHelloInfo
		inner := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			received = hello
			return &tls.Certificate{}, nil
		}
		get := wildcardFallbackCertGetter(inner, newMatch([]string{"oscar.oastsrv.net"}), []string{"oscar.oastsrv.net"})
		orig := &tls.ClientHelloInfo{
			ServerName:        "foo.cid.oscar.oastsrv.net",
			SupportedProtos:   []string{"h2", "http/1.1"},
			SupportedVersions: []uint16{tls.VersionTLS13},
		}
		_, err := get(orig)
		require.NoError(t, err)
		require.NotNil(t, received)
		assert.Equal(t, "wild.oscar.oastsrv.net", received.ServerName)
		assert.Equal(t, []string{"h2", "http/1.1"}, received.SupportedProtos)
		assert.Equal(t, []uint16{tls.VersionTLS13}, received.SupportedVersions)
		// original hello must not be mutated (concurrent handshakes share nothing)
		assert.Equal(t, "foo.cid.oscar.oastsrv.net", orig.ServerName)
	})
}

func TestProvisionTLS(t *testing.T) {
	t.Parallel()

	t.Run("skip_acme_no_tls", func(t *testing.T) {
		srv := testServer(t, Config{
			SkipACME: true,
		})
		srv.provisionTLS(t.Context())
		assert.Nil(t, srv.tlsConfig)
	})

	t.Run("custom_cert_priority", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateTestCert(t, dir)

		srv := testServer(t, Config{
			CertFile:    certPath,
			PrivKeyFile: keyPath,
		})
		srv.provisionTLS(t.Context())
		t.Cleanup(func() { closeServices(t, srv) })

		require.NotNil(t, srv.tlsConfig)
		assert.NotNil(t, srv.tlsConfig.GetCertificate)
		assert.Equal(t, serverNextProtos, srv.tlsConfig.NextProtos)

		cert, err := srv.tlsConfig.GetCertificate(nil)
		require.NoError(t, err)
		assert.NotNil(t, cert)

		// Reloader registered as a service
		require.Len(t, srv.services, 1)
		assert.Equal(t, "cert-reloader", srv.services[0].Name())
	})

	t.Run("invalid_custom_cert", func(t *testing.T) {
		dir := t.TempDir()
		srv := testServer(t, Config{
			CertFile:    filepath.Join(dir, "bad.pem"),
			PrivKeyFile: filepath.Join(dir, "bad-key.pem"),
		})
		srv.provisionTLS(t.Context())
		assert.Nil(t, srv.tlsConfig)
	})

	t.Run("acme_failure_falls_to_self_signed", func(t *testing.T) {
		srv := testServer(t, Config{
			SkipACME: false,
		})
		srv.provisionTLS(t.Context())

		require.NotNil(t, srv.tlsConfig)
		assert.GreaterOrEqual(t, len(srv.tlsConfig.Certificates), 1)
	})
}

func TestStartHTTPS(t *testing.T) {
	t.Parallel()

	t.Run("starts_with_tls", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateTestCert(t, dir)

		srv := testServer(t, Config{
			ListenIP:    "127.0.0.1",
			HTTPSPort:   0,
			CertFile:    certPath,
			PrivKeyFile: keyPath,
		})
		srv.provisionTLS(t.Context())
		require.NotNil(t, srv.tlsConfig)
		t.Cleanup(func() { closeServices(t, srv) })

		// Verify service is registered (reloader already added by provisionTLS)
		initialCount := len(srv.services)
		require.NoError(t, srv.startHTTPS())
		assert.Len(t, srv.services, initialCount+1)
		assert.Equal(t, "HTTPS", srv.services[len(srv.services)-1].Name())
	})

	t.Run("skipped_without_tls", func(t *testing.T) {
		// tlsConfig is nil only if self-signed generation fails (extremely unlikely)
		// Verify startHTTPS is a no-op when tlsConfig is nil
		srv := testServer(t, Config{})
		srv.tlsConfig = nil

		initialCount := len(srv.services)
		require.NoError(t, srv.startHTTPS())
		assert.Len(t, srv.services, initialCount)
	})
}
