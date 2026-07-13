package oobsrv

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	netsmtp "net/smtp"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
		DNSNames:     []string{testDomain, "*." + testDomain},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{derBytes},
			PrivateKey:  key,
		}},
	}
}

// smtpTestServer starts an SMTP server on an ephemeral port.
// Returns the listener address and a cleanup function.
func smtpTestServer(t *testing.T, srv *Server, tlsCfg *tls.Config, implicitTLS bool) (string, func()) {
	t.Helper()
	backend := &smtpBackend{server: srv}

	smtpSrv := smtp.NewServer(backend)
	smtpSrv.Domain = testDomain
	smtpSrv.AllowInsecureAuth = true
	smtpSrv.ReadTimeout = 5 * time.Second
	smtpSrv.WriteTimeout = 5 * time.Second

	if tlsCfg != nil && !implicitTLS {
		smtpSrv.TLSConfig = tlsCfg
	}

	var ln net.Listener
	var err error
	if implicitTLS && tlsCfg != nil {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	} else {
		var lc net.ListenConfig
		ln, err = lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	}
	require.NoError(t, err)

	ln = &teeListener{Listener: ln}

	go func() { _ = smtpSrv.Serve(ln) }()

	return ln.Addr().String(), func() { _ = smtpSrv.Close() }
}

func TestOnSMTPData(t *testing.T) {
	t.Parallel()

	t.Run("increments_smtp_count", func(t *testing.T) {
		srv := testServerWithStorage(t)
		srv.onSMTPData("sender@example.com", []string{"user@" + testDomain}, []byte("body"), "1.2.3.4:25")
		assert.Equal(t, uint64(1), srv.smtpCount.Load())
	})

	t.Run("counter_once_per_data", func(t *testing.T) {
		srv := testServerWithStorage(t)
		rcpts := []string{"a@example.com", "b@example.com", "c@example.com"}
		srv.onSMTPData("from@example.com", rcpts, []byte("body"), "1.2.3.4:25")
		assert.Equal(t, uint64(1), srv.smtpCount.Load())
	})

	t.Run("stores_correlation_match", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		rcpt := "user@" + testCorrelationID + testNonce + "." + testDomain
		srv.onSMTPData("sender@example.com", []string{rcpt}, []byte("email body"), "10.0.0.1:25")

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)

		decrypted := decryptTestInteraction(t, interactions[0], aesKey)
		var interaction InteractionType
		require.NoError(t, json.Unmarshal([]byte(decrypted), &interaction))

		assert.Equal(t, "smtp", interaction.Protocol)
		assert.Equal(t, testCorrelationID, interaction.UniqueID)
		assert.Equal(t, testCorrelationID+testNonce, interaction.FullId)
		assert.Equal(t, "email body", interaction.RawRequest)
		assert.Equal(t, "sender@example.com", interaction.SMTPFrom)
		assert.Equal(t, "10.0.0.1", interaction.RemoteAddress)
		assert.Empty(t, interaction.RawResponse)
		assert.Empty(t, interaction.QType)
		assert.False(t, interaction.Timestamp.IsZero())
	})

	t.Run("unconfigured_domain", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		rcpt := "user@" + testCorrelationID + testNonce + ".other.org"
		srv.onSMTPData("sender@example.com", []string{rcpt}, []byte("body"), "1.2.3.4:25")

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		assert.Empty(t, interactions)
	})

	t.Run("multiple_recipients_different_cids", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		cid1 := testCorrelationID
		cid2 := testCorrelationID2
		aesKey1, err := srv.storage.Register(t.Context(), cid1, pubKey, "s1", nil)
		require.NoError(t, err)
		aesKey2, err := srv.storage.Register(t.Context(), cid2, pubKey, "s2", nil)
		require.NoError(t, err)

		rcpt1 := "a@" + cid1 + testNonce + "." + testDomain
		rcpt2 := "b@" + cid2 + testNonce + "." + testDomain
		srv.onSMTPData("from@example.com", []string{rcpt1, rcpt2}, []byte("shared body"), "1.2.3.4:25")

		i1, err := testGetAndClearInteractions(t, srv.storage, cid1, "s1")
		require.NoError(t, err)
		require.Len(t, i1, 1)

		i2, err := testGetAndClearInteractions(t, srv.storage, cid2, "s2")
		require.NoError(t, err)
		require.Len(t, i2, 1)

		d1 := decryptTestInteraction(t, i1[0], aesKey1)
		d2 := decryptTestInteraction(t, i2[0], aesKey2)
		var int1, int2 InteractionType
		require.NoError(t, json.Unmarshal([]byte(d1), &int1))
		require.NoError(t, json.Unmarshal([]byte(d2), &int2))

		assert.Equal(t, cid1, int1.UniqueID)
		assert.Equal(t, cid2, int2.UniqueID)
		assert.Equal(t, "shared body", int1.RawRequest)
		assert.Equal(t, "shared body", int2.RawRequest)
	})

	t.Run("same_cid_per_recipient", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		const nonce1 = "aaa"
		const nonce2 = "bbb"
		rcpt1 := "x@" + testCorrelationID + nonce1 + "." + testDomain
		rcpt2 := "y@" + testCorrelationID + nonce2 + "." + testDomain
		srv.onSMTPData("from@example.com", []string{rcpt1, rcpt2}, []byte("body"), "1.2.3.4:25")

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 2)

		d1 := decryptTestInteraction(t, interactions[0], aesKey)
		d2 := decryptTestInteraction(t, interactions[1], aesKey)
		var int1, int2 InteractionType
		require.NoError(t, json.Unmarshal([]byte(d1), &int1))
		require.NoError(t, json.Unmarshal([]byte(d2), &int2))

		assert.Equal(t, testCorrelationID, int1.UniqueID)
		assert.Equal(t, testCorrelationID, int2.UniqueID)
		assert.Equal(t, testCorrelationID+nonce1, int1.FullId)
		assert.Equal(t, testCorrelationID+nonce2, int2.FullId)
	})

	t.Run("no_at_in_recipient", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		srv.onSMTPData("from@example.com", []string{"no-domain"}, []byte("body"), "1.2.3.4:25")

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		assert.Empty(t, interactions)
	})

	t.Run("domain_case_insensitive", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		rcpt := "user@" + testCorrelationID + testNonce + ".TEST.COM"
		srv.onSMTPData("sender@example.com", []string{rcpt}, []byte("body"), "1.2.3.4:25")

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)

		decrypted := decryptTestInteraction(t, interactions[0], aesKey)
		var interaction InteractionType
		require.NoError(t, json.Unmarshal([]byte(decrypted), &interaction))

		assert.Equal(t, testCorrelationID, interaction.UniqueID)
		assert.Equal(t, testCorrelationID+testNonce, interaction.FullId)
	})

	t.Run("wildcard_capture", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Wildcard = true
			c.Auth = true
			c.Token = "tok"
		})

		rcpt := "user@anything." + testDomain
		srv.onSMTPData("sender@example.com", []string{rcpt}, []byte("email body"), "10.0.0.1:25")

		data := srv.tldBuckets[testDomain].ReadFrom("consumer1")
		require.Len(t, data, 1)

		var interaction InteractionType
		require.NoError(t, json.Unmarshal(data[0], &interaction))
		assert.Equal(t, "smtp", interaction.Protocol)
		assert.Equal(t, "anything."+testDomain, interaction.UniqueID)
		assert.Equal(t, "anything."+testDomain, interaction.FullId)
		assert.Equal(t, "email body", interaction.RawRequest)
		assert.Equal(t, "sender@example.com", interaction.SMTPFrom)
		assert.Equal(t, "10.0.0.1", interaction.RemoteAddress)
	})

	t.Run("empty_recipients_no_storage", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey

		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		srv.onSMTPData("sender@test.com", []string{}, []byte("body"), "10.0.0.1:1234")

		assert.Equal(t, uint64(1), srv.smtpCount.Load())
		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		assert.Nil(t, interactions)
	})

	t.Run("ipv6_remote_address", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey

		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		srv.onSMTPData("sender@test.com",
			[]string{"user@" + testCorrelationID + "nop." + testDomain},
			[]byte("body"), "[::1]:54321")

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)

		decrypted := decryptTestInteraction(t, interactions[0], aesKey)
		assert.Contains(t, decrypted, `"remote-address":"::1"`)
	})
}

func TestSMTPSession(t *testing.T) {
	t.Parallel()

	t.Run("auth_plain_accepts_all", func(t *testing.T) {
		session := &smtpSession{}
		srv, err := session.Auth("PLAIN")
		require.NoError(t, err)

		challenge, done, err := srv.Next([]byte("\x00user\x00pass"))
		require.NoError(t, err)
		assert.True(t, done)
		assert.Nil(t, challenge)
	})

	t.Run("auth_login_accepts_all", func(t *testing.T) {
		session := &smtpSession{}
		srv, err := session.Auth("LOGIN")
		require.NoError(t, err)

		// No initial response -> Username: challenge
		challenge, done, err := srv.Next(nil)
		require.NoError(t, err)
		assert.False(t, done)
		assert.Equal(t, []byte("Username:"), challenge)

		// Username -> Password: challenge
		challenge, done, err = srv.Next([]byte("user"))
		require.NoError(t, err)
		assert.False(t, done)
		assert.Equal(t, []byte("Password:"), challenge)

		// Password -> done
		challenge, done, err = srv.Next([]byte("pass"))
		require.NoError(t, err)
		assert.True(t, done)
		assert.Nil(t, challenge)
	})

	t.Run("auth_login_initial_response", func(t *testing.T) {
		session := &smtpSession{}
		srv, err := session.Auth("LOGIN")
		require.NoError(t, err)

		// Initial response contains username, skip Username: challenge
		challenge, done, err := srv.Next([]byte("admin"))
		require.NoError(t, err)
		assert.False(t, done)
		assert.Equal(t, []byte("Password:"), challenge)

		_, done, err = srv.Next([]byte("secret"))
		require.NoError(t, err)
		assert.True(t, done)
	})

	t.Run("auth_cram_md5_accepts_all", func(t *testing.T) {
		session := &smtpSession{}
		srv, err := session.Auth("CRAM-MD5")
		require.NoError(t, err)

		// Get challenge
		challenge, done, err := srv.Next(nil)
		require.NoError(t, err)
		assert.False(t, done)
		assert.Contains(t, string(challenge), "@interactsh>")

		// Send response -> accepted
		_, done, err = srv.Next([]byte("user abcdef1234567890"))
		require.NoError(t, err)
		assert.True(t, done)
	})

	t.Run("auth_unsupported", func(t *testing.T) {
		session := &smtpSession{}
		_, err := session.Auth("XOAUTH2")
		assert.Error(t, err)
	})

	t.Run("reset_clears_for_next_message", func(t *testing.T) {
		session := &smtpSession{}

		// First transaction
		err := session.Mail("first@example.com", nil)
		require.NoError(t, err)
		err = session.Rcpt("rcpt1@example.com", nil)
		require.NoError(t, err)
		session.Reset()

		assert.Empty(t, session.from)
		assert.Empty(t, session.recipients)

		// Second transaction
		err = session.Mail("second@example.com", nil)
		require.NoError(t, err)
		err = session.Rcpt("rcpt2@example.com", nil)
		require.NoError(t, err)

		assert.Equal(t, "second@example.com", session.from)
		require.Len(t, session.recipients, 1)
		assert.Equal(t, "rcpt2@example.com", session.recipients[0])
	})
}

func TestSMTPServer(t *testing.T) {
	t.Parallel()

	t.Run("greeting_contains_domain", func(t *testing.T) {
		srv := testServerWithStorage(t)
		addr, cleanup := smtpTestServer(t, srv, nil, false)
		t.Cleanup(cleanup)

		dialer := net.Dialer{Timeout: time.Second}
		conn, err := dialer.DialContext(t.Context(), "tcp", addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		err = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		require.NoError(t, err)
		scanner := bufio.NewScanner(conn)
		require.True(t, scanner.Scan())
		greeting := scanner.Text()
		assert.Contains(t, greeting, "220")
		assert.Contains(t, greeting, testDomain)
	})

	t.Run("ehlo_advertises_auth", func(t *testing.T) {
		srv := testServerWithStorage(t)
		addr, cleanup := smtpTestServer(t, srv, nil, false)
		t.Cleanup(cleanup)

		c, err := netsmtp.Dial(addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })

		ok, params := c.Extension("AUTH")
		assert.True(t, ok)
		assert.Contains(t, params, "PLAIN")
		assert.Contains(t, params, "LOGIN")
		assert.Contains(t, params, "CRAM-MD5")
	})

	t.Run("ehlo_advertises_starttls", func(t *testing.T) {
		srv := testServerWithStorage(t)
		tlsCfg := testTLSConfig(t)
		addr, cleanup := smtpTestServer(t, srv, tlsCfg, false)
		t.Cleanup(cleanup)

		c, err := netsmtp.Dial(addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })

		ok, _ := c.Extension("STARTTLS")
		assert.True(t, ok)
	})

	t.Run("starttls_upgrade_succeeds", func(t *testing.T) {
		srv := testServerWithStorage(t)
		tlsCfg := testTLSConfig(t)
		addr, cleanup := smtpTestServer(t, srv, tlsCfg, false)
		t.Cleanup(cleanup)

		c, err := netsmtp.Dial(addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })

		require.NoError(t, c.StartTLS(&tls.Config{InsecureSkipVerify: true}))

		// Verify SMTP commands work after upgrade
		require.NoError(t, c.Mail("sender@example.com"))
		require.NoError(t, c.Rcpt("rcpt@example.com"))
	})

	t.Run("no_starttls_without_tls", func(t *testing.T) {
		srv := testServerWithStorage(t)
		addr, cleanup := smtpTestServer(t, srv, nil, false)
		t.Cleanup(cleanup)

		c, err := netsmtp.Dial(addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })

		ok, _ := c.Extension("STARTTLS")
		assert.False(t, ok)
	})

	t.Run("implicit_tls_connection", func(t *testing.T) {
		srv := testServerWithStorage(t)
		tlsCfg := testTLSConfig(t)
		addr, cleanup := smtpTestServer(t, srv, tlsCfg, true)
		t.Cleanup(cleanup)

		dialer := tls.Dialer{
			NetDialer: &net.Dialer{Timeout: time.Second},
			Config:    &tls.Config{InsecureSkipVerify: true},
		}
		conn, err := dialer.DialContext(t.Context(), "tcp", addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		c, err := netsmtp.NewClient(conn, testDomain)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })

		require.NoError(t, c.Hello("test.client"))
	})

	t.Run("captures_interaction_via_data", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		addr, cleanup := smtpTestServer(t, srv, nil, false)
		t.Cleanup(cleanup)

		c, err := netsmtp.Dial(addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })

		rcpt := "user@" + testCorrelationID + testNonce + "." + testDomain
		require.NoError(t, c.Mail("sender@example.com"))
		require.NoError(t, c.Rcpt(rcpt))

		w, err := c.Data()
		require.NoError(t, err)
		_, err = w.Write([]byte("Subject: Test\r\n\r\nHello"))
		require.NoError(t, err)
		require.NoError(t, w.Close())

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)

		decrypted := decryptTestInteraction(t, interactions[0], aesKey)
		var interaction InteractionType
		require.NoError(t, json.Unmarshal([]byte(decrypted), &interaction))

		assert.Equal(t, "smtp", interaction.Protocol)
		assert.Equal(t, testCorrelationID, interaction.UniqueID)
		assert.Equal(t, "sender@example.com", interaction.SMTPFrom)
		assert.Contains(t, interaction.RawRequest, "Subject: Test")
		assert.Equal(t, uint64(1), srv.smtpCount.Load())
	})

	t.Run("accepts_all_recipients", func(t *testing.T) {
		srv := testServerWithStorage(t)
		addr, cleanup := smtpTestServer(t, srv, nil, false)
		t.Cleanup(cleanup)

		c, err := netsmtp.Dial(addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })

		require.NoError(t, c.Mail("from@example.com"))
		require.NoError(t, c.Rcpt("anyone@anywhere.com"))
		require.NoError(t, c.Rcpt("another@somewhere.net"))
	})

	t.Run("concurrent_sessions_same_cid", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey

		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		addr, cleanup := smtpTestServer(t, srv, nil, false)
		t.Cleanup(cleanup)

		var wg sync.WaitGroup
		for i := range 5 {
			wg.Add(1)
			go func() {
				defer wg.Done()

				rcpt := fmt.Sprintf("user@%s%03d.%s", testCorrelationID, i, testDomain)
				c, err := netsmtp.Dial(addr)
				if !assert.NoError(t, err) {
					return
				}
				t.Cleanup(func() { _ = c.Close() })

				if !assert.NoError(t, c.Mail("sender@test.com")) {
					return
				}
				if !assert.NoError(t, c.Rcpt(rcpt)) {
					return
				}
				wc, err := c.Data()
				if !assert.NoError(t, err) {
					return
				}
				_, err = fmt.Fprintf(wc, "Subject: test %d\r\n\r\nbody", i)
				if !assert.NoError(t, err) {
					return
				}
				if !assert.NoError(t, wc.Close()) {
					return
				}
				assert.NoError(t, c.Quit())
			}()
		}
		wg.Wait()

		assert.Equal(t, uint64(5), srv.smtpCount.Load())
		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		assert.Len(t, interactions, 5)
	})
}

func TestTeeConn(t *testing.T) {
	t.Parallel()

	t.Run("reads_are_teed", func(t *testing.T) {
		server, client := net.Pipe()
		tc := &teeConn{Conn: server}
		t.Cleanup(func() { _ = tc.Close() })

		go func() {
			_, _ = client.Write([]byte("EHLO test\r\n"))
			_ = client.Close()
		}()

		buf := make([]byte, 64)
		n, err := tc.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "EHLO test\r\n", string(buf[:n]))
		assert.Equal(t, "EHLO test\r\n", tc.buf.String())
	})

	t.Run("cap_is_respected", func(t *testing.T) {
		server, client := net.Pipe()
		tc := &teeConn{Conn: server}
		t.Cleanup(func() { _ = tc.Close() })

		// Write more than teeConnMaxBuf
		data := make([]byte, teeConnMaxBuf+1024)
		for i := range data {
			data[i] = 'A'
		}
		go func() {
			_, _ = client.Write(data)
			_ = client.Close()
		}()

		out := make([]byte, len(data))
		total := 0
		for total < len(data) {
			n, err := tc.Read(out[total:])
			total += n
			if err != nil {
				break
			}
		}
		assert.Equal(t, len(data), total)
		assert.Equal(t, teeConnMaxBuf, tc.buf.Len())
	})

	t.Run("reset_clears_and_allows_reuse", func(t *testing.T) {
		server, client := net.Pipe()
		tc := &teeConn{Conn: server}
		t.Cleanup(func() { _ = tc.Close() })

		go func() {
			_, _ = client.Write([]byte("first"))
			_, _ = client.Write([]byte("second"))
			_ = client.Close()
		}()

		buf := make([]byte, 64)
		_, err := tc.Read(buf)
		require.NoError(t, err)
		tc.Reset()
		n, err := tc.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "second", string(buf[:n]))
		assert.Equal(t, "second", tc.buf.String())
	})

	t.Run("stopped_prevents_capture", func(t *testing.T) {
		server, client := net.Pipe()
		tc := &teeConn{Conn: server}
		t.Cleanup(func() { _ = tc.Close() })

		go func() {
			_, _ = client.Write([]byte("before"))
			_, _ = client.Write([]byte("after"))
			_ = client.Close()
		}()

		buf := make([]byte, 64)
		_, err := tc.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "before", tc.buf.String())

		tc.stopped = true
		n, err := tc.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "after", string(buf[:n]))
		assert.Equal(t, "before", tc.buf.String()) // unchanged
	})

	t.Run("reset_clears_stopped", func(t *testing.T) {
		server, client := net.Pipe()
		tc := &teeConn{Conn: server}
		t.Cleanup(func() { _ = tc.Close() })

		go func() {
			_, _ = client.Write([]byte("one"))
			_, _ = client.Write([]byte("two"))
			_ = client.Close()
		}()

		buf := make([]byte, 64)
		_, err := tc.Read(buf)
		require.NoError(t, err)
		tc.stopped = true
		tc.Reset()

		assert.False(t, tc.stopped)
		assert.Equal(t, 0, tc.buf.Len())

		n, err := tc.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "two", string(buf[:n]))
		assert.Equal(t, "two", tc.buf.String())
	})
}

func TestTeeListener(t *testing.T) {
	t.Parallel()

	t.Run("accept_returns_tee_conn", func(t *testing.T) {
		var lc net.ListenConfig
		inner, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = inner.Close() })

		tl := &teeListener{Listener: inner}

		go func() {
			var dialer net.Dialer
			conn, _ := dialer.DialContext(t.Context(), "tcp", inner.Addr().String())
			if conn != nil {
				_ = conn.Close()
			}
		}()

		conn, err := tl.Accept()
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		_, ok := conn.(*teeConn)
		assert.True(t, ok)
	})
}

func TestExtractRawPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"normal_address", "<sender@example.com>", "sender@example.com"},
		{"with_esmtp_params", "<sender@example.com> BODY=8BITMIME", "sender@example.com"},
		{"quoted_local_with_gt", `<"ABCcollab@psres.net> "@psres.net>`, `"ABCcollab@psres.net> "@psres.net`},
		{"null_sender", "<>", ""},
		{"no_brackets", "sender@example.com", ""},
		{"empty_string", "", ""},
		{"leading_whitespace", " <user@host.com>", "user@host.com"},
		{"quoted_with_escape", `<"user\"name"@host.com>`, `"user\"name"@host.com`},
		{"source_route", "<@relay:user@example.com>", "@relay:user@example.com"},
		{"simple_quoted", `<"user"@example.com>`, `"user"@example.com`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, extractRawPath(tc.input))
		})
	}
}

func TestParseRawEnvelope(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		raw            string
		wantFrom       string
		wantRecipients []string
	}{
		{
			"normal_envelope",
			"EHLO client\r\nMAIL FROM:<sender@example.com>\r\nRCPT TO:<rcpt@example.com>\r\n",
			"sender@example.com",
			[]string{"rcpt@example.com"},
		},
		{
			"multiple_recipients",
			"MAIL FROM:<from@a.com>\r\nRCPT TO:<one@b.com>\r\nRCPT TO:<two@c.com>\r\n",
			"from@a.com",
			[]string{"one@b.com", "two@c.com"},
		},
		{
			"empty_buffer",
			"",
			"",
			nil,
		},
		{
			"no_smtp_commands",
			"EHLO client\r\nAUTH PLAIN dXNlcg==\r\n",
			"",
			nil,
		},
		{
			"case_insensitive",
			"mail from:<sender@test.com>\r\nrcpt to:<rcpt@test.com>\r\n",
			"sender@test.com",
			[]string{"rcpt@test.com"},
		},
		{
			"null_sender",
			"MAIL FROM:<>\r\nRCPT TO:<rcpt@test.com>\r\n",
			"",
			[]string{"rcpt@test.com"},
		},
		{
			"with_esmtp_params",
			"MAIL FROM:<sender@a.com> BODY=8BITMIME\r\nRCPT TO:<rcpt@b.com> NOTIFY=SUCCESS\r\n",
			"sender@a.com",
			[]string{"rcpt@b.com"},
		},
		{
			"quoted_local_part",
			"MAIL FROM:<sender@a.com>\r\nRCPT TO:<\"quoted>addr\"@b.com>\r\n",
			"sender@a.com",
			[]string{`"quoted>addr"@b.com`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			from, recipients := parseRawEnvelope(tc.raw)
			assert.Equal(t, tc.wantFrom, from)
			assert.Equal(t, tc.wantRecipients, recipients)
		})
	}
}

func TestSMTPRawEnvelopePreservation(t *testing.T) {
	t.Parallel()

	t.Run("quoted_local_part_preserved", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		addr, cleanup := smtpTestServer(t, srv, nil, false)
		t.Cleanup(cleanup)

		dialer := net.Dialer{Timeout: time.Second}
		conn, err := dialer.DialContext(t.Context(), "tcp", addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		reader := bufio.NewReader(conn)
		readLine := func() string {
			line, err := reader.ReadString('\n')
			require.NoError(t, err)
			return line
		}
		writeLine := func(s string) {
			_, _ = fmt.Fprintf(conn, "%s\r\n", s)
		}

		// Read greeting
		readLine()

		// EHLO and read multi-line response
		writeLine("EHLO test")
		for {
			line := readLine()
			if len(line) < 4 || line[3] == ' ' {
				break
			}
		}

		rcptDomain := testCorrelationID + testNonce + "." + testDomain

		writeLine(`MAIL FROM:<"quoted sender"@example.com>`)
		readLine()

		writeLine(fmt.Sprintf(`RCPT TO:<"quoted rcpt"@%s>`, rcptDomain))
		readLine()

		writeLine("DATA")
		readLine()

		writeLine("Subject: Test\r\n\r\nBody\r\n.")
		readLine()

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)

		decrypted := decryptTestInteraction(t, interactions[0], aesKey)
		var interaction InteractionType
		require.NoError(t, json.Unmarshal([]byte(decrypted), &interaction))

		assert.Equal(t, "smtp", interaction.Protocol)
		assert.Equal(t, `"quoted sender"@example.com`, interaction.SMTPFrom)
		assert.Equal(t, `"quoted rcpt"@`+rcptDomain, interaction.SMTPTo)
	})

	t.Run("standard_address_unchanged", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		addr, cleanup := smtpTestServer(t, srv, nil, false)
		t.Cleanup(cleanup)

		c, err := netsmtp.Dial(addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })

		rcpt := "user@" + testCorrelationID + testNonce + "." + testDomain
		require.NoError(t, c.Mail("sender@example.com"))
		require.NoError(t, c.Rcpt(rcpt))
		w, err := c.Data()
		require.NoError(t, err)
		_, _ = w.Write([]byte("Subject: Test\r\n\r\nBody"))
		require.NoError(t, w.Close())

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)

		decrypted := decryptTestInteraction(t, interactions[0], aesKey)
		var interaction InteractionType
		require.NoError(t, json.Unmarshal([]byte(decrypted), &interaction))

		// Standard addresses are identical whether raw or parsed
		assert.Equal(t, "sender@example.com", interaction.SMTPFrom)
		assert.Equal(t, rcpt, interaction.SMTPTo)
	})
}

func TestStartSMTPPort(t *testing.T) {
	t.Parallel()

	t.Run("bind_failure_non_fatal", func(t *testing.T) {
		srv := testServerWithStorage(t)
		backend := &smtpBackend{server: srv}

		// Occupy a port
		var lc net.ListenConfig
		ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })
		port := ln.Addr().(*net.TCPAddr).Port

		serviceCount := len(srv.services)
		srv.startSMTPPort(backend, testDomain, port, "test-conflict", nil, false)

		assert.Len(t, srv.services, serviceCount)
	})
}

func TestStartSMTP(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		withTLS   bool
		wantSMTPS bool
	}{
		{"skips_465_without_tls", false, false},
		{"starts_465_with_tls", true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := testServerWithStorage(t)
			srv.cfg.ListenIP = testListenIP
			srv.cfg.SMTPPort = 0
			srv.cfg.SMTPSPort = 0
			srv.cfg.SMTPAutoTLSPort = 0
			if tc.withTLS {
				srv.tlsConfig = testTLSConfig(t)
			}

			srv.startSMTP()
			t.Cleanup(srv.Shutdown)

			names := make([]string, 0, len(srv.services))
			for _, svc := range srv.services {
				names = append(names, svc.Name())
			}
			assert.Contains(t, names, "SMTP")
			assert.Contains(t, names, "SMTP-STARTTLS")
			if tc.wantSMTPS {
				assert.Contains(t, names, "SMTPS")
			} else {
				assert.NotContains(t, names, "SMTPS")
			}
		})
	}
}
