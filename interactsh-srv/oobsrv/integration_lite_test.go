package oobsrv

import (
	"net"
	"net/http"
	"net/http/httptest"
	netsmtp "net/smtp"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/interactsh-lite/oobclient"
)

// integrationServer creates a Server with in-memory storage and wraps its
// handler in httptest.Server for client registration and polling.
func integrationServer(t *testing.T, opts ...func(*Config)) (*Server, *httptest.Server) {
	t.Helper()

	srv := testServerWithStorage(t, opts...)
	srv.ips = ServerIPs{
		IPv4: []net.IP{net.ParseIP("1.2.3.4").To4()},
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

// integrationClient registers an oobclient.Client against the test server.
// Automatically closed on test cleanup.
func integrationClient(t *testing.T, serverURL, token string) *oobclient.Client {
	t.Helper()

	opts := oobclient.Options{
		ServerURLs:               []string{serverURL},
		DisableKeepAlive:         true,
		CorrelationIdNonceLength: 4,
	}
	if token != "" {
		opts.Token = token
	}
	client, err := oobclient.New(t.Context(), opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// integrationDNS starts a UDP DNS server on an ephemeral port using the
// server's handleDNS handler. Returns the listener address.
func integrationDNS(t *testing.T, srv *Server) string {
	t.Helper()

	var lc net.ListenConfig
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	require.NoError(t, err)
	addr := pc.LocalAddr().String()

	dnsServer := &dns.Server{
		PacketConn: pc,
		Net:        "udp",
		Handler:    dns.HandlerFunc(srv.handleDNS),
	}

	ready := make(chan struct{})
	dnsServer.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = dnsServer.ActivateAndServe() }()

	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("dns server did not start")
	}

	t.Cleanup(func() { _ = dnsServer.Shutdown() })
	return addr
}

// payloadDomain constructs a domain matching the server's configured domain
// using the given correlation ID and nonce.
func payloadDomain(cid, nonce string) string {
	return cid + nonce + "." + testDomain
}

// collectInteractions starts polling, waits for at least minCount interactions,
// stops polling, and returns the collected interactions.
func collectInteractions(t *testing.T, client *oobclient.Client, minCount int, timeout time.Duration) []*oobclient.Interaction {
	t.Helper()

	var mu sync.Mutex
	var result []*oobclient.Interaction

	err := client.StartPolling(10*time.Millisecond, func(i *oobclient.Interaction) {
		mu.Lock()
		result = append(result, i)
		mu.Unlock()
	})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(result) >= minCount
	}, timeout, 20*time.Millisecond)

	require.NoError(t, client.StopPolling())

	mu.Lock()
	defer mu.Unlock()
	out := slices.Clone(result)
	return out
}

// Protocol integration tests

func TestLiteIntegration_dns_interaction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t)
	dnsAddr := integrationDNS(t, srv)
	client := integrationClient(t, ts.URL, "")

	const nonce = "abcd"
	qname := payloadDomain(client.CorrelationID(), nonce)
	queryDNS(t, dnsAddr, qname, dns.TypeA)

	interactions := collectInteractions(t, client, 1, 5*time.Second)
	require.Len(t, interactions, 1)

	i := interactions[0]
	assert.Equal(t, "dns", i.Protocol)
	assert.Equal(t, "A", i.QType)
	assert.Equal(t, client.CorrelationID(), i.UniqueID)
	assert.Equal(t, client.CorrelationID()+nonce, i.FullId)
	assert.NotEmpty(t, i.RawRequest)
	assert.NotEmpty(t, i.RawResponse)
	assert.False(t, i.Timestamp.IsZero())
}

func TestLiteIntegration_http_interaction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	_, ts := integrationServer(t)
	client := integrationClient(t, ts.URL, "")

	const nonce = "efgh"
	payloadHost := payloadDomain(client.CorrelationID(), nonce)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/test-path", nil)
	require.NoError(t, err)
	req.Host = payloadHost
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	interactions := collectInteractions(t, client, 1, 5*time.Second)
	require.Len(t, interactions, 1)

	i := interactions[0]
	assert.Equal(t, "http", i.Protocol)
	assert.Equal(t, client.CorrelationID(), i.UniqueID)
	assert.Equal(t, client.CorrelationID()+nonce, i.FullId)
	assert.Contains(t, i.RawRequest, "GET /test-path")
	assert.Contains(t, i.RawResponse, "200")
	assert.NotEmpty(t, i.RemoteAddress)
	assert.False(t, i.Timestamp.IsZero())
}

func TestLiteIntegration_smtp_interaction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t)
	smtpAddr, cleanup := smtpTestServer(t, srv, nil, false)
	t.Cleanup(cleanup)
	client := integrationClient(t, ts.URL, "")

	const nonce = "ijkl"
	rcpt := "user@" + payloadDomain(client.CorrelationID(), nonce)

	c, err := netsmtp.Dial(smtpAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	require.NoError(t, c.Mail("sender@example.com"))
	require.NoError(t, c.Rcpt(rcpt))
	w, err := c.Data()
	require.NoError(t, err)
	_, err = w.Write([]byte("Subject: Integration\r\n\r\nTest body"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	interactions := collectInteractions(t, client, 1, 5*time.Second)
	require.Len(t, interactions, 1)

	i := interactions[0]
	assert.Equal(t, "smtp", i.Protocol)
	assert.Equal(t, client.CorrelationID(), i.UniqueID)
	assert.Equal(t, client.CorrelationID()+nonce, i.FullId)
	assert.Equal(t, "sender@example.com", i.SMTPFrom)
	assert.Contains(t, i.RawRequest, "Subject: Integration")
	assert.NotEmpty(t, i.RemoteAddress)
}

func TestLiteIntegration_ldap_interaction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	// not parallel, LDAP concurrency constraint

	srv, ts := integrationServer(t)
	ldapAddr := ldapTestServer(t, srv)
	client := integrationClient(t, ts.URL, "")

	const nonce = "mnop"
	baseDN := "dc=" + client.CorrelationID() + nonce + ",dc=test,dc=com"

	conn, err := ldap.DialURL("ldap://" + ldapAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	require.NoError(t, conn.Bind("cn=admin", "password"))
	_, err = conn.Search(&ldap.SearchRequest{
		BaseDN: baseDN,
		Filter: "(objectClass=*)",
	})
	require.NoError(t, err)

	interactions := collectInteractions(t, client, 1, 5*time.Second)
	require.Len(t, interactions, 1)

	i := interactions[0]
	assert.Equal(t, "ldap", i.Protocol)
	assert.Equal(t, client.CorrelationID(), i.UniqueID)
	assert.Equal(t, client.CorrelationID()+nonce, i.FullId)
	assert.Contains(t, i.RawRequest, "Type=Search")
	assert.Contains(t, i.RawRequest, "BaseDn="+baseDN)
}

func TestLiteIntegration_ftp_interaction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t, func(c *Config) {
		c.Auth = true
		c.Token = testToken
		c.FTP = true
	})
	client := integrationClient(t, ts.URL, testToken)
	ftpAddr := ftpTestServer(t, srv, nil, false)

	tp := ftpDial(t, ftpAddr)
	ftpLogin(t, tp, "alice", "secret")
	require.NoError(t, tp.Close())

	// FTP interactions go to extra bucket (plaintext)
	interactions := collectInteractions(t, client, 1, 5*time.Second)

	var found bool
	for _, i := range interactions {
		if i.Protocol == "ftp" {
			found = true
			assert.NotEmpty(t, i.RawRequest)
			assert.NotEmpty(t, i.RemoteAddress)
			break
		}
	}
	assert.True(t, found)
}

// Lifecycle tests

func TestLiteIntegration_deregister(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t)

	client, err := oobclient.New(t.Context(), oobclient.Options{
		ServerURLs:               []string{ts.URL},
		DisableKeepAlive:         true,
		CorrelationIdNonceLength: 4,
	})
	require.NoError(t, err)

	cid := client.CorrelationID()
	assert.True(t, srv.storage.HasCorrelationID(cid))

	require.NoError(t, client.Close())

	assert.False(t, srv.storage.HasCorrelationID(cid))
}

func TestLiteIntegration_session_eviction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t, func(c *Config) {
		c.Eviction = 1 // 1 day TTL
	})

	client, err := oobclient.New(t.Context(), oobclient.Options{
		ServerURLs:               []string{ts.URL},
		DisableKeepAlive:         true,
		CorrelationIdNonceLength: 4,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	cid := client.CorrelationID()
	require.True(t, srv.storage.HasCorrelationID(cid))

	// Advance the storage clock past the TTL to trigger lazy eviction
	srv.storage.(*memoryStorage).clock = func() time.Time { return time.Now().Add(48 * time.Hour) }

	// HasCorrelationID performs lazy eviction
	assert.False(t, srv.storage.HasCorrelationID(cid))
}

func TestLiteIntegration_client_isolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t)
	dnsAddr := integrationDNS(t, srv)

	client1 := integrationClient(t, ts.URL, "")
	client2 := integrationClient(t, ts.URL, "")

	const nonce1 = "aaaa"
	const nonce2 = "bbbb"
	queryDNS(t, dnsAddr, payloadDomain(client1.CorrelationID(), nonce1), dns.TypeA)
	queryDNS(t, dnsAddr, payloadDomain(client2.CorrelationID(), nonce2), dns.TypeA)

	i1 := collectInteractions(t, client1, 1, 5*time.Second)
	i2 := collectInteractions(t, client2, 1, 5*time.Second)

	require.Len(t, i1, 1)
	require.Len(t, i2, 1)
	assert.Equal(t, client1.CorrelationID(), i1[0].UniqueID)
	assert.Equal(t, client2.CorrelationID(), i2[0].UniqueID)
	assert.NotEqual(t, i1[0].UniqueID, i2[0].UniqueID)
}

// Wildcard and shared bucket tests

func TestLiteIntegration_wildcard_tlddata(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	_, ts := integrationServer(t, func(c *Config) {
		c.Wildcard = true
		c.Auth = true
		c.Token = "tok"
	})
	client := integrationClient(t, ts.URL, "tok")

	// bare subdomain with no CID triggers wildcard but not correlation match
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/wildcard-test", nil)
	require.NoError(t, err)
	req.Host = "anything." + testDomain
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	// client receives wildcard interaction via tlddata
	interactions := collectInteractions(t, client, 1, 5*time.Second)

	var found bool
	for _, i := range interactions {
		if i.Protocol == "http" {
			found = true
			assert.Contains(t, i.RawRequest, "GET /wildcard-test")
			break
		}
	}
	assert.True(t, found)
}

func TestLiteIntegration_ftp_extra_shared(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t, func(c *Config) {
		c.Auth = true
		c.Token = testToken
		c.FTP = true
	})

	client1 := integrationClient(t, ts.URL, testToken)
	client2 := integrationClient(t, ts.URL, testToken)

	ftpAddr := ftpTestServer(t, srv, nil, false)

	tp := ftpDial(t, ftpAddr)
	ftpLogin(t, tp, "shared", "user")
	require.NoError(t, tp.Close())

	// both clients should receive the FTP interaction (shared extra bucket)
	i1 := collectInteractions(t, client1, 1, 5*time.Second)
	i2 := collectInteractions(t, client2, 1, 5*time.Second)

	hasFTP := func(interactions []*oobclient.Interaction) bool {
		for _, i := range interactions {
			if i.Protocol == "ftp" {
				return true
			}
		}
		return false
	}

	assert.True(t, hasFTP(i1))
	assert.True(t, hasFTP(i2))
}
