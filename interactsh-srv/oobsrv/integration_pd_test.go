package oobsrv

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	netsmtp "net/smtp"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/miekg/dns"
	pdclient "github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/options"
	pdserver "github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// pdIntegrationClient creates a ProjectDiscovery interactsh client registered
// against the test server. Automatically stopped and closed on test cleanup.
func pdIntegrationClient(t *testing.T, serverURL, token string) *pdclient.Client {
	t.Helper()

	opts := &pdclient.Options{
		ServerURL:           serverURL,
		Token:               token,
		DisableHTTPFallback: true,
	}
	client, err := pdclient.New(opts)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = client.StopPolling()
		_ = client.Close()
	})
	return client
}

// pdCorrelationID extracts the unexported correlation ID from a PD client
// by parsing the URL() output: "{20-char CID}{nonce}.{host}".
func pdCorrelationID(t *testing.T, client *pdclient.Client) string {
	t.Helper()

	url := client.URL()
	require.NotEmpty(t, url)
	dot := strings.IndexByte(url, '.')
	require.Greater(t, dot, 20)
	return url[:20]
}

// collectPDInteractions starts polling, waits for at least minCount interactions,
// stops polling, and returns the collected interactions.
func collectPDInteractions(t *testing.T, client *pdclient.Client, minCount int, timeout time.Duration) []*pdserver.Interaction {
	t.Helper()

	var mu sync.Mutex
	var result []*pdserver.Interaction

	err := client.StartPolling(10*time.Millisecond, func(i *pdserver.Interaction) {
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

func TestPDIntegration_registration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t)
	client := pdIntegrationClient(t, ts.URL, "")

	cid := pdCorrelationID(t, client)
	assert.Len(t, cid, 20)
	assert.True(t, isCIDBase32(cid))
	assert.True(t, srv.storage.HasCorrelationID(cid))
}

func TestPDIntegration_dns_interaction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t)
	dnsAddr := integrationDNS(t, srv)
	client := pdIntegrationClient(t, ts.URL, "")

	cid := pdCorrelationID(t, client)
	const nonce = "abcd"
	qname := payloadDomain(cid, nonce)
	queryDNS(t, dnsAddr, qname, dns.TypeA)

	interactions := collectPDInteractions(t, client, 1, 5*time.Second)
	require.Len(t, interactions, 1)

	i := interactions[0]
	assert.Equal(t, "dns", i.Protocol)
	assert.Equal(t, "A", i.QType)
	assert.Equal(t, cid, i.UniqueID)
	assert.Equal(t, cid+nonce, i.FullId)
	assert.NotEmpty(t, i.RawRequest)
	assert.NotEmpty(t, i.RawResponse)
	assert.False(t, i.Timestamp.IsZero())
}

func TestPDIntegration_http_interaction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	_, ts := integrationServer(t)
	client := pdIntegrationClient(t, ts.URL, "")

	cid := pdCorrelationID(t, client)
	const nonce = "efgh"
	payloadHost := payloadDomain(cid, nonce)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/test-path", nil)
	require.NoError(t, err)
	req.Host = payloadHost
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	interactions := collectPDInteractions(t, client, 1, 5*time.Second)
	require.Len(t, interactions, 1)

	i := interactions[0]
	assert.Equal(t, "http", i.Protocol)
	assert.Equal(t, cid, i.UniqueID)
	assert.Equal(t, cid+nonce, i.FullId)
	assert.Contains(t, i.RawRequest, "GET /test-path")
	assert.Contains(t, i.RawResponse, "200")
	assert.NotEmpty(t, i.RemoteAddress)
	assert.False(t, i.Timestamp.IsZero())
}

func TestPDIntegration_smtp_interaction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t)
	smtpAddr, cleanup := smtpTestServer(t, srv, nil, false)
	t.Cleanup(cleanup)
	client := pdIntegrationClient(t, ts.URL, "")

	cid := pdCorrelationID(t, client)
	const nonce = "ijkl"
	rcpt := "user@" + payloadDomain(cid, nonce)

	c, err := netsmtp.Dial(smtpAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	require.NoError(t, c.Mail("sender@example.com"))
	require.NoError(t, c.Rcpt(rcpt))
	w, err := c.Data()
	require.NoError(t, err)
	_, err = w.Write([]byte("Subject: PDIntegration\r\n\r\nTest body"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	interactions := collectPDInteractions(t, client, 1, 5*time.Second)
	require.Len(t, interactions, 1)

	i := interactions[0]
	assert.Equal(t, "smtp", i.Protocol)
	assert.Equal(t, cid, i.UniqueID)
	assert.Equal(t, cid+nonce, i.FullId)
	assert.Equal(t, "sender@example.com", i.SMTPFrom)
	assert.Contains(t, i.RawRequest, "Subject: PDIntegration")
	assert.NotEmpty(t, i.RemoteAddress)
}

func TestPDIntegration_ldap_interaction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	// not parallel, LDAP concurrency constraint

	srv, ts := integrationServer(t)
	ldapAddr := ldapTestServer(t, srv)
	client := pdIntegrationClient(t, ts.URL, "")

	cid := pdCorrelationID(t, client)
	const nonce = "mnop"
	baseDN := "dc=" + cid + nonce + ",dc=test,dc=com"

	conn, err := ldap.DialURL("ldap://" + ldapAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	require.NoError(t, conn.Bind("cn=admin", "password"))
	_, err = conn.Search(&ldap.SearchRequest{
		BaseDN: baseDN,
		Filter: "(objectClass=*)",
	})
	require.NoError(t, err)

	interactions := collectPDInteractions(t, client, 1, 5*time.Second)
	require.Len(t, interactions, 1)

	i := interactions[0]
	assert.Equal(t, "ldap", i.Protocol)
	assert.Equal(t, cid, i.UniqueID)
	assert.Equal(t, cid+nonce, i.FullId)
	assert.Contains(t, i.RawRequest, "Type=Search")
	assert.Contains(t, i.RawRequest, "BaseDn="+baseDN)
}

func TestPDIntegration_ftp_interaction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t, func(c *Config) {
		c.Auth = true
		c.Token = testToken
		c.FTP = true
	})
	client := pdIntegrationClient(t, ts.URL, testToken)
	ftpAddr := ftpTestServer(t, srv, nil, false)

	tp := ftpDial(t, ftpAddr)
	ftpLogin(t, tp, "alice", "secret")
	require.NoError(t, tp.Close())

	interactions := collectPDInteractions(t, client, 1, 5*time.Second)

	var found bool
	for _, i := range interactions {
		if i.Protocol == "ftp" {
			found = true
			assert.NotEmpty(t, i.RawRequest)
			assert.NotEmpty(t, i.RemoteAddress)
			break
		}
	}
	assert.True(t, found, "expected FTP interaction")
}

// Lifecycle and edge case tests

func TestPDIntegration_deregister(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t)

	client, err := pdclient.New(&pdclient.Options{
		ServerURL:           ts.URL,
		DisableHTTPFallback: true,
	})
	require.NoError(t, err)

	cid := pdCorrelationID(t, client)
	assert.True(t, srv.storage.HasCorrelationID(cid))

	require.NoError(t, client.Close())

	assert.False(t, srv.storage.HasCorrelationID(cid))
}

func TestPDIntegration_keepalive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t)
	dnsAddr := integrationDNS(t, srv)

	client, err := pdclient.New(&pdclient.Options{
		ServerURL:           ts.URL,
		DisableHTTPFallback: true,
		KeepAliveInterval:   200 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = client.StopPolling()
		_ = client.Close()
	})

	cid := pdCorrelationID(t, client)

	time.Sleep(500 * time.Millisecond) // let keep-alive fire at least twice

	assert.True(t, srv.storage.HasCorrelationID(cid))

	// session still functional after keep-alive
	const nonce = "aaaa"
	queryDNS(t, dnsAddr, payloadDomain(cid, nonce), dns.TypeA)

	interactions := collectPDInteractions(t, client, 1, 5*time.Second)
	require.NotEmpty(t, interactions)
	assert.Equal(t, "dns", interactions[0].Protocol)
}

func TestPDIntegration_correlation_id_format(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	_, ts := integrationServer(t)
	client := pdIntegrationClient(t, ts.URL, "")

	cid := pdCorrelationID(t, client)
	assert.Len(t, cid, 20)
	assert.True(t, isCIDBase32(cid), "xid CID should be base32: %q", cid)
}

func TestPDIntegration_poll_multi_protocol(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t)
	dnsAddr := integrationDNS(t, srv)
	client := pdIntegrationClient(t, ts.URL, "")

	cid := pdCorrelationID(t, client)

	// trigger DNS interaction
	queryDNS(t, dnsAddr, payloadDomain(cid, "dnsa"), dns.TypeA)

	// trigger HTTP interaction
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/multi", nil)
	require.NoError(t, err)
	req.Host = payloadDomain(cid, "http")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	interactions := collectPDInteractions(t, client, 2, 5*time.Second)
	require.GreaterOrEqual(t, len(interactions), 2)

	protocols := map[string]bool{}
	for _, i := range interactions {
		protocols[i.Protocol] = true
		assert.Equal(t, cid, i.UniqueID)
	}
	assert.True(t, protocols["dns"])
	assert.True(t, protocols["http"])
}

// Session and multi-client tests

func TestPDIntegration_session_persistence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t)
	dnsAddr := integrationDNS(t, srv)

	// create first client and save session
	client1, err := pdclient.New(&pdclient.Options{
		ServerURL:           ts.URL,
		DisableHTTPFallback: true,
	})
	require.NoError(t, err)

	cid := pdCorrelationID(t, client1)
	sessionFile := t.TempDir() + "/session.yaml"
	require.NoError(t, client1.SaveSessionTo(sessionFile))
	require.NoError(t, client1.Close())

	// parse saved session
	data, err := os.ReadFile(sessionFile)
	require.NoError(t, err)
	var session options.SessionInfo
	require.NoError(t, yaml.Unmarshal(data, &session))

	assert.Equal(t, cid, session.CorrelationID)
	assert.NotEmpty(t, session.SecretKey)
	assert.NotEmpty(t, session.PrivateKey)
	assert.NotEmpty(t, session.PublicKey)
	assert.Contains(t, session.ServerURL, ts.URL)

	// resume session with second client
	client2, err := pdclient.New(&pdclient.Options{
		ServerURL:           ts.URL,
		DisableHTTPFallback: true,
		SessionInfo:         &session,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = client2.StopPolling()
		_ = client2.Close()
	})

	// resumed client can receive interactions
	const nonce = "resu"
	queryDNS(t, dnsAddr, payloadDomain(cid, nonce), dns.TypeA)

	interactions := collectPDInteractions(t, client2, 1, 5*time.Second)
	require.NotEmpty(t, interactions)
	assert.Equal(t, "dns", interactions[0].Protocol)
	assert.Equal(t, cid, interactions[0].UniqueID)
}

func TestPDIntegration_wildcard_tlddata(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	_, ts := integrationServer(t, func(c *Config) {
		c.Wildcard = true
		c.Auth = true
		c.Token = "tok"
	})
	client := pdIntegrationClient(t, ts.URL, "tok")

	// bare subdomain with no CID triggers wildcard
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/wildcard-pd", nil)
	require.NoError(t, err)
	req.Host = "anything." + testDomain
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	interactions := collectPDInteractions(t, client, 1, 5*time.Second)

	var found bool
	for _, i := range interactions {
		if i.Protocol == "http" {
			found = true
			assert.Contains(t, i.RawRequest, "GET /wildcard-pd")
			break
		}
	}
	assert.True(t, found)
}

func TestPDIntegration_client_isolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t)
	dnsAddr := integrationDNS(t, srv)

	client1 := pdIntegrationClient(t, ts.URL, "")
	client2 := pdIntegrationClient(t, ts.URL, "")

	cid1 := pdCorrelationID(t, client1)
	cid2 := pdCorrelationID(t, client2)
	require.NotEqual(t, cid1, cid2)

	queryDNS(t, dnsAddr, payloadDomain(cid1, "aaaa"), dns.TypeA)
	queryDNS(t, dnsAddr, payloadDomain(cid2, "bbbb"), dns.TypeA)

	i1 := collectPDInteractions(t, client1, 1, 5*time.Second)
	i2 := collectPDInteractions(t, client2, 1, 5*time.Second)

	require.Len(t, i1, 1)
	require.Len(t, i2, 1)
	assert.Equal(t, cid1, i1[0].UniqueID)
	assert.Equal(t, cid2, i2[0].UniqueID)
}

// Wire format compatibility tests

func TestPDWireFormat_register_request(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t)

	// construct registration using PD's exported types
	client := pdIntegrationClient(t, ts.URL, "")
	cid := pdCorrelationID(t, client)

	// verify the session is stored correctly
	assert.True(t, srv.storage.HasCorrelationID(cid))
	assert.Equal(t, uint64(1), srv.storage.SessionCount())

	// register a second client using PD's RegisterRequest format manually
	key := &sharedRSAKey.PublicKey
	pubKeyStr := encodeTestPublicKey(t, key)
	regReq := pdserver.RegisterRequest{
		PublicKey:     pubKeyStr,
		SecretKey:     "manual-secret-key",
		CorrelationID: "manualtestcid12345ab",
	}
	body, err := json.Marshal(regReq)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL+"/register", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Equal(t, "registration successful", result["message"])

	assert.True(t, srv.storage.HasCorrelationID("manualtestcid12345ab"))
	assert.Equal(t, uint64(2), srv.storage.SessionCount())
}

func TestPDWireFormat_interaction_json_tags(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	// verify that PD's server.Interaction and our InteractionType
	// have identical JSON field names for all shared fields
	pdType := reflect.TypeOf(pdserver.Interaction{})
	ourType := reflect.TypeOf(InteractionType{})

	pdFields := map[string]string{}
	for i := range pdType.NumField() {
		f := pdType.Field(i)
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		pdFields[f.Name] = name
	}

	// fields we add as extensions beyond the PD wire format
	extensionFields := map[string]bool{
		"SMTPTo": true,
	}

	for i := range ourType.NumField() {
		f := ourType.Field(i)
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		if extensionFields[f.Name] {
			continue
		}
		name := strings.Split(tag, ",")[0]

		pdTag, exists := pdFields[f.Name]
		if assert.True(t, exists, "field %s missing from PD Interaction", f.Name) {
			assert.Equal(t, pdTag, name, "JSON tag mismatch for field %s", f.Name)
		}
	}
}

func TestPDWireFormat_poll_response(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	srv, ts := integrationServer(t)
	dnsAddr := integrationDNS(t, srv)
	client := pdIntegrationClient(t, ts.URL, "")

	cid := pdCorrelationID(t, client)

	// trigger an interaction so poll has data
	queryDNS(t, dnsAddr, payloadDomain(cid, "poll"), dns.TypeA)

	// give server time to store the interaction
	time.Sleep(50 * time.Millisecond)

	// the real validation is that collectPDInteractions works - the PD client
	// successfully decrypts our AES-CTR encrypted data using RSA-OAEP key exchange
	interactions := collectPDInteractions(t, client, 1, 5*time.Second)
	require.Len(t, interactions, 1)
	assert.Equal(t, "dns", interactions[0].Protocol)
	assert.Equal(t, cid, interactions[0].UniqueID)

	// verify PD's PollResponse struct matches our pollResponse wire format
	pdPoll := reflect.TypeOf(pdserver.PollResponse{})
	pdTags := map[string]string{}
	for i := range pdPoll.NumField() {
		f := pdPoll.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		pdTags[tag] = f.Name
	}

	// our poll response must include these exact JSON keys
	for _, key := range []string{"data", "aes_key", "extra"} {
		assert.Contains(t, pdTags, key, "PD PollResponse expects %q field", key)
	}
}

// Remote server integration tests (oscar.oastsrv.net)
//
// These tests validate the PD client against the live oastsrv.net server.
// They use PD client defaults (CID length 20, nonce length 13).
//
// All encryption is validated implicitly: if polling returns readable
// interactions, RSA-OAEP key exchange and AES-256-CTR decryption both work.
//
// TestPDRemote uses a single shared client+session with continuous polling.
// Subtests trigger interactions with unique nonces and wait for them by
// matching FullId. This avoids CID collisions from parallel registrations.

const (
	remoteServerURL    = "oscar.oastsrv.net"
	remoteDNSAddr      = "oscar.oastsrv.net:53"
	remoteDomain       = "oscar.oastsrv.net"
	remoteCIDLength    = 16 // server's configured correlation-id-length
	remotePollInterval = 1 * time.Second
	remotePollTimeout  = 30 * time.Second
)

// skipIfServerUnreachable skips the test if the remote server cannot be reached.
func skipIfServerUnreachable(t *testing.T) {
	t.Helper()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+remoteServerURL, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	if err != nil {
		t.Skipf("remote server unreachable: %v", err)
	}
	require.NoError(t, resp.Body.Close())
}

// remotePayloadDomain builds {cid}{nonce}.oscar.oastsrv.net.
func remotePayloadDomain(cid, nonce string) string {
	return cid + nonce + "." + remoteDomain
}

// queryRemoteDNS sends a DNS query directly to oscar.oastsrv.net:53.
func queryRemoteDNS(t *testing.T, name string, qtype uint16) *dns.Msg {
	t.Helper()

	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = 10 * time.Second
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)

	r, _, err := c.Exchange(m, remoteDNSAddr)
	require.NoError(t, err)
	return r
}

// remoteTestHTTPClient returns an HTTP client for making requests to the remote server.
func remoteTestHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// remoteSession holds shared state for a single-client remote test suite.
type remoteSession struct {
	client *pdclient.Client
	cid    string // 20-char CID generated by PD client

	mu           sync.Mutex
	interactions []*pdserver.Interaction
}

// newRemoteSession registers a PD client and starts continuous polling.
func newRemoteSession(t *testing.T) *remoteSession {
	t.Helper()

	client, err := pdclient.New(&pdclient.Options{
		ServerURL:           remoteServerURL,
		DisableHTTPFallback: true,
	})
	require.NoError(t, err)

	u := client.URL()
	require.NotEmpty(t, u)
	dot := strings.IndexByte(u, '.')
	require.Greater(t, dot, 20, "URL %q too short for CID extraction", u)
	cid := u[:20]

	rs := &remoteSession{client: client, cid: cid}

	err = client.StartPolling(remotePollInterval, func(i *pdserver.Interaction) {
		rs.mu.Lock()
		rs.interactions = append(rs.interactions, i)
		rs.mu.Unlock()
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = client.StopPolling()
		_ = client.Close()
	})
	return rs
}

// waitFor blocks until an interaction matching the predicate appears, then returns it.
func (rs *remoteSession) waitFor(t *testing.T, match func(*pdserver.Interaction) bool) *pdserver.Interaction {
	t.Helper()

	var found *pdserver.Interaction
	require.Eventually(t, func() bool {
		rs.mu.Lock()
		defer rs.mu.Unlock()
		for _, i := range rs.interactions {
			if match(i) {
				found = i
				return true
			}
		}
		return false
	}, remotePollTimeout, 500*time.Millisecond)
	return found
}

// TestPDRemote exercises DNS, HTTP, SMTP, and lifecycle functionality against
// the live server. All clients are created sequentially upfront to avoid CID
// collisions from xid counter truncation, then subtests run in parallel.
func TestPDRemote(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping remote integration test in short mode")
	}
	skipIfServerUnreachable(t)

	rs := newRemoteSession(t)
	cid := rs.cid
	httpClient := remoteTestHTTPClient()

	// DNS subtests

	t.Run("dns_a_record", func(t *testing.T) {
		t.Parallel()

		const nonce = "typea"
		qname := remotePayloadDomain(cid, nonce)

		r := queryRemoteDNS(t, qname, dns.TypeA)
		require.NotEmpty(t, r.Answer)
		a, ok := r.Answer[0].(*dns.A)
		require.True(t, ok, "expected A record type, got %T", r.Answer[0])
		assert.NotNil(t, a.A)

		i := rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+nonce
		})
		assert.Equal(t, "dns", i.Protocol)
		assert.Equal(t, "A", i.QType)
		assert.Equal(t, cid[:remoteCIDLength], i.UniqueID)
		assert.Equal(t, cid+nonce, i.FullId)
		assert.NotEmpty(t, i.RawRequest)
		assert.NotEmpty(t, i.RawResponse)
		assert.NotEmpty(t, i.RemoteAddress)
		assert.False(t, i.Timestamp.IsZero())
		assert.WithinDuration(t, time.Now(), i.Timestamp, 5*time.Minute)
	})

	t.Run("dns_aaaa", func(t *testing.T) {
		t.Parallel()

		const nonce = "aaaa0"
		qname := remotePayloadDomain(cid, nonce)

		queryRemoteDNS(t, qname, dns.TypeAAAA)
		// AAAA response may be empty if server has no IPv6

		i := rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+nonce
		})
		assert.Equal(t, "dns", i.Protocol)
		assert.Equal(t, "AAAA", i.QType)
	})

	t.Run("dns_mx", func(t *testing.T) {
		t.Parallel()

		const nonce = "mxmx0"
		qname := remotePayloadDomain(cid, nonce)

		r := queryRemoteDNS(t, qname, dns.TypeMX)
		require.NotEmpty(t, r.Answer)
		mx, ok := r.Answer[0].(*dns.MX)
		require.True(t, ok)
		assert.Contains(t, mx.Mx, "mail.")

		i := rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+nonce
		})
		assert.Equal(t, "dns", i.Protocol)
		assert.Equal(t, "MX", i.QType)
	})

	t.Run("dns_ns", func(t *testing.T) {
		t.Parallel()

		const nonce = "nsns0"
		qname := remotePayloadDomain(cid, nonce)

		r := queryRemoteDNS(t, qname, dns.TypeNS)
		require.NotEmpty(t, r.Answer)
		ns, ok := r.Answer[0].(*dns.NS)
		require.True(t, ok)
		assert.Contains(t, ns.Ns, "ns1.")

		i := rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+nonce
		})
		assert.Equal(t, "dns", i.Protocol)
		assert.Equal(t, "NS", i.QType)
	})

	t.Run("dns_soa", func(t *testing.T) {
		t.Parallel()

		const nonce = "soaz0"
		qname := remotePayloadDomain(cid, nonce)

		r := queryRemoteDNS(t, qname, dns.TypeSOA)
		require.NotEmpty(t, r.Answer)
		_, ok := r.Answer[0].(*dns.SOA)
		require.True(t, ok)

		i := rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+nonce
		})
		assert.Equal(t, "dns", i.Protocol)
		assert.Equal(t, "SOA", i.QType)
	})

	t.Run("dns_txt", func(t *testing.T) {
		t.Parallel()

		const nonce = "txtz0"
		qname := remotePayloadDomain(cid, nonce)

		r := queryRemoteDNS(t, qname, dns.TypeTXT)
		require.NotEmpty(t, r.Answer)
		_, ok := r.Answer[0].(*dns.TXT)
		require.True(t, ok)

		i := rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+nonce
		})
		assert.Equal(t, "dns", i.Protocol)
		assert.Equal(t, "TXT", i.QType)
	})

	t.Run("dns_any", func(t *testing.T) {
		t.Parallel()

		const nonce = "anyq0"
		qname := remotePayloadDomain(cid, nonce)

		r := queryRemoteDNS(t, qname, dns.TypeANY)
		assert.NotEmpty(t, r.Answer)

		i := rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+nonce
		})
		assert.Equal(t, "dns", i.Protocol)
		assert.Equal(t, "ANY", i.QType)
	})

	// HTTP subtests

	t.Run("http_get", func(t *testing.T) {
		t.Parallel()

		const nonce = "geta0"
		host := remotePayloadDomain(cid, nonce)

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+remoteServerURL+"/test-get-path", nil)
		require.NoError(t, err)
		req.Host = host
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		i := rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+nonce
		})
		assert.Contains(t, []string{"http", "https"}, i.Protocol)
		assert.Equal(t, cid[:remoteCIDLength], i.UniqueID)
		assert.Contains(t, i.RawRequest, "GET /test-get-path")
		assert.Contains(t, i.RawRequest, "Host: "+host)
		assert.NotEmpty(t, i.RawResponse)
		assert.Contains(t, i.RawResponse, "200")
		assert.NotEmpty(t, i.RemoteAddress)
		assert.False(t, i.Timestamp.IsZero())
	})

	t.Run("http_post_body", func(t *testing.T) {
		t.Parallel()

		const nonce = "post0"
		host := remotePayloadDomain(cid, nonce)
		const bodyContent = "SECRET_PAYLOAD_DATA_12345"

		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+remoteServerURL+"/post-endpoint",
			strings.NewReader(bodyContent))
		require.NoError(t, err)
		req.Host = host
		req.Header.Set("Content-Type", "text/plain")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		i := rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+nonce
		})
		assert.Contains(t, i.RawRequest, "POST /post-endpoint")
		assert.Contains(t, i.RawRequest, bodyContent)
	})

	t.Run("http_put", func(t *testing.T) {
		t.Parallel()

		const nonce = "putz0"
		host := remotePayloadDomain(cid, nonce)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, "https://"+remoteServerURL+"/test-put", nil)
		require.NoError(t, err)
		req.Host = host
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		i := rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+nonce
		})
		assert.Contains(t, i.RawRequest, "PUT /test-put")
	})

	t.Run("http_delete", func(t *testing.T) {
		t.Parallel()

		const nonce = "delz0"
		host := remotePayloadDomain(cid, nonce)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodDelete, "https://"+remoteServerURL+"/test-delete", nil)
		require.NoError(t, err)
		req.Host = host
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		i := rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+nonce
		})
		assert.Contains(t, i.RawRequest, "DELETE /test-delete")
	})

	t.Run("http_head", func(t *testing.T) {
		t.Parallel()

		const nonce = "headz"
		host := remotePayloadDomain(cid, nonce)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodHead, "https://"+remoteServerURL+"/test-head", nil)
		require.NoError(t, err)
		req.Host = host
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		i := rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+nonce
		})
		assert.Contains(t, i.RawRequest, "HEAD /test-head")
	})

	t.Run("http_options", func(t *testing.T) {
		t.Parallel()

		const nonce = "optsz"
		host := remotePayloadDomain(cid, nonce)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodOptions, "https://"+remoteServerURL+"/test-opts", nil)
		require.NoError(t, err)
		req.Host = host
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		i := rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+nonce
		})
		assert.Contains(t, i.RawRequest, "OPTIONS /test-opts")
	})

	t.Run("http_robots_txt", func(t *testing.T) {
		t.Parallel()

		const nonce = "roboz"
		host := remotePayloadDomain(cid, nonce)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+remoteServerURL+"/robots.txt", nil)
		require.NoError(t, err)
		req.Host = host
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, resp.Body.Close())
		require.NoError(t, err)

		assert.Contains(t, resp.Header.Get("Content-Type"), "text/plain")
		assert.Contains(t, string(body), "Disallow")

		rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+nonce
		})
	})

	t.Run("http_json_content_type", func(t *testing.T) {
		t.Parallel()

		const nonce = "jsonz"
		host := remotePayloadDomain(cid, nonce)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+remoteServerURL+"/data.json", nil)
		require.NoError(t, err)
		req.Host = host
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, resp.Body.Close())
		require.NoError(t, err)

		assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")
		assert.Contains(t, string(body), `"data"`)

		rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+nonce
		})
	})

	t.Run("http_xml_content_type", func(t *testing.T) {
		t.Parallel()

		const nonce = "xmlz0"
		host := remotePayloadDomain(cid, nonce)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+remoteServerURL+"/data.xml", nil)
		require.NoError(t, err)
		req.Host = host
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, resp.Body.Close())
		require.NoError(t, err)

		assert.Contains(t, resp.Header.Get("Content-Type"), "application/xml")
		assert.Contains(t, string(body), "<data>")

		rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+nonce
		})
	})

	t.Run("http_url_reflection", func(t *testing.T) {
		t.Parallel()

		const nonce = "reflz"
		host := remotePayloadDomain(cid, nonce)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+remoteServerURL+"/reflect-test", nil)
		require.NoError(t, err)
		req.Host = host
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, resp.Body.Close())
		require.NoError(t, err)

		reversed := reverseString(cid + nonce)
		assert.Contains(t, string(body), reversed)

		i := rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+nonce
		})
		assert.Contains(t, i.RawResponse, reversed)
	})

	// Multi-protocol subtest

	t.Run("multi_protocol", func(t *testing.T) {
		t.Parallel()

		const dnsNonce = "mpdn0"
		const httpNonce = "mpht0"

		queryRemoteDNS(t, remotePayloadDomain(cid, dnsNonce), dns.TypeA)

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+remoteServerURL+"/multi", nil)
		require.NoError(t, err)
		req.Host = remotePayloadDomain(cid, httpNonce)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		dnsI := rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+dnsNonce
		})
		httpI := rs.waitFor(t, func(i *pdserver.Interaction) bool {
			return i.FullId == cid+httpNonce
		})
		assert.Equal(t, "dns", dnsI.Protocol)
		assert.Contains(t, []string{"http", "https"}, httpI.Protocol)
	})

	// DNS SSRF records (no client needed)

	t.Run("dns_ssrf_records", func(t *testing.T) {
		t.Parallel()

		ssrfCases := []struct {
			subdomain  string
			expectedIP string
		}{
			{"aws", "169.254.169.254"},
			{"alibaba", "100.100.100.200"},
			{"localhost", "127.0.0.1"},
			{"oracle", "192.0.0.192"},
		}
		for _, tc := range ssrfCases {
			t.Run(tc.subdomain, func(t *testing.T) {
				qname := tc.subdomain + "." + remoteDomain
				r := queryRemoteDNS(t, qname, dns.TypeA)
				require.NotEmpty(t, r.Answer)

				a, ok := r.Answer[0].(*dns.A)
				require.True(t, ok)
				assert.Equal(t, tc.expectedIP, a.A.String(),
					"SSRF record %s should resolve to %s", tc.subdomain, tc.expectedIP)
			})
		}
	})
}
