package oobsrv

import (
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/interactsh-lite/oobclient"
)

func TestACMEStore(t *testing.T) {
	t.Parallel()

	t.Run("set_and_get", func(t *testing.T) {
		s := newACMEStore()
		s.Set("example.com", "token123")
		v, ok := s.Get("example.com")
		assert.True(t, ok)
		assert.Equal(t, "token123", v)
	})

	t.Run("overwrite", func(t *testing.T) {
		s := newACMEStore()
		s.Set("example.com", "old")
		s.Set("example.com", "new")
		v, ok := s.Get("example.com")
		assert.True(t, ok)
		assert.Equal(t, "new", v)
	})

	t.Run("normalizes_fqdn", func(t *testing.T) {
		s := newACMEStore()
		s.Set("Example.COM.", "token")
		v, ok := s.Get("example.com")
		assert.True(t, ok)
		assert.Equal(t, "token", v)
	})
}

func TestParseCustomRecords(t *testing.T) {
	t.Parallel()

	t.Run("standard_format", func(t *testing.T) {
		data := []byte(`
api:
  - type: A
    value: "192.0.2.1"
    ttl: 7200
  - type: AAAA
    value: "2001:db8::1"
`)
		records, err := parseCustomRecords(data)
		require.NoError(t, err)
		require.Len(t, records["api"], 2)
		assert.Equal(t, "A", records["api"][0].Type)
		assert.Equal(t, uint32(7200), records["api"][0].TTL)
		assert.Equal(t, "AAAA", records["api"][1].Type)
		assert.Equal(t, uint32(3600), records["api"][1].TTL) // default
	})

	t.Run("legacy_format", func(t *testing.T) {
		data := []byte(`
myhost: "10.0.0.1"
`)
		records, err := parseCustomRecords(data)
		require.NoError(t, err)
		require.Len(t, records["myhost"], 1)
		assert.Equal(t, "A", records["myhost"][0].Type)
		assert.Equal(t, "10.0.0.1", records["myhost"][0].Value)
		assert.Equal(t, uint32(3600), records["myhost"][0].TTL)
	})

	t.Run("mx_priority", func(t *testing.T) {
		data := []byte(`
mail:
  - type: MX
    value: "mail1.example.com"
  - type: MX
    value: "mail2.example.com"
    priority: 5
`)
		records, err := parseCustomRecords(data)
		require.NoError(t, err)
		require.Len(t, records["mail"], 2)
		assert.Equal(t, uint16(10), records["mail"][0].Priority)
		assert.Equal(t, uint16(5), records["mail"][1].Priority)
	})

	t.Run("invalid_type", func(t *testing.T) {
		data := []byte(`
bad:
  - type: SRV
    value: "srv.example.com"
`)
		_, err := parseCustomRecords(data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported record type")
	})

	t.Run("case_insensitive_type", func(t *testing.T) {
		data := []byte(`
sub:
  - type: aaaa
    value: "2001:db8::1"
`)
		records, err := parseCustomRecords(data)
		require.NoError(t, err)
		assert.Equal(t, "AAAA", records["sub"][0].Type)
	})

	t.Run("unexpected_value_type", func(t *testing.T) {
		data := []byte(`
bad: 42
`)
		_, err := parseCustomRecords(data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected value type")
	})

	t.Run("invalid_yaml", func(t *testing.T) {
		_, err := parseCustomRecords([]byte(":\n\t:"))
		assert.Error(t, err)
	})
}

func TestLoadCustomRecords(t *testing.T) {
	t.Parallel()

	t.Run("builtins_when_empty_path", func(t *testing.T) {
		records, err := loadCustomRecords("")
		require.NoError(t, err)
		_, ok := records["aws"]
		assert.True(t, ok)
	})

	t.Run("operator_overrides_builtin", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "records.yaml")
		err := os.WriteFile(path, []byte(`aws: "10.0.0.1"`), 0644)
		require.NoError(t, err)

		records, err := loadCustomRecords(path)
		require.NoError(t, err)
		require.Len(t, records["aws"], 1)
		assert.Equal(t, "10.0.0.1", records["aws"][0].Value)
	})

	t.Run("file_not_found", func(t *testing.T) {
		_, err := loadCustomRecords("/nonexistent/file.yaml")
		assert.Error(t, err)
	})
}

// testDNSServer creates a Server with DNS handler ready for testing and starts
// a DNS server on loopback. Returns the server and the address to query.
func testDNSServer(t *testing.T, opts ...func(*Server)) (srv *Server, addr string) {
	t.Helper()

	cfg := validTestConfig()

	logger := slog.New(slog.DiscardHandler)
	var err error
	srv, err = New(cfg, logger)
	require.NoError(t, err)

	srv.ips = ServerIPs{
		IPv4: []net.IP{net.ParseIP("1.2.3.4").To4()},
		IPv6: []net.IP{net.ParseIP("2001:db8::1")},
	}

	for _, opt := range opts {
		opt(srv)
	}

	// Start DNS on random port
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	require.NoError(t, err)
	addr = pc.LocalAddr().String()

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
	return srv, addr
}

// queryDNS sends a DNS query and returns the response.
func queryDNS(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()

	c := new(dns.Client)
	c.Net = "udp"
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)

	r, _, err := c.Exchange(m, addr)
	require.NoError(t, err)
	return r
}

func TestDNSDefaultResponses(t *testing.T) {
	t.Parallel()
	_, addr := testDNSServer(t)

	t.Run("a_record", func(t *testing.T) {
		r := queryDNS(t, addr, "sub.test.com", dns.TypeA)
		require.Len(t, r.Answer, 1)
		a, ok := r.Answer[0].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "1.2.3.4", a.A.String())
		assert.Equal(t, uint32(3600), a.Hdr.Ttl)
	})

	t.Run("aaaa_record", func(t *testing.T) {
		r := queryDNS(t, addr, "sub.test.com", dns.TypeAAAA)
		require.Len(t, r.Answer, 1)
		aaaa, ok := r.Answer[0].(*dns.AAAA)
		require.True(t, ok)
		assert.Equal(t, "2001:db8::1", aaaa.AAAA.String())
		assert.Equal(t, uint32(3600), aaaa.Hdr.Ttl)
	})

	t.Run("mx_record", func(t *testing.T) {
		r := queryDNS(t, addr, "sub.test.com", dns.TypeMX)
		require.Len(t, r.Answer, 1)
		mx, ok := r.Answer[0].(*dns.MX)
		require.True(t, ok)
		assert.Equal(t, uint16(1), mx.Preference)
		assert.Equal(t, "mail.test.com.", mx.Mx)
		assert.Equal(t, uint32(3600), mx.Hdr.Ttl)
	})

	t.Run("ns_record_in_answer", func(t *testing.T) {
		r := queryDNS(t, addr, "sub.test.com", dns.TypeNS)
		require.Len(t, r.Answer, 2)
		ns1, ok := r.Answer[0].(*dns.NS)
		require.True(t, ok)
		assert.Equal(t, "ns1.test.com.", ns1.Ns)
		assert.Equal(t, uint32(3600), ns1.Hdr.Ttl)
		ns2, ok := r.Answer[1].(*dns.NS)
		require.True(t, ok)
		assert.Equal(t, "ns2.test.com.", ns2.Ns)
		// No glue for direct NS query
		assert.Empty(t, r.Extra)
		assert.Empty(t, r.Ns)
	})

	t.Run("soa_record", func(t *testing.T) {
		r := queryDNS(t, addr, "sub.test.com", dns.TypeSOA)
		require.Len(t, r.Answer, 1)
		soa, ok := r.Answer[0].(*dns.SOA)
		require.True(t, ok)
		assert.Equal(t, "ns1.test.com.", soa.Ns)
		assert.Equal(t, "letsencrypt.org.", soa.Mbox)
		assert.Equal(t, uint32(1), soa.Serial)
		assert.Equal(t, uint32(0), soa.Refresh)
		assert.Equal(t, uint32(0), soa.Retry)
		assert.Equal(t, uint32(60), soa.Expire)
		assert.Equal(t, uint32(60), soa.Minttl)
		assert.Equal(t, uint32(0), soa.Hdr.Ttl)
	})

	t.Run("txt_record_empty", func(t *testing.T) {
		r := queryDNS(t, addr, "sub.test.com", dns.TypeTXT)
		require.Len(t, r.Answer, 1)
		txt, ok := r.Answer[0].(*dns.TXT)
		require.True(t, ok)
		assert.Equal(t, []string{""}, txt.Txt)
		assert.Equal(t, uint32(0), txt.Hdr.Ttl)
	})

	t.Run("any_returns_a_and_aaaa", func(t *testing.T) {
		r := queryDNS(t, addr, "sub.test.com", dns.TypeANY)
		// Should have A + AAAA in answer
		var aCount, aaaaCount int
		for _, rr := range r.Answer {
			switch rr.(type) {
			case *dns.A:
				aCount++
			case *dns.AAAA:
				aaaaCount++
			}
		}
		assert.Equal(t, 1, aCount)
		assert.Equal(t, 1, aaaaCount)
	})

	t.Run("unsupported_type_empty", func(t *testing.T) {
		r := queryDNS(t, addr, "sub.test.com", dns.TypeSRV)
		assert.Empty(t, r.Answer)
		assert.Equal(t, dns.RcodeSuccess, r.Rcode)
	})

	t.Run("cname_no_default", func(t *testing.T) {
		r := queryDNS(t, addr, "sub.test.com", dns.TypeCNAME)
		assert.Empty(t, r.Answer)
	})

	t.Run("bare_domain_soa", func(t *testing.T) {
		r := queryDNS(t, addr, "test.com", dns.TypeSOA)
		require.Len(t, r.Answer, 1)
		soa, ok := r.Answer[0].(*dns.SOA)
		require.True(t, ok)
		assert.Equal(t, "ns1.test.com.", soa.Ns)
		assert.Equal(t, "letsencrypt.org.", soa.Mbox)
	})

	t.Run("bare_domain_a_record", func(t *testing.T) {
		r := queryDNS(t, addr, "test.com", dns.TypeA)
		require.Len(t, r.Answer, 1)
		a, ok := r.Answer[0].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "1.2.3.4", a.A.String())
	})

	t.Run("ns1_returns_a_record", func(t *testing.T) {
		r := queryDNS(t, addr, "ns1.test.com", dns.TypeA)
		require.Len(t, r.Answer, 1)
		a, ok := r.Answer[0].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "1.2.3.4", a.A.String())
	})

	t.Run("a_multiple_ipv4", func(t *testing.T) {
		_, addr := testDNSServer(t, func(s *Server) {
			s.ips.IPv4 = []net.IP{
				net.ParseIP("10.0.0.1").To4(),
				net.ParseIP("10.0.0.2").To4(),
				net.ParseIP("10.0.0.3").To4(),
			}
		})
		r := queryDNS(t, addr, "sub.test.com", dns.TypeA)
		require.Len(t, r.Answer, 3)
		got := make([]string, len(r.Answer))
		for i, rr := range r.Answer {
			a, ok := rr.(*dns.A)
			require.True(t, ok)
			got[i] = a.A.String()
		}
		assert.Equal(t, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, got)
	})

	t.Run("aaaa_multiple_ipv6", func(t *testing.T) {
		_, addr := testDNSServer(t, func(s *Server) {
			s.ips.IPv6 = []net.IP{
				net.ParseIP("2001:db8::1"),
				net.ParseIP("2001:db8::2"),
			}
		})
		r := queryDNS(t, addr, "sub.test.com", dns.TypeAAAA)
		require.Len(t, r.Answer, 2)
		got := make([]string, len(r.Answer))
		for i, rr := range r.Answer {
			aaaa, ok := rr.(*dns.AAAA)
			require.True(t, ok)
			got[i] = aaaa.AAAA.String()
		}
		assert.Equal(t, []string{"2001:db8::1", "2001:db8::2"}, got)
	})

	t.Run("aaaa_nodata_ipv4_only", func(t *testing.T) {
		_, addr := testDNSServer(t, func(s *Server) {
			s.ips = ServerIPs{IPv4: []net.IP{net.ParseIP("1.2.3.4").To4()}}
		})
		r := queryDNS(t, addr, "sub.test.com", dns.TypeAAAA)
		assert.Equal(t, dns.RcodeSuccess, r.Rcode)
		assert.True(t, r.Authoritative)
		assert.Empty(t, r.Answer)
		require.Len(t, r.Ns, 1)
		soa, ok := r.Ns[0].(*dns.SOA)
		require.True(t, ok)
		assert.Equal(t, "test.com.", soa.Hdr.Name)
		assert.Equal(t, uint32(0), soa.Hdr.Ttl)
		assert.Equal(t, "ns1.test.com.", soa.Ns)
		assert.Empty(t, r.Extra)
	})

	t.Run("a_nodata_ipv6_only", func(t *testing.T) {
		_, addr := testDNSServer(t, func(s *Server) {
			s.ips = ServerIPs{IPv6: []net.IP{net.ParseIP("2001:db8::1")}}
		})
		r := queryDNS(t, addr, "sub.test.com", dns.TypeA)
		assert.Equal(t, dns.RcodeSuccess, r.Rcode)
		assert.Empty(t, r.Answer)
		require.Len(t, r.Ns, 1)
		soa, ok := r.Ns[0].(*dns.SOA)
		require.True(t, ok)
		assert.Equal(t, "test.com.", soa.Hdr.Name)
		assert.Equal(t, uint32(0), soa.Hdr.Ttl)
		assert.Empty(t, r.Extra)
	})

	t.Run("any_nodata_no_ips", func(t *testing.T) {
		_, addr := testDNSServer(t, func(s *Server) {
			s.ips = ServerIPs{}
		})
		r := queryDNS(t, addr, "sub.test.com", dns.TypeANY)
		assert.Equal(t, dns.RcodeSuccess, r.Rcode)
		assert.Empty(t, r.Answer)
		require.Len(t, r.Ns, 1)
		_, ok := r.Ns[0].(*dns.SOA)
		assert.True(t, ok)
		assert.Empty(t, r.Extra)
	})

	t.Run("any_partial_ipv4_only", func(t *testing.T) {
		_, addr := testDNSServer(t, func(s *Server) {
			s.ips = ServerIPs{IPv4: []net.IP{net.ParseIP("1.2.3.4").To4()}}
		})
		r := queryDNS(t, addr, "sub.test.com", dns.TypeANY)
		assert.NotEmpty(t, r.Answer)
		require.Len(t, r.Ns, 2)
		_, isNS := r.Ns[0].(*dns.NS)
		assert.True(t, isNS)
		assert.NotEmpty(t, r.Extra)
	})

	t.Run("a_normal_has_glue", func(t *testing.T) {
		_, addr := testDNSServer(t)
		r := queryDNS(t, addr, "sub.test.com", dns.TypeA)
		assert.NotEmpty(t, r.Answer)
		require.Len(t, r.Ns, 2)
		_, isNS := r.Ns[0].(*dns.NS)
		assert.True(t, isNS)
		assert.NotEmpty(t, r.Extra)
	})

	t.Run("nodata_soa_owner_is_apex", func(t *testing.T) {
		_, addr := testDNSServer(t, func(s *Server) {
			s.ips = ServerIPs{IPv4: []net.IP{net.ParseIP("1.2.3.4").To4()}}
		})
		r := queryDNS(t, addr, "deep.sub.test.com", dns.TypeAAAA)
		assert.Empty(t, r.Answer)
		require.Len(t, r.Ns, 1)
		soa, ok := r.Ns[0].(*dns.SOA)
		require.True(t, ok)
		assert.Equal(t, "test.com.", soa.Hdr.Name)
	})
}

func TestDNSFlags(t *testing.T) {
	t.Parallel()
	_, addr := testDNSServer(t)

	t.Run("aa_always_set", func(t *testing.T) {
		r := queryDNS(t, addr, "sub.test.com", dns.TypeA)
		assert.True(t, r.Authoritative)
	})

	t.Run("ra_always_false", func(t *testing.T) {
		r := queryDNS(t, addr, "sub.test.com", dns.TypeA)
		assert.False(t, r.RecursionAvailable)
	})

	t.Run("rd_copied_from_request", func(t *testing.T) {
		c := new(dns.Client)
		c.Net = "udp"
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("sub.test.com"), dns.TypeA)
		m.RecursionDesired = false

		r, _, err := c.Exchange(m, addr)
		require.NoError(t, err)
		assert.False(t, r.RecursionDesired)
	})
}

func TestDNSGlueRecords(t *testing.T) {
	t.Parallel()
	_, addr := testDNSServer(t)

	t.Run("mx_no_glue", func(t *testing.T) {
		r := queryDNS(t, addr, "sub.test.com", dns.TypeMX)
		assert.Empty(t, r.Ns)
		assert.Empty(t, r.Extra)
	})

	t.Run("glue_record_structure", func(t *testing.T) {
		_, addr := testDNSServer(t)

		r := queryDNS(t, addr, "sub.test.com", dns.TypeA)
		// Authority: 2 NS records (ns1, ns2)
		require.Len(t, r.Ns, 2)
		ns1 := r.Ns[0].(*dns.NS)
		ns2 := r.Ns[1].(*dns.NS)
		assert.Equal(t, "ns1.test.com.", ns1.Ns)
		assert.Equal(t, "ns2.test.com.", ns2.Ns)

		// Extra: 4 glue records (2 NS names x (1 IPv4 + 1 IPv6))
		require.Len(t, r.Extra, 4)

		glueNames := make([]string, 0, len(r.Extra))
		for _, rr := range r.Extra {
			glueNames = append(glueNames, rr.Header().Name)
		}
		assert.Contains(t, glueNames, "ns1.test.com.")
		assert.Contains(t, glueNames, "ns2.test.com.")
	})
}

func TestDNSNonConfiguredDomain(t *testing.T) {
	t.Parallel()
	_, addr := testDNSServer(t)

	r := queryDNS(t, addr, "other.example.org", dns.TypeA)
	assert.Equal(t, dns.RcodeSuccess, r.Rcode)
	assert.True(t, r.Authoritative)
	assert.Empty(t, r.Answer)
	assert.Empty(t, r.Ns)
	assert.Empty(t, r.Extra)
}

func TestDNSCustomRecords(t *testing.T) {
	t.Parallel()

	withCustomRecords := func(s *Server) {
		s.customRecords = customRecords{
			"aws":       {{Type: "A", Value: "169.254.169.254", TTL: 3600}},
			"cdn":       {{Type: "CNAME", Value: "example.cdn.net", TTL: 3600}},
			"mail":      {{Type: "MX", Value: "mail.example.com", TTL: 3600, Priority: 5}},
			"spf":       {{Type: "TXT", Value: "v=spf1 ~all", TTL: 3600}},
			"custom-ns": {{Type: "NS", Value: "ns1.example.com", TTL: 3600}},
			"multi": {
				{Type: "A", Value: "10.0.0.1", TTL: 3600},
				{Type: "TXT", Value: "hello", TTL: 3600},
			},
		}
	}

	t.Run("custom_a_record", func(t *testing.T) {
		_, addr := testDNSServer(t, withCustomRecords)
		r := queryDNS(t, addr, "aws.test.com", dns.TypeA)
		require.Len(t, r.Answer, 1)
		a, ok := r.Answer[0].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "169.254.169.254", a.A.String())
	})

	t.Run("custom_cname", func(t *testing.T) {
		_, addr := testDNSServer(t, withCustomRecords)
		r := queryDNS(t, addr, "cdn.test.com", dns.TypeCNAME)
		require.Len(t, r.Answer, 1)
		cname, ok := r.Answer[0].(*dns.CNAME)
		require.True(t, ok)
		assert.Equal(t, "example.cdn.net.", cname.Target)
	})

	t.Run("custom_mx_priority", func(t *testing.T) {
		_, addr := testDNSServer(t, withCustomRecords)
		r := queryDNS(t, addr, "mail.test.com", dns.TypeMX)
		require.Len(t, r.Answer, 1)
		mx, ok := r.Answer[0].(*dns.MX)
		require.True(t, ok)
		assert.Equal(t, uint16(5), mx.Preference)
	})

	t.Run("custom_txt", func(t *testing.T) {
		_, addr := testDNSServer(t, withCustomRecords)
		r := queryDNS(t, addr, "spf.test.com", dns.TypeTXT)
		require.Len(t, r.Answer, 1)
		txt, ok := r.Answer[0].(*dns.TXT)
		require.True(t, ok)
		assert.Equal(t, []string{"v=spf1 ~all"}, txt.Txt)
	})

	t.Run("custom_ns_no_glue", func(t *testing.T) {
		_, addr := testDNSServer(t, withCustomRecords)
		r := queryDNS(t, addr, "custom-ns.test.com", dns.TypeNS)
		require.Len(t, r.Answer, 1)
		assert.Empty(t, r.Extra)
	})

	t.Run("custom_any_returns_all", func(t *testing.T) {
		_, addr := testDNSServer(t, withCustomRecords)
		r := queryDNS(t, addr, "multi.test.com", dns.TypeANY)
		assert.Len(t, r.Answer, 2)
	})

	t.Run("custom_a_no_default_fallback", func(t *testing.T) {
		_, addr := testDNSServer(t, withCustomRecords)
		// Query AAAA for a subdomain that only has custom A -> no default AAAA
		r := queryDNS(t, addr, "aws.test.com", dns.TypeAAAA)
		assert.Empty(t, r.Answer)
	})

	t.Run("custom_subdomain_matching", func(t *testing.T) {
		_, addr := testDNSServer(t, func(s *Server) {
			s.customRecords["v2.api"] = []customRecord{{Type: "A", Value: "10.0.0.2", TTL: 3600}}
		})
		r := queryDNS(t, addr, "v2.api.test.com", dns.TypeA)
		require.Len(t, r.Answer, 1)
		a, ok := r.Answer[0].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "10.0.0.2", a.A.String())
	})

	t.Run("bare_domain_custom_records", func(t *testing.T) {
		_, addr := testDNSServer(t, func(s *Server) {
			s.customRecords[""] = []customRecord{
				{Type: "TXT", Value: "v=spf1 include:example.com ~all", TTL: 300},
				{Type: "TXT", Value: "google-site-verification=abc123", TTL: 300},
			}
		})
		r := queryDNS(t, addr, "test.com", dns.TypeTXT)
		require.Len(t, r.Answer, 2)
		got := make([]string, len(r.Answer))
		for i, rr := range r.Answer {
			txt, ok := rr.(*dns.TXT)
			require.True(t, ok)
			require.Len(t, txt.Txt, 1)
			got[i] = txt.Txt[0]
		}
		assert.Equal(t, "v=spf1 include:example.com ~all", got[0])
		assert.Equal(t, "google-site-verification=abc123", got[1])
	})

	t.Run("custom_aaaa_record", func(t *testing.T) {
		_, addr := testDNSServer(t, func(s *Server) {
			s.customRecords = customRecords{
				"v6": {{Type: "AAAA", Value: "2001:db8::99", TTL: 7200}},
			}
		})
		r := queryDNS(t, addr, "v6.test.com", dns.TypeAAAA)
		require.Len(t, r.Answer, 1)
		aaaa, ok := r.Answer[0].(*dns.AAAA)
		require.True(t, ok)
		assert.Equal(t, "2001:db8::99", aaaa.AAAA.String())
		assert.Equal(t, uint32(7200), aaaa.Hdr.Ttl)
	})

	t.Run("custom_a_invalid_ip", func(t *testing.T) {
		_, addr := testDNSServer(t, func(s *Server) {
			s.customRecords = customRecords{
				"bad": {{Type: "A", Value: "not-an-ip", TTL: 3600}},
			}
		})
		r := queryDNS(t, addr, "bad.test.com", dns.TypeA)
		assert.Empty(t, r.Answer)
	})

	t.Run("custom_record_type_filtering", func(t *testing.T) {
		_, addr := testDNSServer(t, func(s *Server) {
			s.customRecords["info"] = []customRecord{
				{Type: "TXT", Value: "hello", TTL: 3600},
				{Type: "TXT", Value: "world", TTL: 3600},
			}
		})
		// TypeA query against TXT-only custom records returns empty
		rA := queryDNS(t, addr, "info.test.com", dns.TypeA)
		assert.Empty(t, rA.Answer)

		// TypeTXT query returns the custom TXT records
		rTXT := queryDNS(t, addr, "info.test.com", dns.TypeTXT)
		require.Len(t, rTXT.Answer, 2)
		for _, rr := range rTXT.Answer {
			_, ok := rr.(*dns.TXT)
			assert.True(t, ok)
		}
	})
}

func TestDNSACMEChallenge(t *testing.T) {
	t.Parallel()

	t.Run("txt_from_store", func(t *testing.T) {
		srv, addr := testDNSServer(t)
		srv.acmeStore.Set("_acme-challenge.test.com", "challenge-token")

		r := queryDNS(t, addr, "_acme-challenge.test.com", dns.TypeTXT)
		require.Len(t, r.Answer, 1)
		txt, ok := r.Answer[0].(*dns.TXT)
		require.True(t, ok)
		assert.Equal(t, []string{"challenge-token"}, txt.Txt)
	})

	t.Run("not_captured", func(t *testing.T) {
		srv, addr := testDNSServer(t)
		srv.acmeStore.Set("_acme-challenge.test.com", "token")

		// Register a session to check interaction storage
		_, err := srv.storage.Register(t.Context(), testCorrelationID, &sharedRSAKey.PublicKey, "secret", nil)
		require.NoError(t, err)

		queryDNS(t, addr, "_acme-challenge.test.com", dns.TypeTXT)

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		assert.Empty(t, interactions)
	})

	t.Run("soa_response", func(t *testing.T) {
		_, addr := testDNSServer(t)
		r := queryDNS(t, addr, "_acme-challenge.test.com", dns.TypeSOA)
		require.Len(t, r.Answer, 1)
		_, ok := r.Answer[0].(*dns.SOA)
		assert.True(t, ok)
	})

	t.Run("missing_record_empty", func(t *testing.T) {
		_, addr := testDNSServer(t)
		r := queryDNS(t, addr, "_acme-challenge.test.com", dns.TypeTXT)
		assert.Empty(t, r.Answer)
	})

	t.Run("a_returns_server_ips", func(t *testing.T) {
		_, addr := testDNSServer(t)
		r := queryDNS(t, addr, "_acme-challenge.test.com", dns.TypeA)
		require.Len(t, r.Answer, 1)
		a, ok := r.Answer[0].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "1.2.3.4", a.A.String())
	})

	t.Run("aaaa_returns_server_ipv6", func(t *testing.T) {
		_, addr := testDNSServer(t)
		r := queryDNS(t, addr, "_acme-challenge.test.com", dns.TypeAAAA)
		require.Len(t, r.Answer, 1)
		aaaa, ok := r.Answer[0].(*dns.AAAA)
		require.True(t, ok)
		assert.Equal(t, "2001:db8::1", aaaa.AAAA.String())
	})

	t.Run("ns_returns_ns_records", func(t *testing.T) {
		_, addr := testDNSServer(t)
		r := queryDNS(t, addr, "_acme-challenge.test.com", dns.TypeNS)
		require.Len(t, r.Answer, 2)
		ns1, ok := r.Answer[0].(*dns.NS)
		require.True(t, ok)
		assert.Equal(t, "ns1.test.com.", ns1.Ns)
		ns2, ok := r.Answer[1].(*dns.NS)
		require.True(t, ok)
		assert.Equal(t, "ns2.test.com.", ns2.Ns)
	})

	t.Run("unsupported_type_empty", func(t *testing.T) {
		_, addr := testDNSServer(t)
		r := queryDNS(t, addr, "_acme-challenge.test.com", dns.TypeMX)
		assert.Empty(t, r.Answer)
	})

	t.Run("acme_overrides_custom_record", func(t *testing.T) {
		srv, addr := testDNSServer(t, func(s *Server) {
			s.customRecords = customRecords{
				"_acme-challenge": {{Type: "A", Value: "10.0.0.1", TTL: 3600}},
			}
		})
		srv.acmeStore.Set("_acme-challenge.test.com", "acme-wins")

		r := queryDNS(t, addr, "_acme-challenge.test.com", dns.TypeTXT)
		require.Len(t, r.Answer, 1)
		txt, ok := r.Answer[0].(*dns.TXT)
		require.True(t, ok)
		assert.Equal(t, []string{"acme-wins"}, txt.Txt)
	})

	t.Run("nested_subdomain_challenge", func(t *testing.T) {
		srv, addr := testDNSServer(t)
		srv.acmeStore.Set("_acme-challenge.sub.test.com", "nested-token")

		r := queryDNS(t, addr, "_acme-challenge.sub.test.com", dns.TypeTXT)
		require.Len(t, r.Answer, 1)
		txt, ok := r.Answer[0].(*dns.TXT)
		require.True(t, ok)
		assert.Equal(t, []string{"nested-token"}, txt.Txt)
	})
}

func TestDNSNameCasePreservation(t *testing.T) {
	t.Parallel()
	_, addr := testDNSServer(t)

	r := queryDNS(t, addr, "AbCdEf.Test.COM", dns.TypeA)
	require.Len(t, r.Answer, 1)
	// The name in the response should preserve original case
	assert.Equal(t, "AbCdEf.Test.COM.", r.Answer[0].Header().Name)
}

func TestDNSMultiDomain(t *testing.T) {
	t.Parallel()

	_, addr := testDNSServer(t, func(s *Server) {
		s.cfg.Domains = []string{"sub.example.com", "example.com"}
	})

	t.Run("specific_domain_matched", func(t *testing.T) {
		r := queryDNS(t, addr, "x.sub.example.com", dns.TypeA)
		require.Len(t, r.Answer, 1)
		// Query was matched (not empty response)
		assert.Equal(t, dns.RcodeSuccess, r.Rcode)
	})

	t.Run("general_domain_matched", func(t *testing.T) {
		r := queryDNS(t, addr, "x.example.com", dns.TypeA)
		require.Len(t, r.Answer, 1)
	})

	t.Run("first_match_extracts_correct_fullid", func(t *testing.T) {
		srv, addr := testDNSServer(t, func(s *Server) {
			s.cfg.Domains = []string{"sub.example.com", "example.com"}
		})

		key := sharedRSAKey
		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
		require.NoError(t, err)

		// Query under sub.example.com - full-id should strip sub.example.com
		queryDNS(t, addr, testCorrelationID+testNonce+".sub.example.com", dns.TypeA)

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)

		interaction := decryptDNSInteraction(t, interactions[0], aesKey)
		// First-match strips "sub.example.com", leaving cid+nonce as full-id
		assert.Equal(t, testCorrelationID+testNonce, interaction.FullId)
	})
}

func TestDNSCounterAlwaysIncrements(t *testing.T) {
	t.Parallel()

	srv, addr := testDNSServer(t)
	assert.Equal(t, uint64(0), srv.dnsCount.Load())

	// Configured domain
	queryDNS(t, addr, "sub.test.com", dns.TypeA)
	assert.Equal(t, uint64(1), srv.dnsCount.Load())

	// Non-configured domain
	queryDNS(t, addr, "other.example.org", dns.TypeA)
	assert.Equal(t, uint64(2), srv.dnsCount.Load())

	// ACME challenge
	queryDNS(t, addr, "_acme-challenge.test.com", dns.TypeTXT)
	assert.Equal(t, uint64(3), srv.dnsCount.Load())
}

func TestDNSInteractionCapture(t *testing.T) {
	t.Parallel()

	t.Run("correlation_id_extracted", func(t *testing.T) {
		srv, addr := testDNSServer(t)
		key := sharedRSAKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
		require.NoError(t, err)

		// Query with correlation ID as subdomain prefix + nonce
		queryDNS(t, addr, testCorrelationID+"abc.test.com", dns.TypeA)

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)
	})

	t.Run("correct_interaction_fields", func(t *testing.T) {
		srv, addr := testDNSServer(t)
		key := sharedRSAKey
		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
		require.NoError(t, err)

		queryDNS(t, addr, testCorrelationID+"abc.test.com", dns.TypeA)

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)

		// Decrypt the interaction
		interaction := decryptDNSInteraction(t, interactions[0], aesKey)

		assert.Equal(t, "dns", interaction.Protocol)
		assert.Equal(t, testCorrelationID, interaction.UniqueID)
		assert.Equal(t, testCorrelationID+"abc", interaction.FullId)
		assert.Equal(t, "A", interaction.QType)
		assert.NotEmpty(t, interaction.RawRequest)
		assert.NotEmpty(t, interaction.RawResponse)
		assert.NotEmpty(t, interaction.RemoteAddress)
		assert.False(t, interaction.Timestamp.IsZero())
	})

	t.Run("no_capture_non_configured", func(t *testing.T) {
		srv, addr := testDNSServer(t)
		key := sharedRSAKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
		require.NoError(t, err)

		queryDNS(t, addr, testCorrelationID+"abc.other.org", dns.TypeA)

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		assert.Empty(t, interactions)
	})

	t.Run("remote_addr_without_port", func(t *testing.T) {
		srv, _ := testDNSServer(t)
		key := sharedRSAKey
		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
		require.NoError(t, err)

		// Build a DNS request message
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(testCorrelationID+testNonce+".test.com"), dns.TypeA)

		srv.captureDNSInteraction(m, "raw-response",
			dns.TypeA, "test.com", testCorrelationID+testNonce, "1.2.3.4")

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)

		interaction := decryptDNSInteraction(t, interactions[0], aesKey)
		assert.Equal(t, "1.2.3.4", interaction.RemoteAddress)
	})

	t.Run("wildcard_tld_bucket", func(t *testing.T) {
		srv, addr := testDNSServer(t, func(s *Server) {
			s.cfg.Wildcard = true
			s.cfg.Auth = true
			s.cfg.Token = testToken
			s.tldBuckets = map[string]*SharedBucket{
				"test.com": NewSharedBucket(s.cfg.MaxSharedInteractions, 24*time.Hour),
			}
		})
		key := sharedRSAKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
		require.NoError(t, err)

		queryDNS(t, addr, testCorrelationID+"abc.test.com", dns.TypeA)

		// Check TLD bucket has an entry
		bucket := srv.tldBuckets["test.com"]
		entries := bucket.ReadFrom("any-consumer")
		require.Len(t, entries, 1)

		// Parse the wildcard interaction
		var interaction oobclient.Interaction
		err = json.Unmarshal(entries[0], &interaction)
		require.NoError(t, err)
		assert.Equal(t, "dns", interaction.Protocol)
		// Wildcard unique-id and full-id are the full queried domain
		assert.Contains(t, interaction.UniqueID, "test.com")
	})
}

func TestDNSScanEverywhere(t *testing.T) {
	t.Parallel()

	srv, addr := testDNSServer(t, func(s *Server) {
		s.cfg.ScanEverywhere = true
	})
	key := sharedRSAKey
	_, err := srv.storage.Register(t.Context(), testCorrelationID, &key.PublicKey, "secret", nil)
	require.NoError(t, err)

	// Embed correlation ID in a subdomain that wouldn't match standard extraction
	queryDNS(t, addr, "prefix."+testCorrelationID+"abc.test.com", dns.TypeA)

	interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
	require.NoError(t, err)
	require.Len(t, interactions, 1)
}

func TestStartDNS(t *testing.T) {
	t.Parallel()

	t.Run("binds_udp_and_tcp", func(t *testing.T) {
		cfg := validTestConfig()
		cfg.ListenIP = "127.0.0.1"
		cfg.DNSPort = 0

		logger := slog.New(slog.DiscardHandler)
		srv, err := New(cfg, logger)
		require.NoError(t, err)

		srv.ips = ServerIPs{IPv4: []net.IP{net.ParseIP("1.2.3.4").To4()}}

		initialCount := len(srv.services)
		require.NoError(t, srv.startDNS())
		// Should have added at least UDP service (TCP may also succeed)
		assert.Greater(t, len(srv.services), initialCount)
		assert.Equal(t, "DNS-UDP", srv.services[initialCount].Name())

		for _, svc := range srv.services[initialCount:] {
			assert.NoError(t, svc.Close())
		}
	})

	t.Run("tcp_failure_non_fatal", func(t *testing.T) {
		// Occupy a TCP port so DNS-TCP bind fails
		var lc net.ListenConfig
		tcpLn, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = tcpLn.Close() })
		_, portStr, err := net.SplitHostPort(tcpLn.Addr().String())
		require.NoError(t, err)
		port, err := strconv.Atoi(portStr)
		require.NoError(t, err)

		cfg := validTestConfig()
		cfg.ListenIP = "127.0.0.1"
		cfg.DNSPort = port

		logger := slog.New(slog.DiscardHandler)
		srv, err := New(cfg, logger)
		require.NoError(t, err)

		srv.ips = ServerIPs{IPv4: []net.IP{net.ParseIP("1.2.3.4").To4()}}

		initialCount := len(srv.services)
		require.NoError(t, srv.startDNS())

		// UDP should succeed, TCP should have failed silently
		udpAdded := len(srv.services) - initialCount
		assert.GreaterOrEqual(t, udpAdded, 1)

		// Verify only DNS-UDP was added (no DNS-TCP)
		names := make([]string, 0, len(srv.services[initialCount:]))
		for _, svc := range srv.services[initialCount:] {
			names = append(names, svc.Name())
		}
		assert.Contains(t, names, "DNS-UDP")
		assert.NotContains(t, names, "DNS-TCP")

		for _, svc := range srv.services[initialCount:] {
			assert.NoError(t, svc.Close())
		}
	})
}

// decryptDNSInteraction decrypts an AES-encrypted interaction string and unmarshals it into the target.
func decryptDNSInteraction(t *testing.T, encrypted []byte, aesKey []byte) oobclient.Interaction {
	t.Helper()

	plaintext := decryptTestInteraction(t, encrypted, aesKey)
	var interaction oobclient.Interaction
	require.NoError(t, json.Unmarshal([]byte(plaintext), &interaction))
	return interaction
}
