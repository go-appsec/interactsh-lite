package oobsrv

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

const defaultTTL = 3600

type customRecord struct {
	Type     string `yaml:"type"`
	Value    string `yaml:"value"`
	TTL      uint32 `yaml:"ttl"`
	Priority uint16 `yaml:"priority"`
}

type customRecords map[string][]customRecord

var supportedRecordTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "MX": true, "TXT": true, "NS": true,
}

// builtinSSRFRecords are default SSRF DNS records.
var builtinSSRFRecords = customRecords{
	"aws":       {{Type: "A", Value: "169.254.169.254", TTL: 3600}},
	"alibaba":   {{Type: "A", Value: "100.100.100.200", TTL: 3600}},
	"localhost": {{Type: "A", Value: "127.0.0.1", TTL: 3600}},
	"oracle":    {{Type: "A", Value: "192.0.0.192", TTL: 3600}},
}

// parseCustomRecords parses YAML DNS records. Supports typed record lists and legacy string->A format.
func parseCustomRecords(data []byte) (customRecords, error) {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing custom records: %w", err)
	}

	records := make(customRecords, len(raw))
	for key, val := range raw {
		key = strings.ToLower(key)
		switch v := val.(type) {
		case string:
			// Legacy format: simple string -> A record
			records[key] = []customRecord{{Type: "A", Value: v, TTL: 3600}}
		case []any:
			// Standard format: list of record objects
			yamlBytes, err := yaml.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("re-marshaling records for %q: %w", key, err)
			}
			var recs []customRecord
			if err := yaml.Unmarshal(yamlBytes, &recs); err != nil {
				return nil, fmt.Errorf("parsing records for %q: %w", key, err)
			}
			for i := range recs {
				recs[i].Type = strings.ToUpper(recs[i].Type)
				if !supportedRecordTypes[recs[i].Type] {
					return nil, fmt.Errorf("unsupported record type %q for subdomain %q", recs[i].Type, key)
				}
				if recs[i].TTL == 0 {
					recs[i].TTL = 3600
				}
				if recs[i].Type == "MX" && recs[i].Priority == 0 {
					recs[i].Priority = 10
				}
			}
			records[key] = recs
		default:
			return nil, fmt.Errorf("unexpected value type for subdomain %q", key)
		}
	}
	return records, nil
}

// loadCustomRecords loads DNS records from YAML, overlaid on built-in SSRF records.
func loadCustomRecords(path string) (customRecords, error) {
	if path == "" {
		return maps.Clone(builtinSSRFRecords), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading custom records file: %w", err)
	}

	operator, err := parseCustomRecords(data)
	if err != nil {
		return nil, err
	}

	// Operator records override builtins
	result := maps.Clone(builtinSSRFRecords)
	maps.Copy(result, operator)
	return result, nil
}

// acmeStore is a thread-safe store for ACME DNS-01 challenge TXT records.
type acmeStore struct {
	mu      sync.RWMutex
	records map[string]string
}

func newACMEStore() *acmeStore {
	return &acmeStore{records: make(map[string]string)}
}

// Set stores a challenge TXT record. FQDN is normalized.
func (s *acmeStore) Set(fqdn, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records[normalizeFQDN(fqdn)] = value
}

// Get returns a challenge TXT record.
func (s *acmeStore) Get(fqdn string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	v, ok := s.records[normalizeFQDN(fqdn)]
	return v, ok
}

// Delete removes a challenge TXT record.
func (s *acmeStore) Delete(fqdn string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.records, normalizeFQDN(fqdn))
}

// normalizeFQDN lowercases and strips trailing dot.
func normalizeFQDN(fqdn string) string {
	return strings.TrimSuffix(strings.ToLower(fqdn), ".")
}

// dnsService wraps a miekg/dns.Server as a Service.
type dnsService struct {
	name   string
	logger *slog.Logger
	server *dns.Server
}

// Compiler check that dnsService implements Service.
var _ Service = (*dnsService)(nil)

func (d *dnsService) Name() string { return d.name }

func (d *dnsService) Start() error {
	var lc net.ListenConfig
	switch d.server.Net {
	case "udp":
		pc, err := lc.ListenPacket(context.Background(), "udp", d.server.Addr)
		if err != nil {
			return err
		}
		d.server.PacketConn = pc
	case "tcp":
		ln, err := lc.Listen(context.Background(), "tcp", d.server.Addr)
		if err != nil {
			return err
		}
		d.server.Listener = ln
	}
	ready := make(chan struct{})
	d.server.NotifyStartedFunc = func() { close(ready) }
	go func() {
		if err := d.server.ActivateAndServe(); err != nil {
			d.logger.Debug("dns service stopped", "name", d.name, "error", err)
		}
	}()
	<-ready
	d.logger.Info("[" + d.name + "] Listening on " + strings.ToUpper(d.server.Net) + " " + d.server.Addr)
	return nil
}

func (d *dnsService) Close() error {
	return d.server.Shutdown()
}

// handleDNS dispatches queries: non-configured domain -> ACME -> custom records -> default.
func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}
	s.dnsCount.Add(1)

	q := r.Question[0]
	qnameLower := normalizeFQDN(q.Name)

	// Build base response
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = false

	// Match against configured domains
	domain, ok := s.matchedDomain(qnameLower)
	if !ok {
		// Non-configured domain: empty NOERROR, no capture
		_ = w.WriteMsg(m)
		return
	}

	subdomain := extractSubdomain(qnameLower, domain)

	// ACME challenges are never captured
	if subdomain == "_acme-challenge" || strings.HasPrefix(subdomain, "_acme-challenge.") {
		s.buildACMEResponse(m, q.Name, q.Qtype, domain)
		_ = w.WriteMsg(m)
		return
	}

	// Custom records or default response
	if records, found := s.customRecords[subdomain]; found {
		s.buildCustomResponse(m, q.Name, q.Qtype, records)
	} else {
		s.buildDefaultResponse(m, q.Name, q.Qtype, domain, subdomain)
	}

	rawResponse := m.String() // Capture raw-response before sending

	// Interaction capture (before sending response)
	s.captureDNSInteraction(r, rawResponse, q.Qtype, domain, subdomain, w.RemoteAddr().String())

	_ = w.WriteMsg(m)
}

// matchedDomain finds the configured domain matching qname by suffix.
func (s *Server) matchedDomain(qname string) (string, bool) {
	for _, domain := range s.cfg.Domains {
		if qname == domain || strings.HasSuffix(qname, "."+domain) {
			return domain, true
		}
	}
	return "", false
}

// extractSubdomain strips the domain suffix from qname. Returns "" for bare domain.
func extractSubdomain(qname, domain string) string {
	if qname == domain {
		return ""
	}
	// qname is "sub.domain.com", domain is "domain.com"
	// result: "sub"
	suffix := "." + domain
	if strings.HasSuffix(qname, suffix) {
		return qname[:len(qname)-len(suffix)]
	}
	return ""
}

// ensureTrailingDot adds trailing dot for DNS wire format.
func ensureTrailingDot(name string) string {
	if !strings.HasSuffix(name, ".") {
		return name + "."
	}
	return name
}

func (s *Server) buildDefaultResponse(m *dns.Msg, qname string, qtype uint16, domain, subdomain string) {
	fqdn := ensureTrailingDot(qname)
	domainDot := ensureTrailingDot(domain)

	switch qtype {
	case dns.TypeA:
		for _, ip := range s.ips.IPv4 {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: defaultTTL},
				A:   ip,
			})
		}
		if len(m.Answer) > 0 {
			s.addNSAuthority(m, domainDot)
			s.addGlueRecords(m, domainDot)
		} else {
			s.addNODATAAuthority(m, domainDot)
		}

	case dns.TypeAAAA:
		for _, ip := range s.ips.IPv6 {
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: defaultTTL},
				AAAA: ip,
			})
		}
		if len(m.Answer) > 0 {
			s.addNSAuthority(m, domainDot)
			s.addGlueRecords(m, domainDot)
		} else {
			s.addNODATAAuthority(m, domainDot)
		}

	case dns.TypeMX:
		m.Answer = append(m.Answer, &dns.MX{
			Hdr:        dns.RR_Header{Name: fqdn, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: defaultTTL},
			Preference: 1,
			Mx:         "mail." + domainDot,
		})

	case dns.TypeNS:
		// Direct NS query: ns1/ns2 in answer, no authority, no glue
		m.Answer = append(m.Answer,
			&dns.NS{
				Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: defaultTTL},
				Ns:  "ns1." + domainDot,
			},
			&dns.NS{
				Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: defaultTTL},
				Ns:  "ns2." + domainDot,
			},
		)

	case dns.TypeSOA:
		m.Answer = append(m.Answer, s.soaRecord(fqdn, domainDot))

	case dns.TypeTXT:
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
			Txt: []string{""},
		})

	case dns.TypeANY:
		// Default ANY: A + AAAA only
		for _, ip := range s.ips.IPv4 {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: defaultTTL},
				A:   ip,
			})
		}
		for _, ip := range s.ips.IPv6 {
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: defaultTTL},
				AAAA: ip,
			})
		}
		if len(m.Answer) > 0 {
			s.addNSAuthority(m, domainDot)
			s.addGlueRecords(m, domainDot)
		} else {
			s.addNODATAAuthority(m, domainDot)
		}

	default:
		// Unsupported query type: empty NOERROR (still captured)
	}
}

func (s *Server) buildCustomResponse(m *dns.Msg, qname string, qtype uint16, records []customRecord) {
	fqdn := ensureTrailingDot(qname)

	for _, rec := range records {
		recType := dnsStringToType(rec.Type)
		if qtype != dns.TypeANY && qtype != recType {
			continue
		}

		rr := s.customRecordToRR(fqdn, rec)
		if rr != nil {
			m.Answer = append(m.Answer, rr)
		}
	}
}

func (s *Server) buildACMEResponse(m *dns.Msg, qname string, qtype uint16, domain string) {
	fqdn := ensureTrailingDot(qname)
	domainDot := ensureTrailingDot(domain)

	switch qtype {
	case dns.TypeTXT:
		// Look up in ACME store (normalize without trailing dot)
		acmeFQDN := normalizeFQDN(qname)
		if value, ok := s.acmeStore.Get(acmeFQDN); ok {
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
				Txt: []string{value},
			})
		}

	case dns.TypeSOA:
		m.Answer = append(m.Answer, s.soaRecord(fqdn, domainDot))

	case dns.TypeNS:
		m.Answer = append(m.Answer,
			&dns.NS{
				Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: defaultTTL},
				Ns:  "ns1." + domainDot,
			},
			&dns.NS{
				Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: defaultTTL},
				Ns:  "ns2." + domainDot,
			},
		)

	case dns.TypeA:
		for _, ip := range s.ips.IPv4 {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: defaultTTL},
				A:   ip,
			})
		}

	case dns.TypeAAAA:
		for _, ip := range s.ips.IPv6 {
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: defaultTTL},
				AAAA: ip,
			})
		}

	default:
		// Other types: empty NOERROR
	}
}

func (s *Server) addNSAuthority(m *dns.Msg, domainDot string) {
	m.Ns = append(m.Ns,
		&dns.NS{
			Hdr: dns.RR_Header{Name: domainDot, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: defaultTTL},
			Ns:  "ns1." + domainDot,
		},
		&dns.NS{
			Hdr: dns.RR_Header{Name: domainDot, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: defaultTTL},
			Ns:  "ns2." + domainDot,
		},
	)
}

func (s *Server) addGlueRecords(m *dns.Msg, domainDot string) {
	for _, nsName := range []string{"ns1." + domainDot, "ns2." + domainDot} {
		for _, ip := range s.ips.IPv4 {
			m.Extra = append(m.Extra, &dns.A{
				Hdr: dns.RR_Header{Name: nsName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: defaultTTL},
				A:   ip,
			})
		}
		for _, ip := range s.ips.IPv6 {
			m.Extra = append(m.Extra, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: nsName, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: defaultTTL},
				AAAA: ip,
			})
		}
	}
}

// addNODATAAuthority adds a zone-apex SOA to the authority section for NODATA responses (RFC 2308).
func (s *Server) addNODATAAuthority(m *dns.Msg, domainDot string) {
	m.Ns = append(m.Ns, s.soaRecord(domainDot, domainDot))
}

func (s *Server) soaRecord(fqdn, domainDot string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: fqdn, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 0},
		Ns:      "ns1." + domainDot,
		Mbox:    "letsencrypt.org.",
		Serial:  1,
		Refresh: 0,
		Retry:   0,
		Expire:  60,
		Minttl:  60,
	}
}

func dnsStringToType(s string) uint16 {
	switch strings.ToUpper(s) {
	case "A":
		return dns.TypeA
	case "AAAA":
		return dns.TypeAAAA
	case "CNAME":
		return dns.TypeCNAME
	case "MX":
		return dns.TypeMX
	case "TXT":
		return dns.TypeTXT
	case "NS":
		return dns.TypeNS
	default:
		return dns.TypeNone
	}
}

func (s *Server) customRecordToRR(fqdn string, rec customRecord) dns.RR {
	switch strings.ToUpper(rec.Type) {
	case "A":
		ip := net.ParseIP(rec.Value)
		if ip == nil {
			return nil
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil
		}
		return &dns.A{
			Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rec.TTL},
			A:   ip4,
		}
	case "AAAA":
		ip := net.ParseIP(rec.Value)
		if ip == nil || ip.To4() != nil {
			return nil
		}
		return &dns.AAAA{
			Hdr:  dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rec.TTL},
			AAAA: ip,
		}
	case "CNAME":
		return &dns.CNAME{
			Hdr:    dns.RR_Header{Name: fqdn, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: rec.TTL},
			Target: ensureTrailingDot(rec.Value),
		}
	case "MX":
		return &dns.MX{
			Hdr:        dns.RR_Header{Name: fqdn, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: rec.TTL},
			Preference: rec.Priority,
			Mx:         ensureTrailingDot(rec.Value),
		}
	case "TXT":
		return &dns.TXT{
			Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: rec.TTL},
			Txt: []string{rec.Value},
		}
	case "NS":
		return &dns.NS{
			Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rec.TTL},
			Ns:  ensureTrailingDot(rec.Value),
		}
	default:
		return nil
	}
}

func (s *Server) captureDNSInteraction(r *dns.Msg, rawResponse string, qtype uint16, domain, subdomain, remoteAddr string) {
	remoteIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		remoteIP = remoteAddr
	}

	rawRequest := r.String()
	qtypeStr := dns.TypeToString[qtype]
	qnameLower := normalizeFQDN(r.Question[0].Name)
	now := time.Now().UTC()

	if s.captureInteraction(domain, subdomain, rawRequest, InteractionType{
		Protocol:      protocolDNS,
		UniqueID:      qnameLower,
		FullId:        qnameLower,
		QType:         qtypeStr,
		RawRequest:    rawRequest,
		RawResponse:   rawResponse,
		RemoteAddress: remoteIP,
		Timestamp:     now,
	}, InteractionType{
		Protocol:      protocolDNS,
		QType:         qtypeStr,
		RawRequest:    rawRequest,
		RawResponse:   rawResponse,
		RemoteAddress: remoteIP,
		Timestamp:     now,
	}) {
		s.dnsMatched.Add(1)
	}
}

func (s *Server) startDNS() error {
	addr := net.JoinHostPort(s.cfg.ListenIP, strconv.Itoa(s.cfg.DNSPort))
	handler := dns.HandlerFunc(s.handleDNS)

	// UDP (fatal on bind failure)
	udpSvc := &dnsService{
		name:   "DNS-UDP",
		logger: s.logger,
		server: &dns.Server{Addr: addr, Net: "udp", Handler: handler},
	}
	if err := udpSvc.Start(); err != nil {
		return fmt.Errorf("DNS UDP bind %s: %w", addr, err)
	}
	s.addService(udpSvc)

	// TCP (non-fatal on bind failure)
	tcpSvc := &dnsService{
		name:   "DNS-TCP",
		logger: s.logger,
		server: &dns.Server{Addr: addr, Net: "tcp", Handler: handler},
	}
	if err := tcpSvc.Start(); err != nil {
		s.logger.Warn("DNS TCP bind failed, continuing with UDP only", "error", err)
	} else {
		s.addService(tcpSvc)
	}
	return nil
}

// resolveIPs classifies configured IPs or auto-detects them.
func (s *Server) resolveIPs() error {
	if len(s.cfg.IPs) > 0 {
		s.ips = ClassifyIPs(s.cfg.IPs)
		s.logger.Info("using configured IPs", "ipv4", formatIPs(s.ips.IPv4), "ipv6", formatIPs(s.ips.IPv6))
		return nil
	}

	if ip := net.ParseIP(s.cfg.ListenIP); ip != nil && !ip.IsUnspecified() {
		// Non-default listen IP: use it directly
		s.ips = ClassifyIPs([]string{s.cfg.ListenIP})
		s.logger.Info("using listen IP", "ipv4", formatIPs(s.ips.IPv4), "ipv6", formatIPs(s.ips.IPv6))
		return nil
	}

	ips, err := DetectIPs(s.logger)
	if err != nil {
		return err
	}
	s.ips = ips
	s.logger.Info("auto-detected IPs", "ipv4", formatIPs(s.ips.IPv4), "ipv6", formatIPs(s.ips.IPv6))
	return nil
}

func formatIPs(ips []net.IP) string {
	if len(ips) == 0 {
		return "(none)"
	}
	strs := make([]string, len(ips))
	for i, ip := range ips {
		strs[i] = ip.String()
	}
	return strings.Join(strs, ", ")
}
