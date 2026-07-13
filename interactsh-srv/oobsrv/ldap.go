package oobsrv

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/vjeantet/ldapserver"
)

func init() {
	ldapserver.Logger = ldapserver.DiscardingLogger
}

// startLDAP starts the LDAP interaction capture server. Non-fatal on bind failure.
func (s *Server) startLDAP() {
	addr := net.JoinHostPort(s.cfg.ListenIP, strconv.Itoa(s.cfg.LDAPPort))

	mux := ldapserver.NewRouteMux()
	mux.Bind(s.handleLDAPBind)
	mux.Search(s.handleLDAPSearch)
	mux.Add(s.handleLDAPAdd)
	mux.Delete(s.handleLDAPDelete)
	mux.Modify(s.handleLDAPModify)
	mux.Compare(s.handleLDAPCompare)
	mux.Abandon(s.handleLDAPAbandon)
	mux.Extended(s.handleLDAPStartTLS()).RequestName(ldapserver.NoticeOfStartTLS)
	mux.Extended(s.handleLDAPWhoAmI()).RequestName(ldapserver.NoticeOfWhoAmI)
	mux.NotFound(s.handleLDAPNotFound)

	srv := ldapserver.NewServer()
	srv.Handle(mux)

	svc := &ldapService{
		name:   "LDAP",
		logger: s.logger,
		server: srv,
		addr:   addr,
	}
	if err := svc.Start(); err != nil {
		s.logger.Warn("[LDAP] start failed, skipping", "error", err)
		return
	}
	s.addService(svc)
}

// ldapService wraps a ldapserver.Server as a Service.
type ldapService struct {
	name   string
	logger *slog.Logger
	server *ldapserver.Server
	addr   string
}

// Compiler check that ldapService implements Service.
var _ Service = (*ldapService)(nil)

func (l *ldapService) Name() string { return l.name }

func (l *ldapService) Start() error {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", l.addr)
	if err != nil {
		return err
	}
	l.logger.Info(fmt.Sprintf("[%s] Listening on TCP %s", l.name, ln.Addr()))
	go func() {
		if err := l.server.Serve(ln); err != nil {
			l.logger.Debug("ldap service stopped", "error", err)
		}
	}()
	return nil
}

func (l *ldapService) Close() error {
	l.server.Stop()
	return nil
}

func (s *Server) handleLDAPBind(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	s.ldapCount.Add(1)

	if s.cfg.LDAP && s.extraBucket != nil {
		r := m.GetBindRequest()
		var pass string
		if r.AuthenticationChoice() == "simple" {
			pass = string(r.AuthenticationSimple())
		}
		rawRequest := fmt.Sprintf("Type=Bind\nAuthenticationChoice=%s\nUser=%s\nPass=%s\n",
			r.AuthenticationChoice(), string(r.Name()), pass)
		s.captureLDAPExtra(rawRequest, ldapRemoteAddr(m))
	}

	w.Write(ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess))
}

// handleLDAPSearch returns a fake entry and captures correlation IDs from BaseDN.
func (s *Server) handleLDAPSearch(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	s.ldapCount.Add(1)

	r := m.GetSearchRequest()
	baseDN := string(r.BaseObject())

	attrs := r.Attributes()
	attrStrs := make([]string, len(attrs))
	for i, a := range attrs {
		attrStrs[i] = string(a)
	}

	filterStr := r.FilterString()
	rawRequest := fmt.Sprintf("Type=Search\nBaseDn=%s\nFilter=%s\nAttributes=%s\n",
		baseDN, filterStr, strings.Join(attrStrs, ", "))

	remoteAddr := ldapRemoteAddr(m)

	// Capture interactions before sending response to avoid race with client
	if s.cfg.LDAP && s.extraBucket != nil {
		s.captureLDAPExtra(rawRequest, remoteAddr)
	}
	s.captureLDAPSearchInteraction(baseDN, rawRequest, remoteAddr)

	// Always send fake entry
	entry := ldapserver.NewSearchResultEntry("cn=interactsh," + baseDN)
	entry.AddAttribute("mail", "interact@s.h", "interact@s.h")
	entry.AddAttribute("company", "aaa")
	entry.AddAttribute("department", "bbbb")
	entry.AddAttribute("l", "cccc")
	entry.AddAttribute("mobile", "123456789")
	entry.AddAttribute("telephoneNumber", "123456789")
	entry.AddAttribute("cn", "interact")
	w.Write(entry)
	w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
}

func (s *Server) handleLDAPAdd(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	s.ldapCount.Add(1)

	if s.cfg.LDAP && s.extraBucket != nil {
		r := m.GetAddRequest()
		var sb strings.Builder
		_, _ = fmt.Fprintf(&sb, "Type=Add\nEntity=%s\n", string(r.Entry()))
		for _, attr := range r.Attributes() {
			for _, val := range attr.Vals() {
				_, _ = fmt.Fprintf(&sb, "Attribute Name=%s Attribute Value=%s\n", string(attr.Type_()), string(val))
			}
		}
		s.captureLDAPExtra(sb.String(), ldapRemoteAddr(m))
	}

	w.Write(ldapserver.NewAddResponse(ldapserver.LDAPResultSuccess))
}

func (s *Server) handleLDAPDelete(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	s.ldapCount.Add(1)

	if s.cfg.LDAP && s.extraBucket != nil {
		r := m.GetDeleteRequest()
		rawRequest := fmt.Sprintf("Type=Delete\nEntity=%s\n", string(r))
		s.captureLDAPExtra(rawRequest, ldapRemoteAddr(m))
	}

	w.Write(ldapserver.NewDeleteResponse(ldapserver.LDAPResultSuccess))
}

func (s *Server) handleLDAPModify(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	s.ldapCount.Add(1)

	if s.cfg.LDAP && s.extraBucket != nil {
		r := m.GetModifyRequest()
		var sb strings.Builder
		_, _ = fmt.Fprintf(&sb, "Type=Modify\nEntity=%s\n", string(r.Object()))
		for _, change := range r.Changes() {
			mod := change.Modification()
			vals := make([]string, len(mod.Vals()))
			for i, v := range mod.Vals() {
				vals[i] = string(v)
			}
			var opName string
			switch int(change.Operation()) {
			case ldapserver.ModifyRequestChangeOperationAdd:
				opName = "Add"
			case ldapserver.ModifyRequestChangeOperationDelete:
				opName = "Delete"
			case ldapserver.ModifyRequestChangeOperationReplace:
				opName = "Replace"
			default:
				opName = fmt.Sprintf("Unknown(%d)", int(change.Operation()))
			}
			_, _ = fmt.Fprintf(&sb, "Operation=%s Attribute=%s Values=[%s]\n",
				opName, string(mod.Type_()), strings.Join(vals, " - "))
		}
		s.captureLDAPExtra(sb.String(), ldapRemoteAddr(m))
	}

	w.Write(ldapserver.NewModifyResponse(ldapserver.LDAPResultSuccess))
}

// handleLDAPCompare always returns CompareTrue.
func (s *Server) handleLDAPCompare(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	s.ldapCount.Add(1)

	if s.cfg.LDAP && s.extraBucket != nil {
		r := m.GetCompareRequest()
		rawRequest := fmt.Sprintf("Type=Compare\nEntity=%s\nAttribute name to compare=%s\nAttribute value expected=%s\n",
			string(r.Entry()), string(r.Ava().AttributeDesc()), string(r.Ava().AssertionValue()))
		s.captureLDAPExtra(rawRequest, ldapRemoteAddr(m))
	}

	w.Write(ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareTrue))
}

func (s *Server) handleLDAPAbandon(_ ldapserver.ResponseWriter, m *ldapserver.Message) {
	s.ldapCount.Add(1)

	if s.cfg.LDAP && s.extraBucket != nil {
		r := m.GetAbandonRequest()
		rawRequest := fmt.Sprintf("Type=Abandon\nMessageID=%d\n", r)
		s.captureLDAPExtra(rawRequest, ldapRemoteAddr(m))
	}
}

// handleLDAPStartTLS returns a handler for StartTLS extended operations.
func (s *Server) handleLDAPStartTLS() ldapserver.HandlerFunc {
	return func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		s.ldapCount.Add(1)

		if s.cfg.LDAP && s.extraBucket != nil {
			s.captureLDAPExtra("Type=Extended\nName=StartTLS\n", ldapRemoteAddr(m))
		}

		if s.tlsConfig == nil {
			s.logger.Debug("LDAP StartTLS rejected, TLS not available")
			res := ldapserver.NewExtendedResponse(ldapserver.LDAPResultOperationsError)
			res.SetDiagnosticMessage("TLS not available")
			w.Write(res)
			return
		}

		tlsConn := tls.Server(m.Client.GetConn(), s.tlsConfig)
		res := ldapserver.NewExtendedResponse(ldapserver.LDAPResultSuccess)
		res.SetResponseName(ldapserver.NoticeOfStartTLS)
		w.Write(res)

		if err := tlsConn.HandshakeContext(context.Background()); err != nil {
			s.logger.Debug("LDAP StartTLS handshake failed", "error", err)
			return
		}
		m.Client.SetConn(tlsConn)
	}
}

// handleLDAPWhoAmI returns a handler for WhoAmI extended operations.
func (s *Server) handleLDAPWhoAmI() ldapserver.HandlerFunc {
	return func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		s.ldapCount.Add(1)

		if s.cfg.LDAP && s.extraBucket != nil {
			s.captureLDAPExtra("Type=Extended\nName=WhoAmI\n", ldapRemoteAddr(m))
		}

		s.logger.Debug("LDAP WhoAmI request", "remote", ldapRemoteAddr(m))
		w.Write(ldapserver.NewExtendedResponse(ldapserver.LDAPResultSuccess))
	}
}

// handleLDAPNotFound handles unrouted operations.
func (s *Server) handleLDAPNotFound(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	s.ldapCount.Add(1)

	switch m.ProtocolOpName() {
	case "ExtendedRequest":
		// Non-StartTLS/WhoAmI extended ops return success per spec
		if s.cfg.LDAP && s.extraBucket != nil {
			r := m.GetExtendedRequest()
			rawRequest := fmt.Sprintf("Type=Extended\nName=%s\nValue=%s\n",
				r.RequestName(), r.RequestValue())
			s.captureLDAPExtra(rawRequest, ldapRemoteAddr(m))
		}
		w.Write(ldapserver.NewExtendedResponse(ldapserver.LDAPResultSuccess))
	default:
		if s.cfg.LDAP && s.extraBucket != nil {
			rawRequest := fmt.Sprintf("Type=%s\n", m.ProtocolOpName())
			s.captureLDAPExtra(rawRequest, ldapRemoteAddr(m))
		}
		w.Write(ldapserver.NewResponse(ldapserver.LDAPResultUnwillingToPerform))
	}
}

// captureLDAPSearchInteraction stores interactions for BaseDN correlation matches.
func (s *Server) captureLDAPSearchInteraction(baseDN, rawRequest, remoteAddr string) {
	matches := MatchLDAPCorrelationID(baseDN, s.cfg.CorrelationIdLength, s.cfg.Domains, s.storage.HasCorrelationID)

	s.storeMatchedInteractions(matches, InteractionType{
		Protocol:      protocolLDAP,
		RawRequest:    rawRequest,
		RemoteAddress: remoteAddr,
		Timestamp:     time.Now().UTC(),
	})
}

// captureLDAPExtra stores an interaction in the extra bucket for full logging.
func (s *Server) captureLDAPExtra(rawRequest, remoteAddr string) {
	if s.extraBucket == nil {
		return
	}
	interaction := InteractionType{
		Protocol:      protocolLDAP,
		RawRequest:    rawRequest,
		RemoteAddress: remoteAddr,
		Timestamp:     time.Now().UTC(),
	}
	if data, err := json.Marshal(interaction); err == nil {
		s.extraBucket.Append(data)
	}
}

// ldapRemoteAddr returns the remote address from an LDAP client connection.
func ldapRemoteAddr(m *ldapserver.Message) string {
	return m.Client.Addr().String()
}
