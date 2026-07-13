package oobsrv

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

const teeConnMaxBuf = 8192 // 8 KB cap for raw SMTP envelope capture

// teeConn wraps a net.Conn and copies Read bytes into a capped buffer.
// Used to capture raw SMTP commands before go-smtp's parser normalizes them.
// go-smtp processes one connection per goroutine, so no mutex is needed.
type teeConn struct {
	net.Conn
	buf     bytes.Buffer
	stopped bool // set after snapshot to stop capturing body/ciphertext
}

func (t *teeConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 && !t.stopped && t.buf.Len() < teeConnMaxBuf {
		limit := teeConnMaxBuf - t.buf.Len()
		if n < limit {
			limit = n
		}
		t.buf.Write(p[:limit])
	}
	return n, err
}

func (t *teeConn) Reset() {
	t.buf.Reset()
	t.stopped = false
}

// teeListener wraps a net.Listener, returning teeConn-wrapped connections.
type teeListener struct {
	net.Listener
}

func (l *teeListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &teeConn{Conn: c}, nil
}

// extractRawPath extracts the mailbox path from a raw SMTP parameter string
// (the text after "MAIL FROM:" or "RCPT TO:"). It finds the content between
// the outermost angle brackets, handling quoted strings that may contain '>'.
// Returns empty string on failure, in which case the caller uses the parsed fallback.
func extractRawPath(param string) string {
	param = strings.TrimSpace(param)
	if strings.HasPrefix(param, "<>") {
		return ""
	}

	start := strings.IndexByte(param, '<')
	if start < 0 {
		return ""
	}
	inner := param[start+1:]

	// scan for closing '>', skipping '>' inside quoted strings
	var inQuote bool
	for i := 0; i < len(inner); i++ {
		switch {
		case inner[i] == '\\' && inQuote:
			i++ // skip escaped character
		case inner[i] == '"':
			inQuote = !inQuote
		case inner[i] == '>' && !inQuote:
			return inner[:i]
		}
	}
	return ""
}

// parseRawEnvelope scans raw SMTP session bytes for MAIL FROM and RCPT TO
// commands and extracts their paths without the address-parsing normalization
// that go-smtp applies (bracket stripping, quote removal, escape processing).
func parseRawEnvelope(raw string) (from string, recipients []string) {
	const mailPrefix = "MAIL FROM:"
	const rcptPrefix = "RCPT TO:"

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		upper := strings.ToUpper(line)

		if strings.HasPrefix(upper, mailPrefix) {
			if path := extractRawPath(line[len(mailPrefix):]); path != "" {
				from = path
			}
		} else if strings.HasPrefix(upper, rcptPrefix) {
			if path := extractRawPath(line[len(rcptPrefix):]); path != "" {
				recipients = append(recipients, path)
			}
		}
	}
	return from, recipients
}

// smtpBackend implements smtp.Backend for OOB interaction capture.
type smtpBackend struct {
	server *Server
}

// Compiler check that smtpBackend implements smtp.Backend.
var _ smtp.Backend = (*smtpBackend)(nil)

func (b *smtpBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	var tee *teeConn
	if tc, ok := c.Conn().(*teeConn); ok {
		tee = tc
	}
	return &smtpSession{
		server:     b.server,
		remoteAddr: c.Conn().RemoteAddr().String(),
		tee:        tee,
	}, nil
}

type smtpSession struct {
	server     *Server
	remoteAddr string
	from       string
	recipients []string
	tee        *teeConn // nil after STARTTLS (go-smtp replaces conn with *tls.Conn, so type assertion fails)
}

// Compiler check that smtpSession implements smtp.AuthSession.
var _ smtp.AuthSession = (*smtpSession)(nil)

func (s *smtpSession) AuthMechanisms() []string {
	return []string{"PLAIN", "LOGIN", "CRAM-MD5"}
}

func (s *smtpSession) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case "PLAIN":
		return sasl.NewPlainServer(func(_, _, _ string) error {
			return nil
		}), nil
	case "LOGIN":
		return &loginServer{}, nil
	case "CRAM-MD5":
		return &cramMD5Server{}, nil
	default:
		return nil, fmt.Errorf("unsupported mechanism: %s", mech)
	}
}

func (s *smtpSession) Mail(from string, opts *smtp.MailOptions) error {
	s.from = from
	return nil
}

func (s *smtpSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.recipients = append(s.recipients, to)
	return nil
}

func (s *smtpSession) Data(r io.Reader) error {
	// Snapshot raw envelope before reading body (which adds to the tee buffer).
	// Use raw values when extraction succeeds, parsed values otherwise.
	from := s.from
	recipients := s.recipients
	if s.tee != nil {
		rawFrom, rawRecipients := parseRawEnvelope(s.tee.buf.String())
		s.tee.stopped = true // stop capturing message body / post-STARTTLS ciphertext
		if rawFrom != "" {
			from = rawFrom
		}
		if len(rawRecipients) > 0 {
			recipients = rawRecipients
		}
	}

	// Limit what we store but accept the full message (SIZE 0 advertised)
	orig := r
	if s.server.cfg.MaxRequestSize > 0 {
		r = io.LimitReader(r, int64(s.server.cfg.MaxRequestSize)*1024*1024)
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	// Drain any excess so the SMTP transaction completes successfully
	_, _ = io.Copy(io.Discard, orig)
	s.server.onSMTPData(from, recipients, body, s.remoteAddr)
	return nil
}

func (s *smtpSession) Reset() {
	s.from = ""
	s.recipients = nil
	if s.tee != nil {
		s.tee.Reset()
	}
}

func (s *smtpSession) Logout() error {
	return nil
}

// loginServer implements sasl.Server for the LOGIN mechanism.
type loginServer struct {
	gotUsername bool
}

// Compiler check that loginServer implements sasl.Server.
var _ sasl.Server = (*loginServer)(nil)

func (s *loginServer) Next(response []byte) ([]byte, bool, error) {
	if !s.gotUsername {
		if len(response) == 0 {
			return []byte("Username:"), false, nil
		}
		s.gotUsername = true
		return []byte("Password:"), false, nil
	}
	return nil, true, nil
}

// cramMD5Server implements sasl.Server for the CRAM-MD5 mechanism.
type cramMD5Server struct {
	challenged bool
}

// Compiler check that cramMD5Server implements sasl.Server.
var _ sasl.Server = (*cramMD5Server)(nil)

func (s *cramMD5Server) Next(response []byte) ([]byte, bool, error) {
	if !s.challenged {
		s.challenged = true
		challenge := fmt.Sprintf("<%d@interactsh>", time.Now().UnixNano())
		return []byte(challenge), false, nil
	}
	return nil, true, nil
}

// onSMTPData processes a completed SMTP message, matching each recipient against registered correlation IDs.
func (s *Server) onSMTPData(from string, recipients []string, body []byte, remoteAddr string) {
	s.smtpCount.Add(1)

	remoteIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		remoteIP = remoteAddr
	}

	bodyStr := string(body)
	now := time.Now().UTC()

	var matched bool
	for _, rcpt := range recipients {
		if s.captureSMTPInteraction(from, rcpt, bodyStr, remoteIP, now) {
			matched = true
		}
	}
	if matched {
		s.smtpMatched.Add(1)
	}
}

func (s *Server) captureSMTPInteraction(from, rcpt, body, remoteIP string, now time.Time) bool {
	_, recipientDomain, ok := strings.Cut(rcpt, "@")
	if !ok {
		return false
	}
	recipientDomain = strings.ToLower(recipientDomain)

	domain, domainOk := s.matchedDomain(recipientDomain)
	if !domainOk {
		return false
	}

	return s.captureInteraction(domain, recipientDomain, "", InteractionType{
		Protocol:      protocolSMTP,
		UniqueID:      recipientDomain,
		FullId:        recipientDomain,
		RawRequest:    body,
		SMTPFrom:      from,
		SMTPTo:        rcpt,
		RemoteAddress: remoteIP,
		Timestamp:     now,
	}, InteractionType{
		Protocol:      protocolSMTP,
		RawRequest:    body,
		SMTPFrom:      from,
		SMTPTo:        rcpt,
		RemoteAddress: remoteIP,
		Timestamp:     now,
	})
}

// smtpService wraps a go-smtp Server and its listener as a Service.
type smtpService struct {
	name     string
	logger   *slog.Logger
	server   *smtp.Server
	listener net.Listener
}

// Compiler check that smtpService implements Service.
var _ Service = (*smtpService)(nil)

// slogSMTPLogger adapts *slog.Logger to go-smtp's Logger interface,
// routing connection-level errors to debug (normal internet noise).
type slogSMTPLogger struct {
	logger *slog.Logger
}

func (l *slogSMTPLogger) Printf(format string, v ...interface{}) {
	l.logger.Debug(fmt.Sprintf(format, v...))
}

func (l *slogSMTPLogger) Println(v ...interface{}) {
	l.logger.Debug(fmt.Sprint(v...))
}

func (s *smtpService) Name() string { return s.name }

func (s *smtpService) Start() error {
	go func() {
		s.logger.Info(fmt.Sprintf("[%s] Listening on TCP %s", s.name, s.listener.Addr()))
		if err := s.server.Serve(s.listener); err != nil {
			s.logger.Debug("smtp service stopped", "name", s.name, "error", err)
		}
	}()
	return nil
}

func (s *smtpService) Close() error {
	return s.server.Close()
}

func (s *Server) startSMTP() {
	backend := &smtpBackend{server: s}
	hostname := s.cfg.Domains[0]

	// Port 25: plain SMTP
	s.startSMTPPort(backend, hostname, s.cfg.SMTPPort, "SMTP", nil, false)

	// Port 587: STARTTLS (plaintext with optional TLS upgrade)
	s.startSMTPPort(backend, hostname, s.cfg.SMTPSPort, "SMTP-STARTTLS", s.tlsConfig, false)

	// Port 465: implicit TLS (only if TLS available)
	if s.tlsConfig != nil {
		s.startSMTPPort(backend, hostname, s.cfg.SMTPAutoTLSPort, "SMTPS", s.tlsConfig, true)
	} else {
		s.logger.Info("SMTPS (implicit TLS) disabled, no TLS config")
	}
}

// startSMTPPort binds and starts a single SMTP listener. Non-fatal on bind failure.
func (s *Server) startSMTPPort(backend smtp.Backend, hostname string, port int, name string, tlsCfg *tls.Config, implicitTLS bool) {
	addr := net.JoinHostPort(s.cfg.ListenIP, strconv.Itoa(port))

	smtpSrv := smtp.NewServer(backend)
	smtpSrv.Domain = hostname
	smtpSrv.AllowInsecureAuth = true
	// Do not set MaxMessageBytes: advertise SIZE 0 (unlimited) so clients never refuse to send
	// Body truncation is handled in Data()
	smtpSrv.ErrorLog = &slogSMTPLogger{logger: s.logger}

	// STARTTLS: set TLSConfig so the server advertises STARTTLS in EHLO
	if tlsCfg != nil && !implicitTLS {
		smtpSrv.TLSConfig = tlsCfg
	}

	var ln net.Listener
	var err error
	if implicitTLS {
		ln, err = tls.Listen("tcp", addr, tlsCfg)
	} else {
		var lc net.ListenConfig
		ln, err = lc.Listen(context.Background(), "tcp", addr)
	}
	if err != nil {
		s.logger.Warn(fmt.Sprintf("[%s] bind failed, skipping", name), "addr", addr, "error", err)
		return
	}

	ln = &teeListener{Listener: ln}

	svc := &smtpService{
		name:     name,
		logger:   s.logger,
		server:   smtpSrv,
		listener: ln,
	}
	if err := svc.Start(); err != nil {
		s.logger.Warn(fmt.Sprintf("[%s] start failed, skipping", name), "error", err)
		_ = ln.Close()
		return
	}
	s.addService(svc)
}
