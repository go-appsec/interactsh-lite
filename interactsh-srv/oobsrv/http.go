package oobsrv

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"
)

func (s *Server) startHTTP() error {
	addr := net.JoinHostPort(s.cfg.ListenIP, strconv.Itoa(s.cfg.HTTPPort))
	svc := &httpService{
		name:   "HTTP",
		logger: s.logger,
		server: &http.Server{
			Addr:              addr,
			Handler:           s.handler,
			ReadHeaderTimeout: 60 * time.Second,
			IdleTimeout:       2 * time.Minute,
			ErrorLog:          s.httpErrorLog(),
		},
	}
	if err := svc.Start(); err != nil {
		return fmt.Errorf("[HTTP] bind %s: %w", addr, err)
	}
	s.addService(svc)
	return nil
}

// httpService wraps *http.Server as a Service with synchronous bind detection.
type httpService struct {
	name     string
	logger   *slog.Logger
	server   *http.Server
	listener net.Listener
}

func (h *httpService) Name() string { return h.name }

func (h *httpService) Start() error {
	var ln net.Listener
	var err error
	if h.server.TLSConfig != nil {
		ln, err = tls.Listen("tcp", h.server.Addr, h.server.TLSConfig)
	} else {
		ln, err = net.Listen("tcp", h.server.Addr)
	}
	if err != nil {
		return err
	}
	h.listener = ln
	go func() {
		h.logger.Info(fmt.Sprintf("[%s] Listening on TCP %s", h.name, ln.Addr()))
		if err := h.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			h.logger.Error("listener stopped", "name", h.name, "error", err)
		}
	}()
	return nil
}

func (h *httpService) Close() error {
	return h.server.Close()
}
