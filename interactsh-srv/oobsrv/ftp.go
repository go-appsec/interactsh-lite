package oobsrv

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	ftpserver "goftp.io/server/v2"
)

// ftpAuth implements ftpserver.Auth, accepting all credentials.
type ftpAuth struct{}

// Compiler check that ftpAuth implements ftpserver.Auth.
var _ ftpserver.Auth = (*ftpAuth)(nil)

func (a *ftpAuth) CheckPasswd(_ *ftpserver.Context, _, _ string) (bool, error) {
	return true, nil
}

// ftpDriver implements ftpserver.Driver with a NOP pattern. Stat, ListDir,
// and GetFile use the real directory; other operations are no-ops.
type ftpDriver struct {
	rootDir        string
	maxUploadBytes int64 // 0 = unlimited
}

// Compiler check that ftpDriver implements ftpserver.Driver.
var _ ftpserver.Driver = (*ftpDriver)(nil)

func (d *ftpDriver) realPath(path string) string {
	return filepath.Join(d.rootDir, filepath.Clean("/"+path))
}

// safePath resolves symlinks and validates the result stays within rootDir.
func (d *ftpDriver) safePath(path string) (string, error) {
	joined := d.realPath(path)
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(d.rootDir)
	if err != nil {
		return "", err
	}
	if resolved != resolvedRoot && !strings.HasPrefix(resolved, resolvedRoot+string(filepath.Separator)) {
		return "", errors.New("path escapes root directory")
	}
	return resolved, nil
}

func (d *ftpDriver) Stat(_ *ftpserver.Context, path string) (os.FileInfo, error) {
	safe, err := d.safePath(path)
	if err != nil {
		return nil, err
	}
	return os.Stat(safe)
}

func (d *ftpDriver) ListDir(_ *ftpserver.Context, path string, callback func(os.FileInfo) error) error {
	safe, err := d.safePath(path)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(safe)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if info, err := entry.Info(); err != nil {
			return err
		} else if err := callback(info); err != nil {
			return err
		}
	}
	return nil
}

func (d *ftpDriver) GetFile(_ *ftpserver.Context, path string, offset int64) (int64, io.ReadCloser, error) {
	safe, err := d.safePath(path)
	if err != nil {
		return 0, nil, err
	}
	f, err := os.Open(safe)
	if err != nil {
		return 0, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return 0, nil, err
	}
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			_ = f.Close()
			return 0, nil, err
		}
	}
	return info.Size() - offset, f, nil
}

func (d *ftpDriver) PutFile(_ *ftpserver.Context, _ string, data io.Reader, _ int64) (int64, error) {
	if d.maxUploadBytes > 0 {
		data = io.LimitReader(data, d.maxUploadBytes)
	}
	return io.Copy(io.Discard, data)
}

func (d *ftpDriver) DeleteDir(_ *ftpserver.Context, _ string) error  { return nil }
func (d *ftpDriver) DeleteFile(_ *ftpserver.Context, _ string) error { return nil }
func (d *ftpDriver) MakeDir(_ *ftpserver.Context, _ string) error    { return nil }

func (d *ftpDriver) Rename(_ *ftpserver.Context, _, _ string) error { return nil }

// ftpNotifier implements ftpserver.Notifier, capturing FTP operations in the extra bucket.
type ftpNotifier struct {
	server *Server
}

// Compiler check that ftpNotifier implements ftpserver.Notifier.
var _ ftpserver.Notifier = (*ftpNotifier)(nil)

func (n *ftpNotifier) capture(ctx *ftpserver.Context, description string) {
	rawRequest := ctx.Cmd + " " + ctx.Param + "\n" + description
	n.server.captureFTPInteraction(rawRequest, ctx.Sess.RemoteAddr().String())
}

func (n *ftpNotifier) BeforeLoginUser(ctx *ftpserver.Context, userName string) {
	n.server.ftpCount.Add(1)
	n.capture(ctx, userName+" logging in")
}

func (n *ftpNotifier) AfterUserLogin(ctx *ftpserver.Context, userName, password string, _ bool, _ error) {
	n.capture(ctx, "user "+userName+" logged in with password "+password)
}

func (n *ftpNotifier) BeforePutFile(ctx *ftpserver.Context, dstPath string) {
	n.server.ftpCount.Add(1)
	n.capture(ctx, "uploading "+dstPath)
}

func (n *ftpNotifier) AfterFilePut(ctx *ftpserver.Context, dstPath string, _ int64, _ error) {
	n.capture(ctx, "uploaded "+dstPath)
}

func (n *ftpNotifier) BeforeDeleteFile(ctx *ftpserver.Context, dstPath string) {
	n.server.ftpCount.Add(1)
	n.capture(ctx, "deleting "+dstPath)
}

func (n *ftpNotifier) AfterFileDeleted(ctx *ftpserver.Context, dstPath string, _ error) {
	n.capture(ctx, "deleted "+dstPath)
}

func (n *ftpNotifier) BeforeDownloadFile(ctx *ftpserver.Context, dstPath string) {
	n.server.ftpCount.Add(1)
	n.capture(ctx, "downloading file "+dstPath)
}

func (n *ftpNotifier) AfterFileDownloaded(ctx *ftpserver.Context, dstPath string, _ int64, _ error) {
	n.capture(ctx, "downloaded file "+dstPath)
}

func (n *ftpNotifier) BeforeChangeCurDir(ctx *ftpserver.Context, oldCurDir, newCurDir string) {
	n.server.ftpCount.Add(1)
	n.capture(ctx, "changing directory from "+oldCurDir+" to "+newCurDir)
}

func (n *ftpNotifier) AfterCurDirChanged(ctx *ftpserver.Context, oldCurDir, newCurDir string, _ error) {
	n.capture(ctx, "changed directory from "+oldCurDir+" to "+newCurDir)
}

func (n *ftpNotifier) BeforeCreateDir(ctx *ftpserver.Context, dstPath string) {
	n.server.ftpCount.Add(1)
	n.capture(ctx, "creating directory "+dstPath)
}

func (n *ftpNotifier) AfterDirCreated(ctx *ftpserver.Context, dstPath string, _ error) {
	n.capture(ctx, "created directory "+dstPath)
}

func (n *ftpNotifier) BeforeDeleteDir(ctx *ftpserver.Context, dstPath string) {
	n.server.ftpCount.Add(1)
	n.capture(ctx, "deleting directory "+dstPath)
}

func (n *ftpNotifier) AfterDirDeleted(ctx *ftpserver.Context, dstPath string, _ error) {
	n.capture(ctx, "deleted directory "+dstPath)
}

// captureFTPInteraction stores an FTP interaction in the extra bucket.
func (s *Server) captureFTPInteraction(rawRequest, remoteAddr string) {
	if s.extraBucket == nil {
		return
	}
	interaction := InteractionType{
		Protocol:      protocolFTP,
		RawRequest:    rawRequest,
		RemoteAddress: remoteAddr,
		Timestamp:     time.Now().UTC(),
	}
	if data, err := json.Marshal(interaction); err == nil {
		s.extraBucket.Append(data)
	}
}

// startFTP starts FTP and FTPS interaction capture servers.
func (s *Server) startFTP() {
	ftpDir := s.cfg.FTPDir
	if ftpDir == "" {
		var err error
		ftpDir, err = os.MkdirTemp("", "interactsh-ftp-*")
		if err != nil {
			s.logger.Error("failed to create FTP temp dir", "error", err)
			return
		}
		s.ftpTempDir = ftpDir
	}
	s.logger.Info("FTP directory", "path", ftpDir)

	var maxUploadBytes int64
	if s.cfg.MaxRequestSize > 0 {
		maxUploadBytes = int64(s.cfg.MaxRequestSize) * 1024 * 1024
	}
	driver := &ftpDriver{rootDir: ftpDir, maxUploadBytes: maxUploadBytes}
	notifier := &ftpNotifier{server: s}
	auth := &ftpAuth{}
	perm := ftpserver.NewSimplePerm("interactsh", "interactsh")

	// FTP (plain) on FTPPort
	s.startFTPPort(driver, notifier, auth, perm, s.cfg.FTPPort, "FTP", false)

	// FTPS (implicit TLS) on FTPSPort
	if s.tlsConfig != nil {
		s.startFTPPort(driver, notifier, auth, perm, s.cfg.FTPSPort, "FTPS", true)
	} else {
		s.logger.Info("FTPS disabled, no TLS config")
	}
}

// startFTPPort binds and starts a single FTP listener. Non-fatal on bind failure.
func (s *Server) startFTPPort(driver ftpserver.Driver, notifier ftpserver.Notifier, auth ftpserver.Auth, perm ftpserver.Perm, port int, name string, implicitTLS bool) {
	addr := net.JoinHostPort(s.cfg.ListenIP, strconv.Itoa(port))

	ftpSrv, err := ftpserver.NewServer(&ftpserver.Options{
		Driver:   driver,
		Auth:     auth,
		Perm:     perm,
		Hostname: s.cfg.ListenIP,
		Port:     port,
		Name:     "interactsh",
		Logger:   &ftpserver.DiscardLogger{},
	})
	if err != nil {
		s.logger.Warn(fmt.Sprintf("[%s] create failed, skipping", name), "error", err)
		return
	}
	ftpSrv.RegisterNotifer(notifier)

	var ln net.Listener
	if implicitTLS {
		ln, err = tls.Listen("tcp", addr, s.tlsConfig)
	} else {
		var lc net.ListenConfig
		ln, err = lc.Listen(context.Background(), "tcp", addr)
	}
	if err != nil {
		s.logger.Warn(fmt.Sprintf("[%s] bind failed, skipping", name), "addr", addr, "error", err)
		return
	}

	svc := &ftpService{
		name:     name,
		logger:   s.logger,
		server:   ftpSrv,
		listener: ln,
	}
	if err := svc.Start(); err != nil {
		s.logger.Warn(fmt.Sprintf("[%s] start failed, skipping", name), "error", err)
		_ = ln.Close()
		return
	}
	s.addService(svc)
}

// ftpService wraps a goftp Server and its listener as a Service.
type ftpService struct {
	name     string
	logger   *slog.Logger
	server   *ftpserver.Server
	listener net.Listener
}

// Compiler check that ftpService implements Service.
var _ Service = (*ftpService)(nil)

func (f *ftpService) Name() string { return f.name }

func (f *ftpService) Start() error {
	go func() {
		f.logger.Info(fmt.Sprintf("[%s] Listening on TCP %s", f.name, f.listener.Addr()))
		if err := f.server.Serve(f.listener); err != nil {
			f.logger.Debug("ftp service stopped", "name", f.name, "error", err)
		}
	}()
	return nil
}

func (f *ftpService) Close() error {
	// Close the listener directly instead of calling server.Shutdown()
	// to avoid a data race in goftp between Serve() writing the
	// internal context and Shutdown() reading it.
	return f.listener.Close()
}
