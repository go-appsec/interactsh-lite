package oobsrv

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ftpserver "goftp.io/server/v2"
)

// ftpTestServer starts an FTP server on an ephemeral port. Returns the listener address.
func ftpTestServer(t *testing.T, srv *Server, tlsCfg *tls.Config, implicitTLS bool) string {
	t.Helper()

	ftpDir := t.TempDir()
	driver := &ftpDriver{rootDir: ftpDir}
	notifier := &ftpNotifier{server: srv}
	auth := &ftpAuth{}
	perm := ftpserver.NewSimplePerm("test", "test")

	ftpSrv, err := ftpserver.NewServer(&ftpserver.Options{
		Driver:   driver,
		Auth:     auth,
		Perm:     perm,
		Hostname: "127.0.0.1",
		Port:     0,
		Name:     "test-ftp",
		Logger:   &ftpserver.DiscardLogger{},
	})
	require.NoError(t, err)
	ftpSrv.RegisterNotifer(notifier)

	var ln net.Listener
	if implicitTLS && tlsCfg != nil {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	} else {
		var lc net.ListenConfig
		ln, err = lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	}
	require.NoError(t, err)

	go func() { _ = ftpSrv.Serve(ln) }()

	t.Cleanup(func() { _ = ftpSrv.Shutdown() })
	return ln.Addr().String()
}

// ftpDial connects to an FTP server and reads the 220 welcome.
func ftpDial(t *testing.T, addr string) *textproto.Conn {
	t.Helper()

	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(t.Context(), "tcp", addr)
	require.NoError(t, err)
	err = conn.SetDeadline(time.Now().Add(5 * time.Second))
	require.NoError(t, err)
	tp := textproto.NewConn(conn)
	_, _, err = tp.ReadCodeLine(220)
	require.NoError(t, err)
	return tp
}

// ftpLogin sends USER and PASS commands over a textproto connection.
func ftpLogin(t *testing.T, tp *textproto.Conn, user, pass string) {
	t.Helper()

	id, err := tp.Cmd("USER %s", user)
	require.NoError(t, err)
	tp.StartResponse(id)
	_, _, err = tp.ReadCodeLine(331)
	require.NoError(t, err)
	tp.EndResponse(id)

	id, err = tp.Cmd("PASS %s", pass)
	require.NoError(t, err)
	tp.StartResponse(id)
	_, _, err = tp.ReadCodeLine(230)
	require.NoError(t, err)
	tp.EndResponse(id)
}

func TestFtpDriver(t *testing.T) {
	t.Parallel()

	t.Run("stat_delegates_to_dir", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello"), 0644))
		d := &ftpDriver{rootDir: dir}

		info, err := d.Stat(nil, "/test.txt")
		require.NoError(t, err)
		assert.Equal(t, "test.txt", info.Name())
		assert.Equal(t, int64(5), info.Size())
	})

	t.Run("stat_nonexistent", func(t *testing.T) {
		d := &ftpDriver{rootDir: t.TempDir()}
		_, err := d.Stat(nil, "/nope.txt")
		assert.Error(t, err)
	})

	t.Run("list_dir_delegates", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0644))
		d := &ftpDriver{rootDir: dir}

		var names []string
		err := d.ListDir(nil, "/", func(info os.FileInfo) error {
			names = append(names, info.Name())
			return nil
		})
		require.NoError(t, err)
		assert.Len(t, names, 2)
		assert.Contains(t, names, "a.txt")
		assert.Contains(t, names, "b.txt")
	})

	t.Run("get_file_delegates", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "data.txt"), []byte("content"), 0644))
		d := &ftpDriver{rootDir: dir}

		size, rc, err := d.GetFile(nil, "/data.txt", 0)
		require.NoError(t, err)
		t.Cleanup(func() { _ = rc.Close() })
		assert.Equal(t, int64(7), size)
		data, err := io.ReadAll(rc)
		require.NoError(t, err)
		assert.Equal(t, "content", string(data))
	})

	t.Run("get_file_with_offset", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "data.txt"), []byte("abcdefgh"), 0644))
		d := &ftpDriver{rootDir: dir}

		size, rc, err := d.GetFile(nil, "/data.txt", 3)
		require.NoError(t, err)
		t.Cleanup(func() { _ = rc.Close() })
		assert.Equal(t, int64(5), size)
		data, err := io.ReadAll(rc)
		require.NoError(t, err)
		assert.Equal(t, "defgh", string(data))
	})

	t.Run("get_file_offset_at_size", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "data.txt"), []byte("abcdef"), 0644))
		d := &ftpDriver{rootDir: dir}

		size, rc, err := d.GetFile(nil, "/data.txt", 6)
		require.NoError(t, err)
		t.Cleanup(func() { _ = rc.Close() })
		assert.Equal(t, int64(0), size)
		data, err := io.ReadAll(rc)
		require.NoError(t, err)
		assert.Empty(t, data)
	})

	t.Run("put_file_discards", func(t *testing.T) {
		dir := t.TempDir()
		d := &ftpDriver{rootDir: dir}
		n, err := d.PutFile(nil, "/upload.txt", strings.NewReader("data"), -1)
		require.NoError(t, err)
		assert.Equal(t, int64(4), n)
		// file should not actually exist
		_, err = os.Stat(filepath.Join(dir, "upload.txt"))
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("get_file_nonexistent", func(t *testing.T) {
		d := &ftpDriver{rootDir: t.TempDir()}
		_, _, err := d.GetFile(nil, "/nope.txt", 0)
		assert.Error(t, err)
	})

	t.Run("list_dir_nonexistent", func(t *testing.T) {
		d := &ftpDriver{rootDir: t.TempDir()}
		err := d.ListDir(nil, "/nonexistent", func(os.FileInfo) error { return nil })
		assert.Error(t, err)
	})

	t.Run("delete_file_returns_nil", func(t *testing.T) {
		d := &ftpDriver{rootDir: t.TempDir()}
		assert.NoError(t, d.DeleteFile(nil, "/anything.txt"))
	})

	t.Run("rename_returns_nil", func(t *testing.T) {
		d := &ftpDriver{rootDir: t.TempDir()}
		assert.NoError(t, d.Rename(nil, "/old.txt", "/new.txt"))
	})

	t.Run("path_traversal_safe", func(t *testing.T) {
		dir := t.TempDir()
		d := &ftpDriver{rootDir: dir}
		// Traversal attempt should resolve within rootDir
		rp := d.realPath("/../../../etc/passwd")
		assert.True(t, strings.HasPrefix(rp, dir))
	})
}

func TestCaptureFTPInteraction(t *testing.T) {
	t.Parallel()

	t.Run("stores_in_extra_bucket", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Auth = true
			c.Token = testToken
			c.FTP = true
		})

		srv.captureFTPInteraction("USER alice\nalice logging in", "10.0.0.1:12345")

		data := srv.extraBucket.ReadFrom("test-consumer")
		require.Len(t, data, 1)

		var interaction InteractionType
		require.NoError(t, json.Unmarshal(data[0], &interaction))
		assert.Equal(t, "ftp", interaction.Protocol)
		assert.Equal(t, "USER alice\nalice logging in", interaction.RawRequest)
		assert.Equal(t, "10.0.0.1:12345", interaction.RemoteAddress)
		assert.False(t, interaction.Timestamp.IsZero())
	})
}

func TestFTPServer(t *testing.T) {
	t.Parallel()

	t.Run("login_captures_interactions", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Auth = true
			c.Token = testToken
			c.FTP = true
		})
		addr := ftpTestServer(t, srv, nil, false)

		tp := ftpDial(t, addr)
		t.Cleanup(func() { _ = tp.Close() })
		ftpLogin(t, tp, "alice", "secret")

		require.Eventually(t, func() bool {
			return srv.ftpCount.Load() >= 1
		}, time.Second, 10*time.Millisecond)

		data := srv.extraBucket.ReadFrom("test-consumer")
		// BeforeLoginUser + AfterUserLogin = at least 2
		require.GreaterOrEqual(t, len(data), 2)

		var beforeLogin, afterLogin bool
		for _, d := range data {
			var interaction InteractionType
			if json.Unmarshal(d, &interaction) == nil && interaction.Protocol == "ftp" {
				if strings.Contains(interaction.RawRequest, "alice logging in") {
					beforeLogin = true
				}
				if strings.Contains(interaction.RawRequest, "logged in with password secret") {
					afterLogin = true
				}
			}
		}
		assert.True(t, beforeLogin)
		assert.True(t, afterLogin)

		// Verify RemoteAddress includes port
		var firstInteraction InteractionType
		require.NoError(t, json.Unmarshal(data[0], &firstInteraction))
		assert.Contains(t, firstInteraction.RemoteAddress, ":")
	})

	t.Run("file_operations_captured", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Auth = true
			c.Token = testToken
			c.FTP = true
		})
		addr := ftpTestServer(t, srv, nil, false)

		tp := ftpDial(t, addr)
		t.Cleanup(func() { _ = tp.Close() })
		ftpLogin(t, tp, "user", "pass")

		// CWD / (root always exists in the temp dir)
		id, err := tp.Cmd("CWD %s", "/")
		require.NoError(t, err)
		tp.StartResponse(id)
		_, _, err = tp.ReadCodeLine(250)
		tp.EndResponse(id)
		require.NoError(t, err)

		// MKD /newdir
		id, err = tp.Cmd("MKD %s", "/newdir")
		require.NoError(t, err)
		tp.StartResponse(id)
		_, _, err = tp.ReadCodeLine(257)
		tp.EndResponse(id)
		require.NoError(t, err)

		// RMD /newdir
		id, err = tp.Cmd("RMD %s", "/newdir")
		require.NoError(t, err)
		tp.StartResponse(id)
		_, _, err = tp.ReadCodeLine(250)
		tp.EndResponse(id)
		require.NoError(t, err)

		// login + CWD + MKD + RMD = 4
		require.Eventually(t, func() bool {
			return srv.ftpCount.Load() >= 4
		}, time.Second, 10*time.Millisecond)

		data := srv.extraBucket.ReadFrom("test-consumer")
		require.GreaterOrEqual(t, len(data), 8)

		var cwdFound, mkdFound, rmdFound bool
		for _, d := range data {
			var interaction InteractionType
			if json.Unmarshal(d, &interaction) == nil && interaction.Protocol == "ftp" {
				if strings.Contains(interaction.RawRequest, "changing directory") || strings.Contains(interaction.RawRequest, "changed directory") {
					cwdFound = true
				}
				if strings.Contains(interaction.RawRequest, "creating directory") || strings.Contains(interaction.RawRequest, "created directory") {
					mkdFound = true
				}
				if strings.Contains(interaction.RawRequest, "deleting directory") || strings.Contains(interaction.RawRequest, "deleted directory") {
					rmdFound = true
				}
			}
		}
		assert.True(t, cwdFound)
		assert.True(t, mkdFound)
		assert.True(t, rmdFound)
	})

	t.Run("concurrent_login_sessions", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Auth = true
			c.Token = testToken
			c.FTP = true
		})

		addr := ftpTestServer(t, srv, nil, false)

		var wg sync.WaitGroup
		for range 5 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				dialer := net.Dialer{Timeout: 2 * time.Second}
				conn, err := dialer.DialContext(t.Context(), "tcp", addr)
				if !assert.NoError(t, err) {
					return
				}
				assert.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
				tp := textproto.NewConn(conn)
				defer func() { _ = tp.Close() }()
				if _, _, err = tp.ReadCodeLine(220); !assert.NoError(t, err) {
					return
				}
				id, err := tp.Cmd("USER %s", "anonymous")
				if !assert.NoError(t, err) {
					return
				}
				tp.StartResponse(id)
				_, _, err = tp.ReadCodeLine(331)
				tp.EndResponse(id)
				if !assert.NoError(t, err) {
					return
				}
				id, err = tp.Cmd("PASS %s", "anonymous@")
				if !assert.NoError(t, err) {
					return
				}
				tp.StartResponse(id)
				_, _, err = tp.ReadCodeLine(230)
				tp.EndResponse(id)
				if !assert.NoError(t, err) {
					return
				}
				_, err = tp.Cmd("QUIT")
				assert.NoError(t, err)
			}()
		}
		wg.Wait()

		// 1 count per login x 5
		require.Eventually(t, func() bool {
			return srv.ftpCount.Load() >= 5
		}, 5*time.Second, 50*time.Millisecond)
	})
}

func TestStartFTP(t *testing.T) {
	t.Parallel()

	t.Run("bind_failure_non_fatal", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Auth = true
			c.Token = testToken
			c.FTP = true
		})
		srv.cfg.ListenIP = testListenIP

		// Occupy a port
		var lc net.ListenConfig
		ln, err := lc.Listen(t.Context(), "tcp", testListenIP+":0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })

		srv.cfg.FTPPort = ln.Addr().(*net.TCPAddr).Port
		srv.cfg.FTPSPort = ln.Addr().(*net.TCPAddr).Port

		serviceCount := len(srv.services)
		srv.startFTP()
		t.Cleanup(srv.Shutdown)

		// FTP fails to bind, FTPS skipped (no TLS), no new services
		assert.Len(t, srv.services, serviceCount)
	})

	cases := []struct {
		name     string
		withTLS  bool
		wantFTPS bool
	}{
		{"ftps_skipped_without_tls", false, false},
		{"ftps_starts_with_tls", true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := testServerWithStorage(t, func(c *Config) {
				c.Auth = true
				c.Token = testToken
				c.FTP = true
			})
			srv.cfg.ListenIP = testListenIP
			srv.cfg.FTPPort = 0
			srv.cfg.FTPSPort = 0
			if tc.withTLS {
				srv.tlsConfig = testTLSConfig(t)
			}

			srv.startFTP()
			t.Cleanup(srv.Shutdown)

			names := make([]string, 0, len(srv.services))
			for _, svc := range srv.services {
				names = append(names, svc.Name())
			}
			assert.Contains(t, names, "FTP")
			if tc.wantFTPS {
				assert.Contains(t, names, "FTPS")
			} else {
				assert.NotContains(t, names, "FTPS")
			}
		})
	}
}

func TestFTPSServer(t *testing.T) {
	t.Parallel()

	srv := testServerWithStorage(t, func(c *Config) {
		c.Auth = true
		c.Token = testToken
		c.FTP = true
	})
	tlsCfg := testTLSConfig(t)
	addr := ftpTestServer(t, srv, tlsCfg, true)

	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 2 * time.Second},
		Config:    &tls.Config{InsecureSkipVerify: true},
	}
	conn, err := dialer.DialContext(t.Context(), "tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	err = conn.SetDeadline(time.Now().Add(5 * time.Second))
	require.NoError(t, err)
	tp := textproto.NewConn(conn)
	code, _, err := tp.ReadCodeLine(220)
	require.NoError(t, err)
	assert.Equal(t, 220, code)
}
