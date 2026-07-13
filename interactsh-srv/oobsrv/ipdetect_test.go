package oobsrv

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyIPs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []string
		wantIPv4 int
		wantIPv6 int
	}{
		{"ipv4_only", []string{"1.2.3.4"}, 1, 0},
		{"ipv6_only", []string{"2001:db8::1"}, 0, 1},
		{"mixed", []string{"1.2.3.4", "2001:db8::1"}, 1, 1},
		{"multiple_same_family", []string{"1.2.3.4", "5.6.7.8"}, 2, 0},
		{"empty", []string{}, 0, 0},
		{"invalid_skipped", []string{"not-an-ip", "1.2.3.4"}, 1, 0},
		{"whitespace_trimmed", []string{" 1.2.3.4 "}, 1, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyIPs(tt.input)
			assert.Len(t, result.IPv4, tt.wantIPv4)
			assert.Len(t, result.IPv6, tt.wantIPv6)
		})
	}

	t.Run("parsed_values", func(t *testing.T) {
		result := ClassifyIPs([]string{"10.0.0.1", "2001:db8::1"})
		assert.Equal(t, net.ParseIP("10.0.0.1").To4(), result.IPv4[0])
		assert.Equal(t, net.ParseIP("2001:db8::1"), result.IPv6[0])
	})
}

func TestDetectIPExternal(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr bool
		wantIP  string
	}{
		{
			"valid_ipv4",
			func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintln(w, "93.184.216.34")
			},
			false,
			"93.184.216.34",
		},
		{
			"valid_ipv4_whitespace",
			func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("  93.184.216.34  \n"))
			},
			false,
			"93.184.216.34",
		},
		{
			"invalid_response",
			func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintln(w, "not-an-ip")
			},
			true,
			"",
		},
		{
			"server_error",
			func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = fmt.Fprintln(w, "error")
			},
			true,
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			t.Cleanup(srv.Close)

			old := checkIPURL
			checkIPURL = srv.URL
			t.Cleanup(func() { checkIPURL = old })

			ip, err := detectIPExternal(t.Context(), "tcp4")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantIP, ip.String())
		})
	}
}

func TestValidateLocalIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"loopback_present", "127.0.0.1", true},
		{"non_local_absent", "93.184.216.34", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, validateLocalIP(net.ParseIP(tt.ip)))
		})
	}
}

func TestDetectIPUDP(t *testing.T) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	old := udpTarget
	udpTarget = pc.LocalAddr().String()
	t.Cleanup(func() { udpTarget = old })

	ip, err := detectIPUDP(t.Context(), "udp4")
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", ip.String())
}

func TestDetectIPv4(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "93.184.216.34")
	}))
	t.Cleanup(srv.Close)

	oldURL := checkIPURL
	checkIPURL = srv.URL
	t.Cleanup(func() { checkIPURL = oldURL })

	var lc net.ListenConfig
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	oldUDP := udpTarget
	udpTarget = pc.LocalAddr().String()
	t.Cleanup(func() { udpTarget = oldUDP })

	ip, err := detectIPv4(t.Context())
	require.NoError(t, err)
	assert.True(t, validateLocalIP(ip), "expected a local interface IP, got %s", ip)
}
