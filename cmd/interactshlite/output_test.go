package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-harden/interactsh-lite/oobclient"
)

func TestFormatStandard(t *testing.T) {
	t.Parallel()

	ts := time.Date(2021, 9, 26, 12, 26, 0, 0, time.UTC)

	tests := []struct {
		name        string
		interaction *oobclient.Interaction
		verbose     bool
		contains    []string
	}{
		{
			name: "dns_standard",
			interaction: &oobclient.Interaction{
				Protocol:      "dns",
				FullID:        "abc123xyz",
				QType:         "A",
				RemoteAddress: "172.253.226.100",
				Timestamp:     ts,
			},
			contains: []string{
				"[abc123xyz]",
				"Received DNS interaction (A)",
				"from 172.253.226.100",
				"at 2021-09-26 12:26:00",
			},
		},
		{
			name: "http_standard",
			interaction: &oobclient.Interaction{
				Protocol:      "http",
				FullID:        "http123",
				RemoteAddress: "43.22.22.50",
				Timestamp:     ts,
			},
			contains: []string{
				"[http123]",
				"Received HTTP interaction",
				"from 43.22.22.50",
			},
		},
		{
			name: "smb_no_address",
			interaction: &oobclient.Interaction{
				Protocol:  "smb",
				FullID:    "smb123",
				Timestamp: ts,
			},
			contains: []string{
				"[smb123]",
				"Received SMB interaction at",
			},
		},
		{
			name: "responder_protocol",
			interaction: &oobclient.Interaction{
				Protocol:  "responder",
				FullID:    "resp123",
				Timestamp: ts,
			},
			contains: []string{
				"[resp123]",
				"Received RESPONDER interaction at",
			},
		},
		{
			name: "verbose_with_request",
			interaction: &oobclient.Interaction{
				Protocol:      "http",
				FullID:        "verbose123",
				RemoteAddress: "10.0.0.1",
				Timestamp:     ts,
				RawRequest:    "GET / HTTP/1.1\nHost: test.com",
				RawResponse:   "HTTP/1.1 200 OK",
			},
			verbose: true,
			contains: []string{
				"[verbose123]",
				"HTTP Request",
				"GET / HTTP/1.1",
				"HTTP Response",
				"HTTP/1.1 200 OK",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			err := formatStandard(&buf, tt.interaction, tt.verbose)
			require.NoError(t, err)

			output := buf.String()
			for _, want := range tt.contains {
				assert.Contains(t, output, want)
			}
		})
	}
}

func TestFormatJSON(t *testing.T) {
	t.Parallel()

	interaction := &oobclient.Interaction{
		Protocol:      "dns",
		UniqueID:      "uniqueid123",
		FullID:        "fullid123",
		QType:         "A",
		RawRequest:    "request data",
		RawResponse:   "response data",
		RemoteAddress: "172.253.226.100",
		Timestamp:     time.Date(2021, 9, 26, 12, 26, 0, 0, time.UTC),
	}

	var buf bytes.Buffer
	err := formatJSON(&buf, interaction)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)

	assert.Equal(t, "dns", result["protocol"])
	assert.Equal(t, "uniqueid123", result["unique-id"])
	assert.Equal(t, "fullid123", result["full-id"])
	assert.Equal(t, "A", result["q-type"])
	assert.Equal(t, "172.253.226.100", result["remote-address"])
	assert.Equal(t, "2021-09-26T12:26:00Z", result["timestamp"])
}

func TestShouldDisplay(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		interaction *oobclient.Interaction
		dnsOnly     bool
		httpOnly    bool
		smtpOnly    bool
		expected    bool
	}{
		{
			name:        "no_filters_shows_all",
			interaction: &oobclient.Interaction{Protocol: "http"},
			expected:    true,
		},
		{
			name:        "dns_only_match",
			interaction: &oobclient.Interaction{Protocol: "dns"},
			dnsOnly:     true,
			expected:    true,
		},
		{
			name:        "dns_only_blocks_http",
			interaction: &oobclient.Interaction{Protocol: "http"},
			dnsOnly:     true,
			expected:    false,
		},
		{
			name:        "http_only_match",
			interaction: &oobclient.Interaction{Protocol: "http"},
			httpOnly:    true,
			expected:    true,
		},
		{
			name:        "smtp_only_blocks_dns",
			interaction: &oobclient.Interaction{Protocol: "dns"},
			smtpOnly:    true,
			expected:    false,
		},
		// OR behavior tests - multiple filters active
		{
			name:        "dns_and_http_shows_dns",
			interaction: &oobclient.Interaction{Protocol: "dns"},
			dnsOnly:     true,
			httpOnly:    true,
			expected:    true,
		},
		{
			name:        "dns_and_http_shows_http",
			interaction: &oobclient.Interaction{Protocol: "http"},
			dnsOnly:     true,
			httpOnly:    true,
			expected:    true,
		},
		{
			name:        "dns_and_http_blocks_smtp",
			interaction: &oobclient.Interaction{Protocol: "smtp"},
			dnsOnly:     true,
			httpOnly:    true,
			expected:    false,
		},
		{
			name:        "all_three_shows_smtp",
			interaction: &oobclient.Interaction{Protocol: "smtp"},
			dnsOnly:     true,
			httpOnly:    true,
			smtpOnly:    true,
			expected:    true,
		},
		// FTP, LDAP, SMB only show when no filter is active
		{
			name:        "no_filter_shows_ftp",
			interaction: &oobclient.Interaction{Protocol: "ftp"},
			expected:    true,
		},
		{
			name:        "dns_only_blocks_ftp",
			interaction: &oobclient.Interaction{Protocol: "ftp"},
			dnsOnly:     true,
			expected:    false,
		},
		{
			name:        "no_filter_shows_ldap",
			interaction: &oobclient.Interaction{Protocol: "ldap"},
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected,
				shouldDisplay(tt.interaction, tt.dnsOnly, tt.httpOnly, tt.smtpOnly, nil, nil))
		})
	}
}

func TestCompilePatterns(t *testing.T) {
	t.Parallel()

	t.Run("valid_patterns", func(t *testing.T) {
		regexes, err := compilePatterns([]string{"ssrf.*", "xxe.*"}, "match")
		require.NoError(t, err)
		assert.Len(t, regexes, 2)
	})

	t.Run("invalid_match_pattern", func(t *testing.T) {
		_, err := compilePatterns([]string{"[invalid"}, "match")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid match pattern")
		assert.Contains(t, err.Error(), "[invalid")
	})

	t.Run("invalid_filter_pattern", func(t *testing.T) {
		_, err := compilePatterns([]string{"[invalid"}, "filter")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid filter pattern")
		assert.Contains(t, err.Error(), "[invalid")
	})

	t.Run("empty_patterns", func(t *testing.T) {
		regexes, err := compilePatterns(nil, "match")
		require.NoError(t, err)
		assert.Empty(t, regexes)
	})
}

func TestShouldDisplay_WithPatterns(t *testing.T) {
	t.Parallel()

	matchRegexes, err := compilePatterns([]string{"ssrf"}, "match")
	require.NoError(t, err)
	filterRegexes, err := compilePatterns([]string{"health"}, "filter")
	require.NoError(t, err)

	t.Run("match_passes", func(t *testing.T) {
		interaction := &oobclient.Interaction{
			Protocol: "http",
			FullID:   "ssrf-test-123",
		}
		assert.True(t, shouldDisplay(interaction, false, false, false, matchRegexes, filterRegexes))
	})

	t.Run("match_fails", func(t *testing.T) {
		interaction := &oobclient.Interaction{
			Protocol: "http",
			FullID:   "other-123",
		}
		assert.False(t, shouldDisplay(interaction, false, false, false, matchRegexes, filterRegexes))
	})

	t.Run("filter_excludes", func(t *testing.T) {
		interaction := &oobclient.Interaction{
			Protocol:   "http",
			FullID:     "ssrf-test-123",
			RawRequest: "health-check",
		}
		assert.False(t, shouldDisplay(interaction, false, false, false, matchRegexes, filterRegexes))
	})
}

func TestVerboseSeparators(t *testing.T) {
	t.Parallel()

	interaction := &oobclient.Interaction{
		Protocol:    "dns",
		FullID:      "test123",
		QType:       "A",
		RawRequest:  "query data",
		RawResponse: "response data",
		Timestamp:   time.Date(2021, 9, 26, 12, 26, 0, 0, time.UTC),
	}

	var buf bytes.Buffer
	err := formatStandard(&buf, interaction, true)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "-----------\nDNS Request\n-----------")
	assert.Contains(t, output, "------------\nDNS Response\n------------")
}
