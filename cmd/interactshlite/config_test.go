package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	t.Run("valid_config", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")

		content := `server: "custom.server.com"
token: "secret-token"
number: 5
poll-interval: 10
correlation-id-length: 15
keep-alive-interval: 2m
dns-only: true
json: true
`
		require.NoError(t, os.WriteFile(path, []byte(content), 0600))

		cfg, err := LoadConfig(path)
		require.NoError(t, err)

		assert.Equal(t, "custom.server.com", cfg.Server)
		assert.Equal(t, "secret-token", cfg.Token)
		assert.Equal(t, 5, cfg.Number)
		assert.Equal(t, 10, cfg.PollInterval)
		assert.Equal(t, 15, cfg.CorrelationIdLength)
		assert.Equal(t, 2*time.Minute, cfg.KeepAliveInterval)
		assert.True(t, cfg.DNSOnly)
		assert.True(t, cfg.JSON)
	})

	t.Run("partial_config_applies_defaults", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")

		content := `server: "custom.server.com"
number: 10
`
		require.NoError(t, os.WriteFile(path, []byte(content), 0600))

		cfg, err := LoadConfig(path)
		require.NoError(t, err)

		assert.Equal(t, "custom.server.com", cfg.Server)
		assert.Equal(t, 10, cfg.Number)
		// Defaults preserved for unset values
		assert.Equal(t, 5, cfg.PollInterval)
		assert.Equal(t, 20, cfg.CorrelationIdLength)
		assert.Equal(t, 13, cfg.CorrelationIdNonceLength)
		assert.Equal(t, time.Minute, cfg.KeepAliveInterval)
	})

	t.Run("nonexistent_file_returns_defaults", func(t *testing.T) {
		cfg, err := LoadConfig("/nonexistent/path/config.yaml")
		require.NoError(t, err)

		assert.Equal(t, "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me", cfg.Server)
		assert.Equal(t, 1, cfg.Number)
		assert.Equal(t, 5, cfg.PollInterval)
		assert.Equal(t, 20, cfg.CorrelationIdLength)
		assert.Equal(t, 13, cfg.CorrelationIdNonceLength)
		assert.Equal(t, time.Minute, cfg.KeepAliveInterval)
	})

	t.Run("invalid_yaml", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.yaml")

		require.NoError(t, os.WriteFile(path, []byte("invalid: [yaml: syntax"), 0600))

		_, err := LoadConfig(path)
		assert.Error(t, err)
	})
}

func TestParseCommaSeparated(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"single_server", "oast.pro", []string{"oast.pro"}},
		{"multiple_servers", "a.com,b.com,c.com", []string{"a.com", "b.com", "c.com"}},
		{"with_spaces", " a.com , b.com ", []string{"a.com", "b.com"}},
		{"empty_string", "", nil},
		{"empty_parts", "a.com,,b.com", []string{"a.com", "b.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseCommaSeparated(tt.input))
		})
	}
}

func TestDefaultConfigPath(t *testing.T) {
	t.Parallel()

	path := DefaultConfigPath()
	assert.Contains(t, path, ".config/interactsh-client/config.yaml")
}
