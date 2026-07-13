package oobsrv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"valid_config", nil, ""},
		{"missing_domain", func(c *Config) { c.Domains = nil }, "domain"},
		{"cidl_below_minimum", func(c *Config) { c.CorrelationIdLength = 2 }, "correlation-id-length"},
		{"cidl_at_minimum", func(c *Config) { c.CorrelationIdLength = 3 }, ""},
		{"disk_without_path", func(c *Config) { c.Disk = true }, "disk-path"},
		{"valid_with_optional_features", func(c *Config) {
			c.Disk = true
			c.DiskPath = "/tmp/db"
			c.FTP = true
			c.Auth = true
			c.Token = "tok"
		}, ""},
		{"ftp_without_auth", func(c *Config) { c.FTP = true }, "ftp"},
		{"ldap_without_auth", func(c *Config) { c.LDAP = true }, "ldap"},
		{"wildcard_without_auth", func(c *Config) { c.Wildcard = true }, "wildcard"},
		{"ldap_with_auth", func(c *Config) { c.LDAP = true; c.Auth = true; c.Token = "tok" }, ""},
		{"wildcard_with_auth", func(c *Config) { c.Wildcard = true; c.Auth = true; c.Token = "tok" }, ""},
		{"auth_without_token", func(c *Config) { c.Auth = true }, "token"},
		{"invalid_eviction_strategy", func(c *Config) { c.EvictionStrategy = "typo" }, "eviction-strategy"},
		{"valid_eviction_sliding", func(c *Config) { c.EvictionStrategy = EvictionSliding }, ""},
		{"valid_eviction_fixed", func(c *Config) { c.EvictionStrategy = EvictionFixed }, ""},
		{"eviction_zero_defaults", func(c *Config) { c.Eviction = 0 }, ""},
		{"eviction_negative_defaults", func(c *Config) { c.Eviction = -1 }, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Domains = []string{"test.com"}
			if tt.mutate != nil {
				tt.mutate(&cfg)
			}
			err := cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}
