package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/go-appsec/interactsh-lite/oobclient"
)

// Config holds CLI configuration from file and flags.
type Config struct {
	Server                   string        `yaml:"server"`
	Token                    string        `yaml:"token"`
	Number                   int           `yaml:"number"`
	PollInterval             int           `yaml:"poll-interval"`
	NoHTTPFallback           bool          `yaml:"no-http-fallback"`
	CorrelationIdLength      int           `yaml:"correlation-id-length"`
	CorrelationIdNonceLength int           `yaml:"correlation-id-nonce-length"`
	KeepAliveInterval        time.Duration `yaml:"keep-alive-interval"`
	DNSOnly                  bool          `yaml:"dns-only"`
	HTTPOnly                 bool          `yaml:"http-only"`
	SMTPOnly                 bool          `yaml:"smtp-only"`
	FTPOnly                  bool          `yaml:"ftp-only"`
	LDAPOnly                 bool          `yaml:"ldap-only"`
	JSON                     bool          `yaml:"json"`
	Verbose                  bool          `yaml:"verbose"`
	Timeout                  time.Duration `yaml:"timeout"`
	Count                    int           `yaml:"count"`
	Redirect                 string        `yaml:"redirect"`
	ResponseStatus           int           `yaml:"response-status"`
	ResponseHeaders          []string      `yaml:"response-header"`
	ResponseBody             string        `yaml:"response-body"`
}

// LoadConfig loads configuration from a YAML file, applying defaults for unset values.
func LoadConfig(path string) (Config, error) {
	cfg := Config{
		Number:            1,
		PollInterval:      2,
		KeepAliveInterval: oobclient.DefaultOptions.KeepAliveInterval,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}

	// Unmarshal over defaults - YAML only overwrites fields present in file
	err = yaml.Unmarshal(data, &cfg)
	return cfg, err
}

// buildResponseConfig derives the stored response config from CLI/file settings.
// Returns nil when no response is configured. Errors if --redirect is combined
// with the --response-* settings.
func buildResponseConfig(cfg Config) (*oobclient.ResponseConfig, error) {
	redirectSet := cfg.Redirect != ""
	responseSet := cfg.ResponseStatus != 0 || len(cfg.ResponseHeaders) > 0 || cfg.ResponseBody != ""

	switch {
	case redirectSet && responseSet:
		return nil, errors.New("--redirect cannot be combined with --response-status/--response-header/--response-body")
	case redirectSet:
		return &oobclient.ResponseConfig{
			StatusCode: 307,
			Headers:    []string{"Location: " + cfg.Redirect},
		}, nil
	case responseSet:
		status := cfg.ResponseStatus
		if status == 0 {
			status = 200
		}
		return &oobclient.ResponseConfig{
			StatusCode: status,
			Headers:    cfg.ResponseHeaders,
			Body:       cfg.ResponseBody,
		}, nil
	default:
		return nil, nil
	}
}

func ParseCommaSeparated(input string) []string {
	if input == "" {
		return nil
	}
	parts := strings.Split(input, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			result = append(result, p)
		}
	}
	return result
}

func DefaultConfigPath() string {
	// Use OS-specific config directory (XDG_CONFIG_HOME on Linux, %APPDATA% on Windows)
	configDir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(configDir, "interactsh-client", "config.yaml")
}
