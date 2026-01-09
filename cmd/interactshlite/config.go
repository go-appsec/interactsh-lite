package main

import (
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds CLI configuration from file and flags.
type Config struct {
	Server                   string        `yaml:"server"`
	Token                    string        `yaml:"token"`
	Number                   int           `yaml:"number"`
	PollInterval             int           `yaml:"poll-interval"`
	NoHTTPFallback           bool          `yaml:"no-http-fallback"`
	CorrelationIDLength      int           `yaml:"correlation-id-length"`
	CorrelationIDNonceLength int           `yaml:"correlation-id-nonce-length"`
	KeepAliveInterval        time.Duration `yaml:"keep-alive-interval"`
	DNSOnly                  bool          `yaml:"dns-only"`
	HTTPOnly                 bool          `yaml:"http-only"`
	SMTPOnly                 bool          `yaml:"smtp-only"`
	JSON                     bool          `yaml:"json"`
	Verbose                  bool          `yaml:"verbose"`
}

// LoadConfig loads configuration from a YAML file, applying defaults for unset values.
func LoadConfig(path string) (Config, error) {
	cfg := Config{
		Server:                   "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me",
		Number:                   1,
		PollInterval:             5,
		CorrelationIDLength:      20,
		CorrelationIDNonceLength: 13,
		KeepAliveInterval:        time.Minute,
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
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + "/.config/interactsh-client/config.yaml"
}
