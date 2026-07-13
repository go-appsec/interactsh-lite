package oobsrv

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Eviction strategy constants for Config.EvictionStrategy.
const (
	EvictionSliding = "sliding"
	EvictionFixed   = "fixed"
)

// defaultEvictionDays is the session TTL in days used when Eviction is unset (<1).
const defaultEvictionDays = 30

// Config holds all server configuration. Field values are populated by YAML
// config loading and CLI flag overrides in the main package.
type Config struct {
	// Input flags
	Domains             []string `yaml:"domain"`
	IPs                 []string `yaml:"ip"`
	ListenIP            string   `yaml:"listen-ip"`
	Eviction            int      `yaml:"eviction"`
	NoEviction          bool     `yaml:"no-eviction"`
	EvictionStrategy    string   `yaml:"eviction-strategy"`
	Auth                bool     `yaml:"auth"`
	Token               string   `yaml:"token"`
	ACAOUrl             string   `yaml:"acao-url"`
	SkipACME            bool     `yaml:"skip-acme"`
	ScanEverywhere      bool     `yaml:"scan-everywhere"`
	CorrelationIdLength int      `yaml:"correlation-id-length"`
	CertFile            string   `yaml:"cert"`
	PrivKeyFile         string   `yaml:"privkey"`
	OriginIPHeader      string   `yaml:"origin-ip-header"`
	MaxRequestSize      int      `yaml:"max-request-size"`

	// Config flags
	Resolvers           []string `yaml:"resolvers"`
	DynamicResp         bool     `yaml:"dynamic-resp"`
	CustomRecords       string   `yaml:"custom-records"`
	HTTPIndex           string   `yaml:"http-index"`
	HTTPDirectory       string   `yaml:"http-directory"`
	DefaultHTTPResponse string   `yaml:"default-http-response"`
	Disk                bool     `yaml:"disk"`
	DiskPath            string   `yaml:"disk-path"`
	ServerHeader        string   `yaml:"server-header"`
	DisableVersion      bool     `yaml:"disable-version"`

	// Service flags
	DNSPort         int    `yaml:"dns-port"`
	HTTPPort        int    `yaml:"http-port"`
	HTTPSPort       int    `yaml:"https-port"`
	SMTPPort        int    `yaml:"smtp-port"`
	SMTPSPort       int    `yaml:"smtps-port"`
	SMTPAutoTLSPort int    `yaml:"smtp-autotls-port"`
	LDAPPort        int    `yaml:"ldap-port"`
	LDAP            bool   `yaml:"ldap"`
	Wildcard        bool   `yaml:"wildcard"`
	FTP             bool   `yaml:"ftp"`
	FTPPort         int    `yaml:"ftp-port"`
	FTPSPort        int    `yaml:"ftps-port"`
	FTPDir          string `yaml:"ftp-dir"`

	// Debug flags
	Debug       bool `yaml:"debug"`
	EnablePprof bool `yaml:"enable-pprof"`
	Metrics     bool `yaml:"metrics"`

	// Injected at startup, not from config file
	Version               string `yaml:"-"`
	MaxSharedInteractions int    `yaml:"-"`
}

// UnmarshalYAML handles goflags-compatible config format where string slice
// fields (domain, ip, resolvers) may be scalar comma-separated strings.
func (c *Config) UnmarshalYAML(node *yaml.Node) error {
	sliceFields := map[string]bool{"domain": true, "ip": true, "resolvers": true}

	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content)-1; i += 2 {
			key := node.Content[i]
			val := node.Content[i+1]
			if sliceFields[key.Value] && val.Kind == yaml.ScalarNode {
				parts := strings.Split(val.Value, ",")
				val.Kind = yaml.SequenceNode
				val.Value = ""
				val.Content = nil
				for _, p := range parts {
					if p = strings.TrimSpace(p); p != "" {
						val.Content = append(val.Content, &yaml.Node{
							Kind:  yaml.ScalarNode,
							Value: p,
						})
					}
				}
			}
		}
	}

	type raw Config
	return node.Decode((*raw)(c))
}

func DefaultConfig() Config {
	return Config{
		ListenIP:              "0.0.0.0",
		Eviction:              defaultEvictionDays,
		EvictionStrategy:      EvictionSliding,
		ACAOUrl:               "*",
		CorrelationIdLength:   20,
		DNSPort:               53,
		HTTPPort:              80,
		HTTPSPort:             443,
		SMTPPort:              25,
		SMTPSPort:             587,
		SMTPAutoTLSPort:       465,
		LDAPPort:              389,
		FTPPort:               21,
		FTPSPort:              990,
		MaxRequestSize:        100,
		MaxSharedInteractions: 10_000,
	}
}

// Validate checks required fields and value constraints.
func (c *Config) Validate() error {
	if len(c.Domains) == 0 {
		return errors.New("at least one domain is required (--domain)")
	}
	if c.CorrelationIdLength < 3 {
		return fmt.Errorf("correlation-id-length must be >= 3, got %d", c.CorrelationIdLength)
	}
	if c.Disk && c.DiskPath == "" {
		return errors.New("--disk-path is required when --disk is enabled")
	}
	if c.FTP && !c.Auth {
		return errors.New("--ftp requires authentication (--auth or --token)")
	}
	if c.LDAP && !c.Auth {
		return errors.New("--ldap requires authentication (--auth or --token)")
	}
	if c.Wildcard && !c.Auth {
		return errors.New("--wildcard requires authentication (--auth or --token)")
	}
	if c.Auth && c.Token == "" {
		return errors.New("--token is required when authentication is enabled")
	}
	if c.EvictionStrategy != EvictionSliding && c.EvictionStrategy != EvictionFixed {
		return fmt.Errorf("eviction-strategy must be %q or %q, got %q", EvictionSliding, EvictionFixed, c.EvictionStrategy)
	}
	return nil
}
