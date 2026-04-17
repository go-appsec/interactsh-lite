# go-appsec/interactsh-lite

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/go-appsec/interactsh-lite/blob/main/LICENSE)
[![Build Status](https://github.com/go-appsec/interactsh-lite/actions/workflows/tests-main.yml/badge.svg)](https://github.com/go-appsec/interactsh-lite/actions/workflows/tests-main.yml)

A lightweight, dependency-minimal Go project for [Interactsh](https://github.com/projectdiscovery/interactsh) out-of-band (OOB/OAST) interaction detection. Provides a client library, standalone CLI client, and a lightweight interaction capture server, all with minimal dependencies and clean APIs.

## Features

- Minimal dependencies with small binaries (client under 10MB, server under 20MB)
- Context-aware API for cancellation and timeouts
- Thread-safe client with clear state machine
- Session persistence for long-running tests
- Cross-compatible: the go-appsec/interactsh-lite client works with ProjectDiscovery's public servers and the go-appsec/interactsh-lite server; the go-appsec/interactsh-lite server works with both this project's client and ProjectDiscovery's official `interactsh-client`
- Redirect testing with session-stored or query parameter encoded redirect responses on hosted `*.oastsrv.net` servers
- Broad HTTPS ALPN support (`h2`, `http/1.1`, `http/1.0`, `spdy/*`, `hq`) so probing with legacy protocol names still complete the TLS handshake and get captured
- Standalone CLI client (installed as `interactsh-lite`) and server (installed as `interactsh-srv`)

## Supported Protocols

| Protocol | Description |
|----------|-------------|
| DNS | A, AAAA, CNAME, MX, TXT, NS, SOA queries |
| HTTP/HTTPS | Full request and response capture |
| SMTP/SMTPS | Email interactions with MAIL FROM and RCPT TO capture |
| FTP/FTPS | FTP file and directory operation capture |
| LDAP | LDAP search query interactions |

## CLI Tool

Download the client binary for your platform from the [latest release](https://github.com/go-appsec/interactsh-lite/releases), or install with `go install`:

```bash
go install github.com/go-appsec/interactsh-lite@latest
```

### CLI Usage

The `interactsh-lite` command provides a standalone tool for OOB interaction detection, largely compatible with ProjectDiscovery's `interactsh-client`.

#### Basic Usage

```bash
# Generate payload and poll for interactions
interactsh-lite

# Generate multiple payloads
interactsh-lite -n 5

# Use a specific server
interactsh-lite -s alpha.oastsrv.net

# JSON output for scripting
interactsh-lite --json

# Verbose output with full request/response data
interactsh-lite -v
```

### CLI Flags

| Flag | Description |
|------|-------------|
| `-s, --server` | Interactsh server(s) to use (comma-separated) |
| `-n, --number` | Number of payloads to generate |
| `-t, --token` | Authentication token for protected servers |
| `--config` | Path to config file |
| `--poll-interval, --pi` | Poll interval in seconds (default: 5) |
| `--keep-alive-interval, --kai` | Keep-alive interval (default: 1m) |
| `--session-file, --sf` | Session file for persistence across restarts |
| `--dns-only` | Display only DNS interactions |
| `--http-only` | Display only HTTP interactions |
| `--smtp-only` | Display only SMTP interactions |
| `--ftp-only` | Display only FTP interactions |
| `--ldap-only` | Display only LDAP interactions |
| `-m, --match` | Regex pattern to include interactions |
| `-f, --filter` | Regex pattern to exclude interactions |
| `-o, --output` | Output file path |
| `--json` | Output in JSON format |
| `-v, --verbose` | Verbose output with request/response data |
| `--payload-store, --ps` | Store generated payloads to file |
| `--payload-store-file, --psf` | Payload store file path (default: interactsh_payload.txt) |
| `--health-check, --hc` | Run diagnostic checks |
| `--version` | Show version |

### Configuration File

Create `~/.config/interactsh-client/config.yaml`:

```yaml
server: "oscar.oastsrv.net,alpha.oastsrv.net,sierra.oastsrv.net,tango.oastsrv.net"
token: ""
poll-interval: 5
keep-alive-interval: 1m
json: false
verbose: false
```

CLI flags override config file values.

### CLI Examples

```bash
# Filter to show only DNS A record interactions
interactsh-lite --dns-only -v

# Match specific patterns in interactions
interactsh-lite -m "ssrf.*" -m "xxe.*"

# Save payloads to file for later use
interactsh-lite -n 10 --payload-store --payload-store-file payloads.txt

# Use session file to persist correlation ID
interactsh-lite --session-file session.yaml

# Run health check diagnostics
interactsh-lite --health-check
```

## Library

### Library Quick Start

```bash
go get github.com/go-appsec/interactsh-lite@latest
```

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/go-appsec/interactsh-lite/oobclient"
)

func main() {
    ctx := context.Background()

    // Create client with default options (uses public servers)
    client, err := oobclient.New(ctx)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Generate a unique payload domain
    payloadURL := client.Domain()
    fmt.Printf("Inject this URL in your target: %s\n", payloadURL)

    // Start polling for interactions
    err = client.StartPolling(5*time.Second, func(i *oobclient.Interaction) {
        fmt.Printf("[%s] %s from %s\n", i.Protocol, i.UniqueID, i.RemoteAddress)
    })
    if err != nil {
        log.Fatal(err)
    }

    // Wait for interactions...
    time.Sleep(60 * time.Second)

    client.StopPolling()
}
```

### Usage Examples

#### Custom Server Configuration

```go
client, err := oobclient.New(ctx, oobclient.Options{
    ServerURLs:        []string{"my-interactsh-server.example.com"},
    Token:             "my-auth-token",
    HTTPTimeout:       15 * time.Second,
    KeepAliveInterval: 30 * time.Second,
})
```

#### Session Persistence

Save and restore sessions to maintain the same correlation ID across restarts:

```go
// Save session before shutdown
if err := client.SaveSession("/tmp/session.yaml"); err != nil {
    log.Fatal(err)
}

// Later, restore the session (optionally pass opts to override behavioral settings)
client, err := oobclient.LoadSession(ctx, "/tmp/session.yaml")
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Previously generated payload URLs still work
```

#### Error Handling

```go
import "errors"

client, err := oobclient.New(ctx, opts)
if errors.Is(err, oobclient.ErrUnauthorized) {
    log.Fatal("Invalid or missing authentication token")
}

err = client.StartPolling(interval, callback)
if errors.Is(err, oobclient.ErrAlreadyPolling) {
    // Already polling, ignore
}
if errors.Is(err, oobclient.ErrClientClosed) {
    // Client was closed, need to create a new one
}
```

#### Domain / Payload Generation

```go
// Domain() returns a unique domain for each call, suitable for correlating
// specific test cases with their interactions.
url1 := client.Domain()
url2 := client.Domain()
// Example: "cn4h7pjqdka31f8e5g6b.alpha.oastsrv.net" (16-char correlation ID + 4-char nonce)
// Example: "cn4h7pjqdka31f8ekne9.alpha.oastsrv.net"
// Both share the same correlation ID prefix but have unique nonces.
```

### Migration from ProjectDiscovery/Interactsh Client

This library is a mostly drop-in replacement for the [official Interactsh](https://github.com/projectdiscovery/interactsh) client with a simplified API.

**Binary size:** If ProjectDiscovery is not already in your dependency tree, switching to `interactsh-lite` can reduce your compiled binary size by up to 20MB.

#### Import Changes

```diff
 import (
-    "github.com/projectdiscovery/interactsh/pkg/client"
-    "github.com/projectdiscovery/interactsh/pkg/server"
+    "github.com/go-appsec/interactsh-lite/oobclient"
 )
```

#### Client Creation

```diff
-opts := client.DefaultOptions
-opts.ServerURL = "oast.pro"
-c, err := client.New(opts)
+ctx := context.Background()
+c, err := oobclient.New(ctx, oobclient.Options{
+    ServerURLs: []string{"oscar.oastsrv.net", "alpha.oastsrv.net", "sierra.oastsrv.net", "tango.oastsrv.net"},
+})
```

Key differences:
- `New()` now takes a `context.Context` as the first parameter
- `ServerURL` (string) is now `ServerURLs` ([]string)

#### Payload Generation

```diff
-// GeneratePayloadURL() generated unique payload domains
-url := c.GeneratePayloadURL()
+// Domain() is now the primary method (each call returns a unique domain with a nonce)
+domain := c.Domain()
```

#### Polling for Interactions

```diff
-c.StartPolling(interval, func(i *server.Interaction) {
+c.StartPolling(interval, func(i *oobclient.Interaction) {
     fmt.Println(i.Protocol, i.RemoteAddress)
 })
```

The `Interaction` struct is compatible - all original fields are preserved, with an added `SMTPTo` field when supported by the server.

#### Closing the Client

```diff
-c.StopPolling()
-c.Close()
+c.Close()  // Automatically stops polling
```

#### Session Persistence

```diff
-c.SaveSessionTo("/path/to/session.yaml")
+c.SaveSession("/path/to/session.yaml")
```

#### Module Error Handling

```diff
-if err != nil && strings.Contains(err.Error(), "unauthorized") {
+if errors.Is(err, oobclient.ErrUnauthorized) {
     // Handle auth error
 }
```

#### Redirect Testing

Unauthenticated servers (including the hosted `*.oastsrv.net` servers) allow 302/307 redirects with a `Location` header.

Session-stored response - set at registration time, applies to all HTTP interactions on the session:

```go
client, err := oobclient.New(ctx, oobclient.Options{
    Response: &oobclient.ResponseConfig{
        StatusCode: 302,
        Headers:    []string{"Location: https://example.com/callback"},
    },
})
```

Per-URL dynamic response - encode response parameters directly in the URL. `client.EncodedResponse()` produces the same format from Go:

```
https://<correlation-id>.oastsrv.net/?status=307&header=Location:+https://target.com
```

### API Reference

#### Types

| Type | Description |
|------|-------------|
| `Client` | Main client for interacting with Interactsh servers |
| `Options` | Configuration options for client creation |
| `Interaction` | Captured OOB interaction data |
| `InteractionCallback` | Callback function type for polling |
| `ResponseConfig` | Session-stored HTTP response configured on a session |

#### Sentinel Errors

| Error | Description |
|-------|-------------|
| `ErrSessionEvicted` | Server evicted the session (correlation ID not found) |
| `ErrUnauthorized` | Invalid or missing authentication token |
| `ErrClientClosed` | Operation attempted on a closed client |
| `ErrAlreadyPolling` | StartPolling called while already polling |

## Server

The go-appsec/interactsh-lite server is a lightweight, self-hosted OOB interaction capture server, installed as `interactsh-srv`. It is API-compatible with [ProjectDiscovery/interactsh](https://github.com/projectdiscovery/interactsh). The server is a separate Go module so the client library stays dependency-minimal.

### Why go-appsec/interactsh-lite Server

The primary motivation is flexibility in how OAST domains can be structured. The reference implementation enforces specific correlation ID and nonce formats tied to the xid library. The go-appsec/interactsh-lite server decouples these: the nonce is fully controlled by the client, and the server accepts the correlation ID and nonce split or combined. This enables shorter, more memorable domain formats, including formats that are friendlier for LLM recall and usage.

Key improvements:

- **Flexible correlation IDs.** Accepts any alphanumeric correlation ID meeting the minimum length. Not xid-based, so no host identity is leaked in payload URLs sent to third-party targets. Supports shorter IDs without collision risk since xid ordering is not assumed.
- **No nonce length requirement.** The reference server hardcodes a minimum nonce length of 3. The go-appsec/interactsh-lite server accepts any nonce length, allowing clients full control over domain structure.
- **Flexible domain formats.** Because the nonce can be split out, combined, or structured differently, clients can generate domains in formats optimized for their use case (e.g., shorter URLs, LLM-friendly patterns).
- **Metrics and correctness fixes.** Fixes session count tracking, corrects metrics field spelling (`heap_allo` to `heap_alloc`, `head_idle` to `heap_idle`), and properly handles keep-alive re-registration.
- **Request size limits.** Adds `--max-request-size` to cap HTTP request body size across all endpoints, protecting against oversized payloads.
- **Defense in depth.** Interactions are encrypted at capture time rather than at poll time, reducing the window where plaintext data exists in memory. Short correlation IDs that cannot be matched are rejected at registration rather than silently accepted.

### Installation

```bash
go install github.com/go-appsec/interactsh-lite/interactsh-srv@latest
```

Or download the binary for your platform from the [latest release](https://github.com/go-appsec/interactsh-lite/releases).

### Prerequisites

Running a self-hosted interactsh server requires:

1. **A domain name** with nameservers pointing to your server's IP address.
2. **A server** (VPS or cloud VM) with a public IP address, running 24/7.

#### Domain and Nameserver Setup

Configure your domain registrar to delegate DNS to your server:

1. **Create glue records**: Add hostname entries `ns1.yourdomain.com` and `ns2.yourdomain.com` both pointing to your server's public IP.
2. **Set nameservers**: Change the domain's nameservers to `ns1.yourdomain.com` and `ns2.yourdomain.com`.

The exact steps vary by registrar. For example, on GoDaddy:
- Navigate to Domain Settings > Hostnames > Add `ns1` and `ns2` with your server IP.
- Navigate to DNS Management > Nameservers > "I'll use my own nameservers" > Enter `ns1.yourdomain.com` and `ns2.yourdomain.com`.

> **Note:** On cloud VMs (AWS EC2, GCP, Azure, etc.), update security groups or firewall rules to allow inbound traffic on the required ports (53, 80, 443, 25, 587, 465, 389, and optionally 21/990 for FTP).

### Basic Usage

Once DNS is configured, start the server:

```bash
interactsh-srv --domain yourdomain.com
```

The server auto-detects its public IP and provisions TLS certificates via ACME (Let's Encrypt). All core services (DNS, HTTP, HTTPS, SMTP, LDAP) start automatically.

### Server CLI Flags

```
INPUT:
  -d, --domain strings                 Configured domain(s) (required, comma-separated)
  -i, --ip strings                     Public IP address(es) (auto-detected if omitted)
      --listen-ip, --lip string        Bind address for all listeners (default "0.0.0.0")
  -e, --eviction int                   Eviction TTL in days (default 30)
      --no-eviction, --ne              Disable TTL-based eviction
      --eviction-strategy, --es string Eviction strategy: sliding or fixed (default "sliding")
  -a, --auth                           Enable authentication (auto-generates token if --token not set)
  -t, --token string                   Authentication token
      --acao-url string                CORS Access-Control-Allow-Origin value (default "*")
      --skip-acme, --sa                Skip ACME certificate generation
      --scan-everywhere, --se          Scan entire request for correlation IDs
      --correlation-id-length, --cidl  Correlation ID length (default 20, min 3)
      --cert string                    Custom TLS certificate file path
      --privkey string                 Custom TLS private key file path
      --origin-ip-header, --oih string HTTP header for real client IP (behind reverse proxy)
      --max-request-size, --mrs int    Max HTTP request body in MB, 0=unlimited (default 100)

CONFIG:
      --config string                  Config file path (default "~/.config/interactsh-server/config.yaml")
  -r, --resolvers strings              DNS resolvers for ACME (file path or comma-separated)
      --dynamic-resp, --dr             Enable dynamic HTTP responses
      --custom-records, --cr string    Custom DNS records YAML file
      --http-index, --hi string        Custom HTML index file
      --http-directory, --hd string    Static file directory served at /s/
      --default-http-response, --dhr   File served for all HTTP requests (highest priority)
      --disk, --ds                     Enable disk-backed storage (LevelDB)
      --disk-path, --dsp string        Disk storage directory (required with --disk)
      --server-header, --csh string    Custom Server header value
      --disable-version, --dv          Suppress X-Interactsh-Version response header

SERVICES:
      --dns-port int                   DNS server port (default 53)
      --http-port int                  HTTP server port (default 80)
      --https-port int                 HTTPS server port (default 443)
      --smtp-port int                  SMTP server port (default 25)
      --smtps-port int                 SMTPS server port (default 587)
      --smtp-autotls-port int          SMTP implicit TLS port (default 465)
      --ldap-port int                  LDAP server port (default 389)
      --ldap                           Enable LDAP full logging (requires auth)
      --wildcard, --wc                 Enable root TLD capture (requires auth)
      --ftp                            Enable FTP service (requires auth)
      --ftp-port int                   FTP server port (default 21)
      --ftps-port int                  FTPS server port (default 990)
      --ftp-dir string                 FTP root directory (temporary if not specified)

DEBUG:
      --version                        Print version and exit
      --debug                          Enable debug logging
  -v, --verbose                        Verbose interaction logging
      --enable-pprof, --ep             Enable pprof on 127.0.0.1:8086
      --health-check, --hc             Run diagnostics and exit
      --metrics                        Enable /metrics endpoint
      --disable-update-check, --duc    No-op, accepted for compatibility
```

### Server Configuration File

Create `~/.config/interactsh-server/config.yaml`. All options are shown below with their defaults:

```yaml
# Input
domain: "yourdomain.com"
# ip: "1.2.3.4"
listen-ip: "0.0.0.0"
eviction: 30
no-eviction: false
eviction-strategy: "sliding"
auth: false
token: ""
acao-url: "*"
skip-acme: false
scan-everywhere: false
correlation-id-length: 20
cert: ""
privkey: ""
origin-ip-header: ""
max-request-size: 100

# Config
resolvers: []
dynamic-resp: false
custom-records: ""
http-index: ""
http-directory: ""
default-http-response: ""
disk: false
disk-path: ""
server-header: ""
disable-version: false

# Services
dns-port: 53
http-port: 80
https-port: 443
smtp-port: 25
smtps-port: 587
smtp-autotls-port: 465
ldap-port: 389
ldap: false
wildcard: false
ftp: false
ftp-port: 21
ftps-port: 990
ftp-dir: ""

# Debug
debug: false
enable-pprof: false
metrics: false
```

CLI flags override config file values. Use `--config-update` to write the merged configuration (CLI flags + config file defaults) to disk:

```bash
interactsh-srv --domain oast.example.com --auth --metrics --config-update
```

### Server Examples

```bash
# Basic single-domain server
interactsh-srv --domain oast.example.com

# With authentication
interactsh-srv --domain oast.example.com --token my-secret-token

# Enable FTP, LDAP logging, and wildcard capture (all require auth)
interactsh-srv --domain oast.example.com --token my-secret --ftp --ldap --wildcard

# Disk-backed storage for persistence across restarts
interactsh-srv --domain oast.example.com --disk --disk-path /var/lib/interactsh

# Custom TLS certificates
interactsh-srv --domain oast.example.com --cert /path/to/cert.pem --privkey /path/to/key.pem

# Behind a reverse proxy (handle TLS externally)
interactsh-srv --domain oast.example.com --origin-ip-header X-Forwarded-For --skip-acme

# Run health check diagnostics
interactsh-srv --health-check
```

### Dynamic Responses and Redirect Testing

With `--dynamic-resp` enabled, the server supports controlled HTTP responses via query parameters and session-stored response configurations. On authenticated servers, any response content is allowed. On unauthenticated servers, only 302/307 redirects with a `Location` header are permitted - this enables redirect testing without exposing the server to arbitrary content injection.

The go-appsec hosted OAST servers (`*.oastsrv.net`) run with `--dynamic-resp` enabled, allowing unauthenticated redirect testing out of the box. See [Redirect Testing](#redirect-testing) for client usage examples.

### Migrating from ProjectDiscovery/interactsh Server

The go-appsec/interactsh-lite server is a drop-in replacement for ProjectDiscovery's `interactsh-server`. The API, wire protocol, and cryptographic model are identical.

#### CLI Flag Changes

- All flags use `--` prefix format (`--config` instead of `-config`, `--debug` instead of `-debug`)
- `--debug` and `--verbose` both control the same log level (no behavioral difference)
- `--correlation-id-nonce-length` / `--cidn` is accepted but deprecated and ignored (nonce length is now fully client-controlled)
- `--disable-update-check` / `--duc` is accepted as a no-op for compatibility
- Added `--max-request-size` / `--mrs` to limit HTTP request body size
- Added `--config-update` to write merged config to disk and exit

#### Not Supported

The following features from ProjectDiscovery/interactsh are not included. Use [ProjectDiscovery/interactsh](https://github.com/projectdiscovery/interactsh) if these are required.

- SMB interaction capture (`--smb`)
- Responder agent (`--responder`)
- Built-in update checking (`--update`)

## Terms of Service

Use of this tool and the hosted OAST service on `*.oastsrv.net` is subject to our [Terms of Service](TERMS-OF-SERVICE.md).
