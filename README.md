# go-harden/interactsh-lite

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/go-harden/interactsh-lite/blob/master/LICENSE)
[![BuildStatus](https://github.com/go-harden/interactsh-lite/actions/workflows/tests-main.yml/badge.svg)](https://github.com/go-harden/interactsh-lite/actions/workflows/tests-main.yml)

A lightweight, dependency-minimal Go client for [Interactsh](https://github.com/projectdiscovery/interactsh) servers. This library provides out-of-band (OOB / OAST) interaction detection for security testing with a clean, simple API.

## Features

- Single package import (`oobclient`)
- Minimal dependencies for minimal size
- Context-aware API for cancellation and timeouts
- Thread-safe client with clear state machine
- Session persistence for long-running tests
- Compatible with public Interactsh servers and self-hosted instances
- Standalone CLI tool (`interactshlite`)

## Supported Protocols

The client can detect the following out-of-band interaction types:

| Protocol | Description |
|----------|-------------|
| DNS | A, AAAA, CNAME, MX, TXT, NS, SOA queries |
| HTTP/HTTPS | Full request and response capture |
| SMTP/SMTPS | Email interactions with MAIL FROM capture |
| LDAP | LDAP search query interactions |

## Library

### Library Quick Start

```bash
go get github.com/go-harden/interactsh-lite@latest
```

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/go-harden/interactsh-lite/oobclient"
)

func main() {
    ctx := context.Background()

    // Create client with default options (uses public servers)
    client, err := oobclient.New(ctx, nil)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Generate a unique payload URL
    payloadURL := client.URL()
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
client, err := oobclient.New(ctx, &oobclient.Options{
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

#### Base Domain vs Unique URLs

```go
// Domain() returns the base domain (static for client lifetime)
baseDomain := client.Domain()
// Example: "cn4h7pjqdka31f8e5g6b.oast.pro" (20-char correlation ID)

// URL() returns unique URLs for each test case
url1 := client.URL()
url2 := client.URL()
// Example: "cn4h7pjqdka31f8e5g6bry8djt4un3h1x.oast.pro" (20 + 13 chars)
// Example: "cn4h7pjqdka31f8e5g6bkne9wfg4a3mt1.oast.pro" (20 + 13 chars)
```

### Migration from ProjectDiscovery/Interactsh

This library is a mostly drop-in replacement for the [official Interactsh](https://github.com/projectdiscovery/interactsh) client with a simplified API.

**Binary size:** If ProjectDiscovery is not already in your dependency tree, switching to `interactsh-lite` can reduce your compiled binary size by up to 20MB.

#### Import Changes

```diff
 import (
-    "github.com/projectdiscovery/interactsh/pkg/client"
-    "github.com/projectdiscovery/interactsh/pkg/server"
+    "github.com/go-harden/interactsh-lite/oobclient"
 )
```

#### Client Creation

```diff
-opts := client.DefaultOptions
-opts.ServerURL = "oast.pro"
-c, err := client.New(opts)
+ctx := context.Background()
+c, err := oobclient.New(ctx, &oobclient.Options{
+    ServerURLs: []string{"oast.pro"},
+})
```

Key differences:
- `New()` now takes a `context.Context` as the first parameter
- `ServerURL` (string) is now `ServerURLs` ([]string)
- Pass `nil` for options to use defaults

#### Polling for Interactions

```diff
-c.StartPolling(interval, func(i *server.Interaction) {
+c.StartPolling(interval, func(i *oobclient.Interaction) {
     fmt.Println(i.Protocol, i.RemoteAddress)
 })
```

The `Interaction` struct fields are identical.

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

### API Reference

#### Types

| Type | Description |
|------|-------------|
| `Client` | Main client for interacting with Interactsh servers |
| `Options` | Configuration options for client creation |
| `Interaction` | Captured OOB interaction data |
| `InteractionCallback` | Callback function type for polling |

#### Sentinel Errors

| Error | Description |
|-------|-------------|
| `ErrSessionEvicted` | Server evicted the session (correlation ID not found) |
| `ErrUnauthorized` | Invalid or missing authentication token |
| `ErrClientClosed` | Operation attempted on a closed client |
| `ErrAlreadyPolling` | StartPolling called while already polling |
| `ErrNotPolling` | StopPolling called while not polling |

## CLI Tool

```bash
go install github.com/go-harden/interactsh-lite/cmd/interactshlite@latest
```

### CLI Usage

The `interactshlite` command provides a standalone tool for OOB interaction detection, compatible with the original `interactsh-client`.

#### Basic Usage

```bash
# Generate payload and poll for interactions
interactshlite

# Generate multiple payloads
interactshlite -n 5

# Use a specific server
interactshlite -s oast.pro

# JSON output for scripting
interactshlite --json

# Verbose output with full request/response data
interactshlite -v
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
server: "oast.fun,oast.me"
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
interactshlite --dns-only -v

# Match specific patterns in interactions
interactshlite -m "ssrf.*" -m "xxe.*"

# Save payloads to file for later use
interactshlite -n 10 --payload-store --payload-store-file payloads.txt

# Use session file to persist correlation ID
interactshlite --session-file session.yaml

# Run health check diagnostics
interactshlite --health-check
```
