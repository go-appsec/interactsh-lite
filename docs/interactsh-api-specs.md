# Interactsh Network API Specification

> Derived from [ProjectDiscovery/interactsh](https://github.com/projectdiscovery/interactsh). Current through v1.3.1.

This document specifies the network protocol for communication between interactsh clients and servers. A conforming implementation must follow these specifications exactly to ensure compatibility.

## Table of Contents

1. [Overview](#overview)
2. [Constants and Defaults](#constants-and-defaults)
3. [Cryptographic Operations](#cryptographic-operations)
4. [Server Communication Protocol](#server-communication-protocol)
5. [URL Generation](#url-generation)
6. [Data Structures](#data-structures)

---

## Overview

The interactsh protocol enables out-of-band (OOB) interaction detection:
1. A client registers with an interactsh server using RSA public key cryptography
2. The client generates unique payload URLs for OOB testing
3. The client polls the server for captured interactions
4. Interaction data is encrypted with AES-256-CTR and exchanged over JSON/HTTP(S)

---

## Constants and Defaults

### Default Values

| Constant | Default Value | Description |
|----------|---------------|-------------|
| `CorrelationIdLength` | `20` | Length of the correlation ID prefix |
| `CorrelationIdLengthMinimum` | `3` | Minimum allowed correlation ID length |
| `CorrelationIdNonceLength` | `13` | Length of the random nonce suffix |
| `CorrelationIdNonceLengthMinimum` | `3` | Minimum allowed nonce length |
| `TotalIdLength` | `33` | CorrelationIdLength + CorrelationIdNonceLength |
| `RSAKeySize` | `2048` | RSA key size in bits |
| `AESKeySize` | `32` | AES-256 key size in bytes (random bytes, not ASCII) |
| `HTTPTimeout` | `10s` | Default HTTP request timeout |
| `DefaultPollInterval` | `5s` | Default polling interval |
| `DefaultKeepAliveInterval` | `60s` | Default keep-alive re-registration interval |

### Default Server URLs

Comma-separated list of public interactsh servers:
```
oscar.oastsrv.net,alpha.oastsrv.net,sierra.oastsrv.net,tango.oastsrv.net
```

### Environment Variables

| Variable | Effect |
|----------|--------|
| `INTERACTSH_TLS_VERIFY=true` | Enforce TLS certificate verification; reject HTTP URLs |

---

## Cryptographic Operations

### RSA Key Generation

Generate a 2048-bit RSA key pair using a cryptographically secure random number generator at client initialization.

### Public Key Encoding

The public key must be encoded for transmission to the server:

1. Marshal the public key using **PKIX/X.509 SubjectPublicKeyInfo** format (ASN.1 DER)
2. Wrap in PEM block with type `RSA PUBLIC KEY`
3. Base64 encode the entire PEM block (standard encoding, with padding)

**Example encoded public key structure:**
```
base64(
  -----BEGIN RSA PUBLIC KEY-----
  <base64-encoded PKIX DER bytes>
  -----END RSA PUBLIC KEY-----
)
```

### AES Key Decryption (Client-side)

The server encrypts a 32-byte AES key using the client's RSA public key. The client must decrypt it:

```
Algorithm: RSA-OAEP
Hash: SHA-256
Label: nil (empty)
Input: base64-decoded aes_key from poll response
Output: 32-byte AES key (random bytes, not ASCII)
```

**Note:** As of v1.3.0, the server generates the AES key using `crypto/rand.Read(32 bytes)` producing arbitrary binary data. Prior versions used a truncated UUID string (`uuid.New().String()[:32]`), which produced only ASCII hex/dash characters. The client-side decryption is identical in both cases since the key arrives RSA-encrypted either way.

### Interaction Data Decryption (Client-side)

Each interaction in the `data` array is AES encrypted. Decrypt as follows:

1. Base64 decode the ciphertext
2. Extract IV: first 16 bytes (AES block size)
3. Extract ciphertext: remaining bytes after IV
4. Decrypt using AES-256-CTR mode
5. Trim trailing whitespace (`\t`, `\r`, `\n`, space) from the plaintext before JSON parsing

**Pseudocode:**
```
function decryptMessage(aesKeyEncrypted, encryptedData):
    // Step 1: Decrypt AES key using RSA-OAEP
    aesKeyBytes = base64Decode(aesKeyEncrypted)
    aesKey = rsaDecryptOAEP(SHA256, privateKey, aesKeyBytes, nil)

    // Step 2: Decode and split ciphertext
    ciphertext = base64Decode(encryptedData)
    if len(ciphertext) < 16:
        return error("ciphertext too small")

    iv = ciphertext[0:16]
    ciphertext = ciphertext[16:]

    // Step 3: Decrypt with AES-CTR
    block = newAESCipher(aesKey)
    stream = newCTR(block, iv)
    plaintext = stream.decrypt(ciphertext)

    // Step 4: Trim trailing whitespace before JSON parsing
    plaintext = trimRight(plaintext, " \t\r\n")

    return plaintext  // JSON bytes
```

---

## Server Communication Protocol

### Server URL Resolution

1. Accept comma-separated list of server domains/URLs
2. Shuffle the list and try each server until one succeeds
3. For each server:
   - If no scheme provided, prepend `https://`
   - Attempt registration
   - If HTTPS fails and HTTP fallback is enabled, retry with `http://`
   - Stop on first successful registration

### Endpoint: POST /register

Register the client with the server.

**Request:**
```http
POST /register HTTP/1.1
Host: <server>
Content-Type: application/json
Authorization: <token>  (optional, if server requires auth)
Content-Length: <length>

{
    "public-key": "<base64-encoded PEM public key>",
    "secret-key": "<UUID v4 string>",
    "correlation-id": "<alphanumeric string of CorrelationIdLength characters>"
}
```

**Success Response (200 OK):**
```json
{
    "message": "registration successful"
}
```

**Error Response (400 Bad Request):**
```json
{
    "error": "<error description>"
}
```

**Error Response (401 Unauthorized):**

Returns HTTP 401 status with an empty body. Occurs when the server requires authentication and the `Authorization` header is missing or does not match the server token.

**Validation:**
- Response must contain `"message": "registration successful"` exactly
- Any other message value is an error
- Attempting to register a correlation ID that already exists returns 400 with `"error": "correlation-id provided already exists"`

### Endpoint: GET /poll

Poll for captured interactions.

**Request:**
```http
GET /poll?id=<correlation-id>&secret=<secret-key> HTTP/1.1
Host: <server>
Authorization: <token>  (optional, if server requires auth)
```

**Query Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `id` | Yes | The correlation ID (20 characters) |
| `secret` | Yes | The secret key (UUID v4) |

**Success Response (200 OK):**
```json
{
    "data": ["<encrypted-interaction-1>", "<encrypted-interaction-2>", ...],
    "aes_key": "<base64-encoded RSA-OAEP encrypted AES key>",
    "extra": ["<unencrypted-json-1>", ...],
    "tlddata": ["<unencrypted-json-1>", ...]
}
```

**Response Fields:**
| Field | Type | Encrypted | Description |
|-------|------|-----------|-------------|
| `data` | `[]string` | Yes | AES-encrypted interaction JSON strings |
| `aes_key` | `string` | RSA-OAEP | Base64-encoded encrypted AES key |
| `extra` | `[]string` | No | Plaintext interaction JSON from token-authenticated services (FTP, SMB, Responder, LDAP with full logging) |
| `tlddata` | `[]string` | No | Plaintext interactions sent to the root domain itself (only when wildcard/root-TLD mode is enabled on the server) |

**Notes:**
- When empty, `data`, `extra`, and `tlddata` serialize as JSON `null` (nil slice), not `[]` — clients must handle both
- `aes_key` is omitted (empty string) when `data` is empty; clients must not depend on it being present when there are no interactions
- `extra` and `tlddata` may be absent
- `extra` contains unencrypted interactions from services that store data under the auth token rather than a correlation ID (FTP hooks, SMB, Responder, LDAP full-logging mode)
- `tlddata` contains interactions directed at the base domain (e.g., `alpha.oastsrv.net`) rather than a correlation-ID subdomain; these use per-consumer read offsets so each polling client receives only unseen interactions

**Error Response (400 Bad Request):**
```json
{
    "error": "<error description>"
}
```

**Error Response (401 Unauthorized):**

Returns HTTP 401 status with an empty body.

**Special Error Detection:**
- If response body contains `"could not get correlation-id from cache"`, the session has been evicted

### Endpoint: POST /deregister

Deregister and cleanup the client session.

**Request:**
```http
POST /deregister HTTP/1.1
Host: <server>
Content-Type: application/json
Authorization: <token>  (optional)
Content-Length: <length>

{
    "correlation-id": "<correlation-id>",
    "secret-key": "<secret-key>"
}
```

**Success Response (200 OK):**
```json
{
    "message": "deregistration successful"
}
```

**Error Response (400 Bad Request):**
```json
{
    "error": "<error description>"
}
```

**Error Response (401 Unauthorized):**

Returns HTTP 401 status with an empty body.

**Special Error Detection:**
- Deregistering a session that has been evicted or does not exist returns 400 with a error containing `"could not get correlation-id"`

### Endpoint: GET /metrics

Optional endpoint that returns server metrics. Only available when the server is started with the `--metrics` flag. Requires authentication if authentication is enabled.

**Request:**
```http
GET /metrics HTTP/1.1
Host: <server>
Authorization: <token>  (optional, if server requires auth)
```

**Success Response (200 OK):**
```json
{
    "dns": 0,
    "ftp": 0,
    "http": 0,
    "ldap": 0,
    "smb": 0,
    "smtp": 0,
    "sessions": 0,
    "cache": { "hit-count": 0, "miss-count": 0, "load-success-count": 0, "load-error-count": 0, "total-load-time": 0, "eviction-count": 0 },
    "memory": { "alloc": "1.2 MB", ... },
    "cpu": { "user": 0, "system": 0, "idle": 0, "nice": 0, "total": 0 },
    "network": { "received": "100 MB", "transmitted": "50 MB" }
}
```

### CORS Support

All endpoints respond to `OPTIONS` preflight requests with HTTP 204 (No Content) and CORS headers.

**CORS Response Headers (all responses):**

| Header | Value |
|--------|-------|
| `Access-Control-Allow-Origin` | Configurable (default: `*`) |
| `Access-Control-Allow-Credentials` | `true` |
| `Access-Control-Allow-Headers` | `Content-Type, Authorization` |

### Standard Response Headers

| Header | Condition | Value |
|--------|-----------|-------|
| `Server` | Always | Server domain (or custom value) |
| `X-Interactsh-Version` | Unless disabled | Server version string |
| `Content-Type` | JSON responses | `application/json; charset=utf-8` |
| `X-Content-Type-Options` | JSON responses | `nosniff` |

### Default Handler (Non-API Requests)

All HTTP requests that do not match the API endpoints (`/register`, `/poll`, `/deregister`, `/metrics`) are handled by a default handler that captures interactions and returns response data.

**Response Content-Type by Path:**

| Path Pattern | Content-Type | Response Format |
|---|---|---|
| `/robots.txt` | text/plain | `User-agent: *\nDisallow: / # <reflection>` |
| `*.json` | application/json | `{"data":"<reflection>"}` |
| `*.xml` | application/xml | `<data><reflection></data>` |
| `/s/*` | varies | Static file serving (if configured) |
| `/` (root) | text/html | Server banner page (customizable) |
| all other | text/html | `<html><head></head><body><reflection></body></html>` |

The `<reflection>` value is the character-reversed full subdomain label (the `correlationID+nonce` portion) extracted from the Host header. This allows clients to verify that the server actually received and processed the request.

**Dynamic Response Parameters (when enabled on the server):**

Requests to non-API paths can control the response via query parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `body` | string | Custom response body |
| `b64_body` | string | Base64-encoded custom response body |
| `header` | string | Custom response header (`Name:Value`), repeatable |
| `status` | int | Custom HTTP status code |
| `delay` | int | Response delay in seconds |

The path `/b64_body:<base64>/` is also supported for base64-encoded body responses.

---

## URL Generation

### Correlation ID Generation

Generate a unique correlation ID at client creation:

1. Generate a time-sortable ID of exactly `CorrelationIdLength` characters (default: 20)
2. The top 20 bits encode the current hour (`unix_seconds / 3600`) for sort ordering
3. Remaining bits are filled with `crypto/rand` random data
4. Encoded using xid-compatible base32 alphabet (`0123456789abcdefghijklmnopqrstuv`)
5. Characters must be lowercase alphanumeric (a-v, 0-9)

### Secret Key Generation

Generate a UUID v4 string:
```
Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
Example: 550e8400-e29b-41d4-a716-446655440000
```

### Domain Generation

The base domain combines the correlation ID with the server host:

```
<correlation-id>.<server-host>

Example: 7k5a3bf9m1qr.alpha.oastsrv.net
```

This value is static for the lifetime of a client session.

### Payload URL Generation

Generate unique payload URLs for OOB testing:

1. Generate random bytes of length `CorrelationIdNonceLength` (default: 13)
2. Encode using **zbase32** encoding (human-readable base32 variant)
3. Truncate to exactly `CorrelationIdNonceLength` characters
4. Concatenate: `<correlation-id><nonce>.<server-domain>`

**zbase32 Alphabet:**
```
ybndrfg8ejkmcpqxot1uwisza345h769
```

**URL Structure:**
```
<correlation-id><nonce>.<server-host>

Example: 7k5a3bf9m1qrabcdefgh.alpha.oastsrv.net
```

**Important:** The URL does NOT include a scheme (http/https). It is a bare domain suitable for:
- DNS lookups
- HTTP/HTTPS requests (prepend scheme as needed)
- SMTP, FTP, LDAP, etc.

---

## Data Structures

### Interaction Object (JSON from Server)

The decrypted interaction JSON has this structure:

```json
{
    "protocol": "http|https|dns|smtp|ftp|ldap|smb|responder",
    "unique-id": "<the unique portion of the subdomain>",
    "full-id": "<full subdomain or identifier>",
    "q-type": "<DNS query type, if protocol=dns>",
    "raw-request": "<raw request data>",
    "raw-response": "<raw response data, if any>",
    "smtp-from": "<MAIL FROM address, if protocol=smtp>",
    "remote-address": "<IP address or IP:port>",
    "timestamp": "<RFC3339 timestamp>",
}
```

### Protocol Values

| Value | Description |
|-------|-------------|
| `http` | HTTP request (plaintext) |
| `https` | HTTPS request (TLS) |
| `dns` | DNS query |
| `smtp` | SMTP connection |
| `ftp` | FTP connection |
| `ldap` | LDAP query |
| `smb` | SMB/Windows share |
| `responder` | Windows Responder interaction |

---

## Appendix: zbase32 Encoding

zbase32 is a human-oriented base32 encoding that avoids visually similar characters.

**Alphabet:** `ybndrfg8ejkmcpqxot1uwisza345h769`

**Mapping:**
```
Value:  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
Char:   y  b  n  d  r  f  g  8  e  j  k  m  c  p  q  x

Value: 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
Char:   o  t  1  u  w  i  s  z  a  3  4  5  h  7  6  9
```

**Encoding:**
1. Take input bytes
2. Process 5 bits at a time
3. Map each 5-bit value to alphabet character
4. Pad if necessary

For the client, generate `CorrelationIdNonceLength` random bytes, encode with zbase32, and truncate to `CorrelationIdNonceLength` characters.

---

## Appendix: Example Flow

```
1. Client generates:
   - RSA-2048 key pair
   - correlation-id: "ck9jfz4x6o1s3d8w2yzn" (20 chars)
   - secret-key: "550e8400-e29b-41d4-a716-446655440000"

2. Client POSTs to https://alpha.oastsrv.net/register:
   {
     "public-key": "LS0tLS1CRUdJTi...",
     "secret-key": "550e8400-e29b-41d4-a716-446655440000",
     "correlation-id": "ck9jfz4x6o1s3d8w2yzn"
   }

3. Server responds: {"message": "registration successful"}

4. Client domain: "ck9jfz4x6o1s3d8w2yzn.alpha.oastsrv.net"

5. Client generates payload URL:
   - nonce: "abcdefghijklm" (13 chars, zbase32)
   - URL: "ck9jfz4x6o1s3d8w2yznabcdefghijklm.alpha.oastsrv.net"

6. User triggers OOB interaction:
   curl http://ck9jfz4x6o1s3d8w2yznabcdefghijklm.alpha.oastsrv.net

7. Client polls GET /poll?id=ck9jfz4x6o1s3d8w2yzn&secret=550e8400...

8. Server responds:
   {
     "data": ["<base64-AES-encrypted interaction>"],
     "aes_key": "<base64-RSA-OAEP encrypted AES key>"
   }

9. Client decrypts:
   - RSA-OAEP decrypt aes_key → 32-byte AES key
   - AES-CTR decrypt data[0] → interaction JSON (trim trailing whitespace)

10. Parsed interaction:
    {
      "protocol": "http",
      "unique-id": "ck9jfz4x6o1s3d8w2yznabcdefghijklm",
      "full-id": "ck9jfz4x6o1s3d8w2yznabcdefghijklm",
      "remote-address": "203.0.113.42",
      "timestamp": "2024-01-15T10:30:00Z",
      "raw-request": "GET / HTTP/1.1\r\nHost: ...",
      "raw-response": "HTTP/1.1 200 OK\r\n..."
    }

11. On shutdown, client POSTs to /deregister
```
