package oobclient

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rs/xid"
	"gopkg.in/yaml.v3"
)

// zbase32Encoding uses the zbase32 alphabet, avoiding visually similar characters for human readability.
var zbase32Encoding = base32.NewEncoding("ybndrfg8ejkmcpqxot1uwisza345h769").WithPadding(base32.NoPadding)

const rsaKeySize = 2048

type clientState int

const (
	stateIdle clientState = iota
	statePolling
	stateClosed
)

// InteractionCallback is invoked for each received interaction.
// Callbacks may be invoked concurrently and should not block for extended periods.
type InteractionCallback func(*Interaction)

// Client communicates with an interactsh server to capture OOB interactions.
// A Client is safe for concurrent use by multiple goroutines.
//
// The typical lifecycle of a Client is:
//  1. Create with New() or LoadSession()
//  2. Generate payload URLs with URL()
//  3. Start polling with StartPolling()
//  4. Process interactions via callback
//  5. Stop polling with StopPolling() (optional, Close() will stop it)
//  6. Close with Close()
type Client struct {
	mu sync.RWMutex

	// Immutable after creation
	serverURL                *url.URL
	correlationID            string
	secretKey                string
	token                    string
	privateKey               *rsa.PrivateKey
	publicKey                *rsa.PublicKey
	publicKeyB64             string
	httpClient               *http.Client
	correlationIDNonceLength int

	// Mutable state (protected by mu)
	state               clientState
	pollCancel          context.CancelFunc
	keepAliveCancel     context.CancelFunc
	keepAliveInterval   time.Duration
	disableHTTPFallback bool
}

// New creates and registers a new client with an interactsh server.
// The context controls the timeout/cancellation of the registration request.
//
// If opts is nil, DefaultOptions is used. The client will try servers from
// opts.ServerURLs in random order until one successfully accepts the registration.
// If HTTPS fails and DisableHTTPFallback is false, HTTP will be attempted as a fallback.
//
// Returns an error if registration fails with all configured servers.
// Use errors.Is() to check for specific error conditions like ErrUnauthorized.
func New(ctx context.Context, opts *Options) (*Client, error) {
	if opts == nil {
		opts = &DefaultOptions
	}

	serverURLs := opts.ServerURLs
	if len(serverURLs) == 0 {
		serverURLs = DefaultOptions.ServerURLs
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpTimeout := opts.HTTPTimeout
		if httpTimeout == 0 {
			httpTimeout = DefaultOptions.HTTPTimeout
		}
		httpClient = newSecureHTTPClient(httpTimeout)
	}

	correlationIDLength := opts.CorrelationIdLength
	if correlationIDLength == 0 {
		correlationIDLength = DefaultOptions.CorrelationIdLength
	}
	correlationIDNonceLength := opts.CorrelationIdNonceLength
	if correlationIDNonceLength == 0 {
		correlationIDNonceLength = DefaultOptions.CorrelationIdNonceLength
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	publicKeyB64, err := encodePublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}

	correlationID := xid.New().String()
	if len(correlationID) > correlationIDLength {
		correlationID = correlationID[:correlationIDLength]
	}
	secretKey := generateUUID4()

	client := &Client{
		correlationID:            correlationID,
		secretKey:                secretKey,
		token:                    opts.Token,
		privateKey:               privateKey,
		publicKey:                &privateKey.PublicKey,
		publicKeyB64:             publicKeyB64,
		keepAliveInterval:        opts.KeepAliveInterval,
		disableHTTPFallback:      opts.DisableHTTPFallback,
		httpClient:               httpClient,
		correlationIDNonceLength: correlationIDNonceLength,
		state:                    stateIdle,
	}

	if err := client.tryRegisterServers(ctx, serverURLs); err != nil {
		return nil, err
	}

	if client.keepAliveInterval > 0 {
		client.startKeepAlive()
	}

	return client, nil
}

// tryRegisterServers attempts registration with servers in random order.
func (c *Client) tryRegisterServers(ctx context.Context, serverURLs []string) error {
	shuffled := slices.Clone(serverURLs)
	shuffleStrings(shuffled)

	var errs []error
	for _, server := range shuffled {
		if err := c.tryRegisterServer(ctx, server); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", server, err))
			continue
		}
		return nil
	}

	return fmt.Errorf("failed to register with any server: %w", errors.Join(errs...))
}

// tryRegisterServer attempts registration with a single server.
func (c *Client) tryRegisterServer(ctx context.Context, server string) error {
	serverURL := server
	if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
		serverURL = "https://" + server
	}

	parsed, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}

	// Try HTTPS first, fall back to HTTP if allowed
	if err := c.performRegistration(ctx, parsed); err != nil {
		if c.disableHTTPFallback || parsed.Scheme != "https" {
			return err
		}
		parsed.Scheme = "http"
		if err := c.performRegistration(ctx, parsed); err != nil {
			return err
		}
	}

	c.serverURL = parsed
	return nil
}

// performRegistration sends the registration request to the server.
func (c *Client) performRegistration(ctx context.Context, serverURL *url.URL) error {
	reqBody := registerRequest{
		PublicKey:     c.publicKeyB64,
		SecretKey:     c.secretKey,
		CorrelationID: c.correlationID,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal registration request: %w", err)
	}

	regURL := serverURL.String() + "/register"
	req, err := http.NewRequestWithContext(ctx, "POST", regURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(data))
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("registration request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode registration response: %w", err)
	}

	if msg, ok := response["message"].(string); !ok || msg != "registration successful" {
		return fmt.Errorf("unexpected registration response: %v", response)
	}
	return nil
}

// startKeepAlive starts a background goroutine that periodically re-registers.
func (c *Client) startKeepAlive() {
	ctx, cancel := context.WithCancel(context.Background())
	c.keepAliveCancel = cancel

	go func() {
		ticker := time.NewTicker(c.keepAliveInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.mu.RLock()
				if c.state == stateClosed {
					c.mu.RUnlock()
					return
				}
				c.mu.RUnlock()

				// Silently attempt re-registration
				_ = c.performRegistration(context.Background(), c.serverURL)
			}
		}
	}()
}

// Domain returns the base interaction domain (correlation-id + server host).
// Static for the client's lifetime. Example: "ck9jfz4x6o1s3d8w2yzn.oast.pro"
//
// Use directly for DNS lookups or as a base for URLs.
// For unique URLs per test case, use URL() instead.
func (c *Client) Domain() string {
	return c.correlationID + "." + c.serverURL.Host
}

// URL returns a unique URL for external interaction requests.
// Each call generates a new URL with a different nonce, suitable for
// correlating specific test cases with their interactions.
//
// Example: "cn4h7pjqdka31f8e5g6bry8djt4un3h1x.oast.pro"
//
// Returns a bare domain (no scheme). Prepend http:// or https:// as needed,
// or use directly for DNS, SMTP, FTP, LDAP, etc.
func (c *Client) URL() string {
	data := make([]byte, c.correlationIDNonceLength)
	_, _ = rand.Read(data)

	nonce := zbase32Encoding.EncodeToString(data)
	if len(nonce) > c.correlationIDNonceLength {
		nonce = nonce[:c.correlationIDNonceLength]
	}

	return c.correlationID + nonce + "." + c.serverURL.Host
}

// StartPolling begins polling the server for interactions at the specified interval.
// The callback is invoked for each received interaction. Callbacks may be invoked
// concurrently from the polling goroutine.
//
// Returns ErrAlreadyPolling if polling is already active.
// Returns ErrClientClosed if the client has been closed.
func (c *Client) StartPolling(interval time.Duration, callback InteractionCallback) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch c.state {
	case statePolling:
		return ErrAlreadyPolling
	case stateClosed:
		return ErrClientClosed
	default:
		ctx, cancel := context.WithCancel(context.Background())
		c.pollCancel = cancel
		c.state = statePolling

		go c.pollLoop(ctx, interval, callback)
	}
	return nil
}

// pollLoop runs the polling loop until cancelled.
func (c *Client) pollLoop(ctx context.Context, interval time.Duration, callback InteractionCallback) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = c.pollInteractions(ctx, callback)
		}
	}
}

// pollInteractions fetches and processes interactions from the server.
func (c *Client) pollInteractions(ctx context.Context, callback InteractionCallback) error {
	pollURL := fmt.Sprintf("%s/poll?id=%s&secret=%s",
		c.serverURL.String(), c.correlationID, c.secretKey)

	req, err := http.NewRequestWithContext(ctx, "GET", pollURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create poll request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("poll request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if bytes.Contains(body, []byte("correlation-id not found")) {
			return ErrSessionEvicted
		}
		return fmt.Errorf("poll failed with status %d: %s", resp.StatusCode, string(body))
	}

	var response pollResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode poll response: %w", err)
	}

	// Process encrypted data
	for _, encData := range response.Data {
		plaintext, err := c.decryptInteraction(response.AESKey, encData)
		if err != nil {
			continue // Skip failed decryptions
		}

		var interaction Interaction
		if err := json.Unmarshal(plaintext, &interaction); err != nil {
			continue // Skip failed unmarshals
		}
		callback(&interaction)
	}

	// Process plaintext extra data
	for _, extraData := range response.Extra {
		var interaction Interaction
		if err := json.Unmarshal([]byte(extraData), &interaction); err != nil {
			continue
		}
		callback(&interaction)
	}

	// Process TLD data
	for _, tldData := range response.TLDData {
		var interaction Interaction
		if err := json.Unmarshal([]byte(tldData), &interaction); err != nil {
			continue
		}
		callback(&interaction)
	}

	return nil
}

// decryptInteraction decrypts an AES-encrypted interaction.
func (c *Client) decryptInteraction(aesKeyB64, ciphertextB64 string) ([]byte, error) {
	// Decrypt AES key using RSA-OAEP
	encryptedKey, err := base64.StdEncoding.DecodeString(aesKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode AES key: %w", err)
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.privateKey, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract IV and decrypt
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	//nolint:staticcheck // CFB required for interactsh protocol compatibility
	stream := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// StopPolling stops the polling loop.
// Returns ErrNotPolling if polling is not active.
// Returns ErrClientClosed if the client has been closed.
//
// After StopPolling returns, no more callbacks will be invoked.
// Polling can be restarted with StartPolling.
func (c *Client) StopPolling() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch c.state {
	case stateClosed:
		return ErrClientClosed
	case stateIdle:
		return ErrNotPolling
	default:
		if c.pollCancel != nil {
			c.pollCancel()
			c.pollCancel = nil
		}
		c.state = stateIdle
	}
	return nil
}

// IsPolling returns true if the client is actively polling for interactions.
func (c *Client) IsPolling() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.state == statePolling
}

// IsClosed returns true if the client has been closed.
func (c *Client) IsClosed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.state == stateClosed
}

// Close stops polling (if active) and deregisters from the server.
// After Close returns, the client cannot be reused.
//
// Close is safe to call multiple times; subsequent calls return nil.
//
// Close attempts to deregister from the server but does not return an error
// if deregistration fails (the session will eventually expire server-side).
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == stateClosed {
		return nil
	}

	if c.pollCancel != nil {
		c.pollCancel()
		c.pollCancel = nil
	}
	if c.keepAliveCancel != nil {
		c.keepAliveCancel()
		c.keepAliveCancel = nil
	}

	c.state = stateClosed

	// Best-effort deregistration (don't return error if it fails)
	_ = c.performDeregistration()

	return nil
}

// performDeregistration sends the deregistration request to the server.
func (c *Client) performDeregistration() error {
	reqBody := deregisterRequest{
		CorrelationID: c.correlationID,
		SecretKey:     c.secretKey,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	deregURL := c.serverURL.String() + "/deregister"
	req, err := http.NewRequestWithContext(context.Background(), "POST", deregURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(data))
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("deregistration failed with status %d", resp.StatusCode)
	}

	return nil
}

// SaveSession persists session credentials to a file for later restoration.
// This allows maintaining the same correlation-id across process restarts,
// which is useful for long-running tests or when you need to preserve
// the payload URLs.
//
// The file is written in YAML format and contains sensitive cryptographic keys.
// Ensure appropriate file permissions (0600 recommended).
func (c *Client) SaveSession(path string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	privateKeyDER := x509.MarshalPKCS1PrivateKey(c.privateKey)

	session := sessionInfo{
		ServerURL:     c.serverURL.String(),
		Token:         c.token,
		PrivateKey:    string(privateKeyDER),
		CorrelationID: c.correlationID,
		SecretKey:     c.secretKey,
		PublicKey:     c.publicKeyB64,
	}

	data, err := yaml.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}

	return nil
}

// LoadSession restores a client from previously saved session credentials.
// The context controls the timeout/cancellation of the re-registration request.
//
// If opts is provided, behavioral settings (KeepAliveInterval, DisableHTTPFallback,
// HTTPTimeout, CorrelationIdNonceLength) are applied. Crypto material and server URL
// are always restored from the session file.
//
// If the server still has the session, re-registration succeeds silently.
// If the session was evicted, the client re-registers with the same credentials,
// preserving the correlation-id and allowing continued use of previously
// generated payload URLs.
//
// Returns an error if the session file cannot be read, parsed, or if
// re-registration fails.
func LoadSession(ctx context.Context, path string, opts ...*Options) (*Client, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read session file: %w", err)
	}

	var session sessionInfo
	if err := yaml.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to parse session file: %w", err)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey([]byte(session.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	publicKey, err := decodePublicKey(session.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	serverURL, err := url.Parse(session.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server URL: %w", err)
	}

	// Apply options or use defaults
	httpTimeout := DefaultOptions.HTTPTimeout
	keepAliveInterval := DefaultOptions.KeepAliveInterval
	correlationIDNonceLength := DefaultOptions.CorrelationIdNonceLength
	var disableHTTPFallback bool
	var httpClient *http.Client

	if len(opts) > 0 && opts[0] != nil {
		opt := opts[0]
		if opt.HTTPTimeout > 0 {
			httpTimeout = opt.HTTPTimeout
		}
		if opt.KeepAliveInterval > 0 {
			keepAliveInterval = opt.KeepAliveInterval
		}
		if opt.CorrelationIdNonceLength > 0 {
			correlationIDNonceLength = opt.CorrelationIdNonceLength
		}
		disableHTTPFallback = opt.DisableHTTPFallback
		httpClient = opt.HTTPClient
	}

	if httpClient == nil {
		httpClient = newSecureHTTPClient(httpTimeout)
	}

	client := &Client{
		serverURL:                serverURL,
		correlationID:            session.CorrelationID,
		secretKey:                session.SecretKey,
		token:                    session.Token,
		privateKey:               privateKey,
		publicKey:                publicKey,
		publicKeyB64:             session.PublicKey,
		httpClient:               httpClient,
		correlationIDNonceLength: correlationIDNonceLength,
		keepAliveInterval:        keepAliveInterval,
		disableHTTPFallback:      disableHTTPFallback,
		state:                    stateIdle,
	}

	// Re-register with server (silently succeeds if session still exists)
	if err := client.performRegistration(ctx, serverURL); err != nil {
		return nil, fmt.Errorf("failed to re-register session: %w", err)
	}

	if client.keepAliveInterval > 0 {
		client.startKeepAlive()
	}

	return client, nil
}

// Internal types for JSON serialization

type registerRequest struct {
	PublicKey     string `json:"public-key"`
	SecretKey     string `json:"secret-key"`
	CorrelationID string `json:"correlation-id"`
}

type deregisterRequest struct {
	CorrelationID string `json:"correlation-id"`
	SecretKey     string `json:"secret-key"`
}

type pollResponse struct {
	Data    []string `json:"data"`
	Extra   []string `json:"extra"`
	AESKey  string   `json:"aes_key"`
	TLDData []string `json:"tlddata,omitempty"`
}

type sessionInfo struct {
	ServerURL     string `yaml:"server-url"`
	Token         string `yaml:"server-token"`
	PrivateKey    string `yaml:"private-key"`
	CorrelationID string `yaml:"correlation-id"`
	SecretKey     string `yaml:"secret-key"`
	PublicKey     string `yaml:"public-key"`
}

func encodePublicKey(pubKey *rsa.PublicKey) (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return base64.StdEncoding.EncodeToString(pubKeyPEM), nil
}

func decodePublicKey(data string) (*rsa.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(decoded)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPubKey, nil
}

func shuffleStrings(s []string) {
	jBytes := make([]byte, 1)
	for i := len(s) - 1; i > 0; i-- {
		_, _ = rand.Read(jBytes)
		j := int(jBytes[0]) % (i + 1)
		s[i], s[j] = s[j], s[i]
	}
}

// generateUUID4 generates a random UUID v4 string using crypto/rand.
// Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
func generateUUID4() string {
	var uuid [16]byte
	_, _ = rand.Read(uuid[:])
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}
