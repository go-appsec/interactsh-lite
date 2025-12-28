package oobclient

import "errors"

// Sentinel errors for common failure conditions.
// Use errors.Is() to check for these conditions.
var (
	// ErrSessionEvicted indicates the server evicted the session (correlation-id not found).
	// This typically happens when the session expires due to inactivity.
	ErrSessionEvicted = errors.New("session evicted by server")

	// ErrUnauthorized indicates invalid or missing authentication token.
	// This occurs when the server requires authentication and the provided token is invalid.
	ErrUnauthorized = errors.New("unauthorized: invalid or missing token")

	// ErrClientClosed indicates an operation was attempted on a closed client.
	// After Close() is called, the client cannot be reused.
	ErrClientClosed = errors.New("client is closed")

	// ErrAlreadyPolling indicates StartPolling was called while already polling.
	// Call StopPolling first before starting a new polling loop.
	ErrAlreadyPolling = errors.New("polling already started")

	// ErrNotPolling indicates StopPolling was called while not polling.
	ErrNotPolling = errors.New("polling not started")
)
