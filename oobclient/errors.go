package oobclient

import "errors"

var (
	// ErrSessionEvicted indicates the server evicted the session.
	// Typically due to inactivity.
	ErrSessionEvicted = errors.New("session evicted by server")

	// ErrUnauthorized indicates invalid or missing authentication token.
	ErrUnauthorized = errors.New("unauthorized: invalid or missing token")

	// ErrClientClosed indicates an operation was attempted on a closed client.
	ErrClientClosed = errors.New("client is closed")

	// ErrAlreadyPolling indicates StartPolling was called while already polling.
	ErrAlreadyPolling = errors.New("polling already started")
)
