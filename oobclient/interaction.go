package oobclient

import "time"

// Interaction represents a captured OOB interaction from the server.
type Interaction struct {
	// Protocol identifies the type of interaction.
	// Values: "http", "dns", "smtp", "ftp", "ldap", "smb", "responder"
	Protocol string `json:"protocol"`

	// UniqueID is the subdomain portion matching correlation-id + nonce.
	UniqueID string `json:"unique-id"`

	// FullId is the complete identifier including any subdomain prefixes.
	FullId string `json:"full-id"`

	// QType is the DNS query type, populated only when Protocol is "dns".
	// Values: "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"
	QType string `json:"q-type,omitempty"`

	// RawRequest contains the raw request data captured by the server.
	// For HTTP, this includes headers and body. For DNS, the query details.
	RawRequest string `json:"raw-request,omitempty"`

	// RawResponse is the raw response data, if applicable.
	RawResponse string `json:"raw-response,omitempty"`

	// SMTPFrom is the MAIL FROM address. Only for "smtp" protocol.
	SMTPFrom string `json:"smtp-from,omitempty"`

	// RemoteAddress is the client IP or IP:port that made the interaction.
	RemoteAddress string `json:"remote-address"`

	// Timestamp is when the server captured the interaction.
	Timestamp time.Time `json:"timestamp"`
}
