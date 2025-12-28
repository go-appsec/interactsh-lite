package oobclient

import "time"

// Interaction represents a captured OOB interaction from the server.
// Each interaction contains details about an external request that was
// captured by the interactsh server when a payload URL was accessed.
type Interaction struct {
	// Protocol identifies the type of interaction.
	// Values: "http", "dns", "smtp", "ftp", "ldap", "smb", "responder"
	Protocol string `json:"protocol"`

	// UniqueID is the unique portion of the subdomain that triggered this interaction.
	// This matches the correlation-id + nonce from URL().
	UniqueID string `json:"unique-id"`

	// FullID is the complete identifier (e.g., full subdomain including any prefixes).
	FullID string `json:"full-id"`

	// QType is the DNS query type, populated only when Protocol is "dns".
	// Values: "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"
	QType string `json:"q-type,omitempty"`

	// RawRequest contains the raw request data captured by the server.
	// For HTTP, this includes headers and body. For DNS, the query details.
	RawRequest string `json:"raw-request,omitempty"`

	// RawResponse contains the raw response data sent by the server, if applicable.
	RawResponse string `json:"raw-response,omitempty"`

	// SMTPFrom is the MAIL FROM address, populated only when Protocol is "smtp".
	SMTPFrom string `json:"smtp-from,omitempty"`

	// RemoteAddress is the client IP address or IP:port that made the interaction.
	RemoteAddress string `json:"remote-address"`

	// Timestamp is when the interaction was captured by the server.
	Timestamp time.Time `json:"timestamp"`

	// AsnInfo contains optional ASN enrichment data for the remote address,
	// including geographic and organizational info (asn, country, org, IP range).
	AsnInfo []map[string]string `json:"asninfo,omitempty"`
}
