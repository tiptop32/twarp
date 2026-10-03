// Package singbox defines the sing-box configuration fragments used by twarp.
package singbox

// Outbound describes a sing-box outbound connection.
type Outbound struct {
	Type           string       `json:"type"`
	Tag            string       `json:"tag"`
	Server         string       `json:"server,omitempty"`
	ServerPort     uint16       `json:"server_port,omitempty"`
	UUID           string       `json:"uuid,omitempty"`
	Flow           string       `json:"flow,omitempty"`
	TLS            *OutboundTLS `json:"tls,omitempty"`
	DomainResolver string       `json:"domain_resolver,omitempty"`
}

// OutboundTLS describes TLS settings for an outbound connection.
type OutboundTLS struct {
	Enabled    bool     `json:"enabled"`
	ServerName string   `json:"server_name,omitempty"`
	UTLS       *UTLS    `json:"utls,omitempty"`
	Reality    *Reality `json:"reality,omitempty"`
}

// UTLS describes the uTLS client fingerprint.
type UTLS struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Reality describes the REALITY handshake parameters.
type Reality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id,omitempty"`
}
