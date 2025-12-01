package listener

import (
	"context"
	"net/http"
)

// Listener represents a network listener that accepts connections
type Listener interface {
	// Start begins accepting connections
	Start(ctx context.Context) error
	// Stop gracefully shuts down the listener
	Stop(ctx context.Context) error
	// Addr returns the listener address
	Addr() string
}

// Handler processes incoming requests and returns an action
type Handler interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// RequestContext contains metadata about the incoming request
type RequestContext struct {
	ClientIP  string
	TLSInfo   *TLSInfo
	ProfileID string
}

// TLSInfo contains TLS connection metadata
type TLSInfo struct {
	Version     uint16
	CipherSuite uint16
	ServerName  string
}
