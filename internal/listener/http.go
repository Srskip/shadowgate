package listener

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// HTTPListener handles HTTP/HTTPS connections
type HTTPListener struct {
	addr       string
	tlsConfig  *tls.Config
	handler    http.Handler
	server     *http.Server
	listener   net.Listener
}

// HTTPListenerConfig configures the HTTP listener
type HTTPListenerConfig struct {
	Addr      string
	TLSConfig *tls.Config
	Handler   http.Handler
}

// NewHTTPListener creates a new HTTP/HTTPS listener
func NewHTTPListener(cfg HTTPListenerConfig) *HTTPListener {
	return &HTTPListener{
		addr:      cfg.Addr,
		tlsConfig: cfg.TLSConfig,
		handler:   cfg.Handler,
	}
}

// Start begins accepting HTTP connections
func (l *HTTPListener) Start(ctx context.Context) error {
	var err error
	l.listener, err = net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", l.addr, err)
	}

	l.server = &http.Server{
		Handler:           l.handler,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	if l.tlsConfig != nil {
		l.server.TLSConfig = l.tlsConfig
		l.listener = tls.NewListener(l.listener, l.tlsConfig)
	}

	go func() {
		if err := l.server.Serve(l.listener); err != nil && err != http.ErrServerClosed {
			// Log error but don't crash
			fmt.Printf("HTTP server error: %v\n", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the HTTP listener
func (l *HTTPListener) Stop(ctx context.Context) error {
	if l.server == nil {
		return nil
	}
	return l.server.Shutdown(ctx)
}

// Addr returns the listener address (actual bound address if available)
func (l *HTTPListener) Addr() string {
	if l.listener != nil {
		return l.listener.Addr().String()
	}
	return l.addr
}

// LoadTLSConfig loads TLS configuration from cert and key files
func LoadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}, nil
}
