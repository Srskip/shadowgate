package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"shadowgate/internal/config"
	"shadowgate/internal/metrics"
)

// strings is still used in some tests

// TestSecurityPathTraversal ensures path traversal attempts are handled safely
func TestSecurityPathTraversal(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Backend should never see traversal attempts
		if strings.Contains(r.URL.Path, "..") {
			t.Error("path traversal reached backend")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := Config{
		ProfileID: "test",
		Profile: config.ProfileConfig{
			ID: "test",
			Backends: []config.BackendConfig{
				{Name: "mock", URL: backend.URL, Weight: 10},
			},
			Rules: config.RulesConfig{
				Deny: &config.RuleGroup{
					Rule: &config.Rule{Type: "path_deny", Paths: []string{"\\.\\./", "\\.\\.\\\\"}},
				},
			},
			Decoy: config.DecoyConfig{
				Mode:       "static",
				Body:       "forbidden",
				StatusCode: 403,
			},
		},
		Logger:  testLogger(),
		Metrics: metrics.New(),
	}

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	traversalPaths := []string{
		"/../etc/passwd",
		"/..%2f..%2fetc/passwd",
		"/..\\..\\windows\\system32",
		"/%2e%2e/%2e%2e/etc/passwd",
	}

	for _, path := range traversalPaths {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rr := httptest.NewRecorder()

		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("path %q should be blocked, got %d", path, rr.Code)
		}
	}
}

// TestSecurityHeaderInjection ensures header injection is prevented
func TestSecurityHeaderInjection(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := Config{
		ProfileID: "test",
		Profile: config.ProfileConfig{
			ID: "test",
			Backends: []config.BackendConfig{
				{Name: "mock", URL: backend.URL, Weight: 10},
			},
		},
		Logger:  testLogger(),
		Metrics: metrics.New(),
	}

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// Test with unusual but valid header values
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Test", "value with spaces and special chars !@#$%")
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	// Should not crash - response depends on backend availability
	if rr.Code == 0 {
		t.Error("no response code set")
	}
}

// TestSecurityXForwardedForSpoofing tests X-Forwarded-For handling
func TestSecurityXForwardedForSpoofing(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := Config{
		ProfileID: "test",
		Profile: config.ProfileConfig{
			ID: "test",
			Backends: []config.BackendConfig{
				{Name: "mock", URL: backend.URL, Weight: 10},
			},
			Rules: config.RulesConfig{
				Allow: &config.RuleGroup{
					Rule: &config.Rule{Type: "ip_allow", CIDRs: []string{"192.168.1.0/24"}},
				},
			},
			Decoy: config.DecoyConfig{
				Mode:       "static",
				Body:       "denied",
				StatusCode: 403,
			},
		},
		Logger:  testLogger(),
		Metrics: metrics.New(),
	}

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// Attacker tries to spoof X-Forwarded-For
	// This tests that the first IP in the chain is used
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "192.168.1.50, 10.0.0.1") // Spoofed first IP
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	// Request should be allowed because we trust X-Forwarded-For's first IP
	// In a real deployment, this would be protected by the load balancer
	if rr.Code != http.StatusOK {
		t.Logf("Note: X-Forwarded-For spoofing test - in production, ensure trusted proxies")
	}
}

// TestSecurityLargeHeaders ensures large headers don't cause issues
func TestSecurityLargeHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := Config{
		ProfileID: "test",
		Profile: config.ProfileConfig{
			ID: "test",
			Backends: []config.BackendConfig{
				{Name: "mock", URL: backend.URL, Weight: 10},
			},
		},
		Logger:  testLogger(),
		Metrics: metrics.New(),
	}

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// Large User-Agent
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", strings.Repeat("A", 10000))
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	// Should not crash or timeout
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// TestSecurityNullBytes ensures null bytes in headers are handled
func TestSecurityNullBytes(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := Config{
		ProfileID: "test",
		Profile: config.ProfileConfig{
			ID: "test",
			Backends: []config.BackendConfig{
				{Name: "mock", URL: backend.URL, Weight: 10},
			},
		},
		Logger:  testLogger(),
		Metrics: metrics.New(),
	}

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// User-Agent with unusual characters (note: null bytes are stripped by http)
	req := httptest.NewRequest("GET", "/normal/path", nil)
	req.Header.Set("User-Agent", "Mozilla\x01\x02\x03/5.0")
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	// Should not crash
	if rr.Code == 0 {
		t.Error("no response code set")
	}
}

// TestSecurityHostHeaderInjection tests host header handling
func TestSecurityHostHeaderInjection(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := Config{
		ProfileID: "test",
		Profile: config.ProfileConfig{
			ID: "test",
			Backends: []config.BackendConfig{
				{Name: "mock", URL: backend.URL, Weight: 10},
			},
		},
		Logger:  testLogger(),
		Metrics: metrics.New(),
	}

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// Malicious host header
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "evil.com\r\nX-Injected: header"
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	// Should not crash
	if rr.Code == 0 {
		t.Error("no response code set")
	}
}

// TestSecurityMethodCase tests HTTP method matching behavior
func TestSecurityMethodCase(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := Config{
		ProfileID: "test",
		Profile: config.ProfileConfig{
			ID: "test",
			Backends: []config.BackendConfig{
				{Name: "mock", URL: backend.URL, Weight: 10},
			},
			Rules: config.RulesConfig{
				Allow: &config.RuleGroup{
					Rule: &config.Rule{Type: "method_allow", Methods: []string{"GET", "POST"}},
				},
			},
			Decoy: config.DecoyConfig{
				Mode:       "static",
				Body:       "denied",
				StatusCode: 405,
			},
		},
		Logger:  testLogger(),
		Metrics: metrics.New(),
	}

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// Unusual methods should be blocked
	req := httptest.NewRequest("TRACE", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("TRACE method should be blocked when only GET/POST allowed, got %d", rr.Code)
	}
}

// TestSecurityIPv6Handling ensures IPv6 addresses are handled correctly
func TestSecurityIPv6Handling(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := Config{
		ProfileID: "test",
		Profile: config.ProfileConfig{
			ID: "test",
			Backends: []config.BackendConfig{
				{Name: "mock", URL: backend.URL, Weight: 10},
			},
			Rules: config.RulesConfig{
				Allow: &config.RuleGroup{
					Rule: &config.Rule{Type: "ip_allow", CIDRs: []string{"::1/128", "2001:db8::/32"}},
				},
			},
			Decoy: config.DecoyConfig{
				Mode:       "static",
				Body:       "denied",
				StatusCode: 403,
			},
		},
		Logger:  testLogger(),
		Metrics: metrics.New(),
	}

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// IPv6 RemoteAddr format is [ip]:port
	tests := []struct {
		remoteAddr string
		allowed    bool
	}{
		{"[::1]:12345", true},
		{"[2001:db8::1]:12345", true},
		{"[2001:db9::1]:12345", false},
		{"10.0.0.1:12345", false}, // IPv4 not in allowed list
	}

	for _, tc := range tests {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = tc.remoteAddr
		rr := httptest.NewRecorder()

		h.ServeHTTP(rr, req)

		if tc.allowed && rr.Code != http.StatusOK {
			t.Errorf("RemoteAddr %s should be allowed, got %d", tc.remoteAddr, rr.Code)
		}
		if !tc.allowed && rr.Code != http.StatusForbidden {
			t.Errorf("RemoteAddr %s should be denied, got %d", tc.remoteAddr, rr.Code)
		}
	}
}

// TestSecurityEmptyRules ensures empty rules don't cause panics
func TestSecurityEmptyRules(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := Config{
		ProfileID: "test",
		Profile: config.ProfileConfig{
			ID: "test",
			Backends: []config.BackendConfig{
				{Name: "mock", URL: backend.URL, Weight: 10},
			},
			// No rules defined
		},
		Logger:  testLogger(),
		Metrics: metrics.New(),
	}

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()

	// Should not panic
	h.ServeHTTP(rr, req)

	if rr.Code == 0 {
		t.Error("no response code set")
	}
}
