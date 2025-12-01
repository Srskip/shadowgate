package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"shadowgate/internal/config"
	"shadowgate/internal/logging"
	"shadowgate/internal/metrics"
)

func testLogger() *logging.Logger {
	l, _ := logging.New(logging.Config{Level: "error", Output: "stdout"})
	return l
}

// TestIntegrationAllowForward tests a request that passes all rules and gets forwarded
func TestIntegrationAllowForward(t *testing.T) {
	// Create a mock backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "mock")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend response"))
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
					Rule: &config.Rule{Type: "ip_allow", CIDRs: []string{"0.0.0.0/0"}},
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

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	if rr.Header().Get("X-Backend") != "mock" {
		t.Error("expected X-Backend header from mock backend")
	}

	body, _ := io.ReadAll(rr.Body)
	if string(body) != "backend response" {
		t.Errorf("unexpected body: %q", body)
	}
}

// TestIntegrationDenyDecoy tests a request that fails rules and gets decoy
func TestIntegrationDenyDecoy(t *testing.T) {
	cfg := Config{
		ProfileID: "test",
		Profile: config.ProfileConfig{
			ID: "test",
			Backends: []config.BackendConfig{
				{Name: "mock", URL: "http://127.0.0.1:59999", Weight: 10},
			},
			Rules: config.RulesConfig{
				Allow: &config.RuleGroup{
					Rule: &config.Rule{Type: "ip_allow", CIDRs: []string{"192.168.0.0/16"}},
				},
			},
			Decoy: config.DecoyConfig{
				Mode:       "static",
				Body:       "<html>Not Found</html>",
				StatusCode: 404,
			},
		},
		Logger:  testLogger(),
		Metrics: metrics.New(),
	}

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// Request from disallowed IP
	req := httptest.NewRequest("GET", "/api/data", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}

	body, _ := io.ReadAll(rr.Body)
	if string(body) != "<html>Not Found</html>" {
		t.Errorf("expected decoy response, got: %q", body)
	}
}

// TestIntegrationUserAgentBlocking tests blocking by user agent
func TestIntegrationUserAgentBlocking(t *testing.T) {
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
				Deny: &config.RuleGroup{
					Rule: &config.Rule{Type: "ua_blacklist", Patterns: []string{"(?i)nmap", "(?i)nikto"}},
				},
			},
			Decoy: config.DecoyConfig{
				Mode:       "static",
				Body:       "blocked",
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

	tests := []struct {
		userAgent string
		blocked   bool
	}{
		{"Mozilla/5.0", false},
		{"Nmap Scripting Engine", true},
		{"nikto/2.1.6", true},
		{"curl/7.64.1", false},
	}

	for _, tc := range tests {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", tc.userAgent)
		req.RemoteAddr = "10.0.0.1:12345"
		rr := httptest.NewRecorder()

		h.ServeHTTP(rr, req)

		if tc.blocked && rr.Code != http.StatusForbidden {
			t.Errorf("UA %q should be blocked, got %d", tc.userAgent, rr.Code)
		}
		if !tc.blocked && rr.Code != http.StatusOK {
			t.Errorf("UA %q should pass, got %d", tc.userAgent, rr.Code)
		}
	}
}

// TestIntegrationRateLimiting tests rate limiting functionality
func TestIntegrationRateLimiting(t *testing.T) {
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
				// Rate limit goes in Allow - when within limits, rule matches (allow passes)
				// When exceeded, rule doesn't match (allow fails -> decoy)
				Allow: &config.RuleGroup{
					Rule: &config.Rule{
						Type:        "rate_limit",
						MaxRequests: 2,
						Window:      "1s",
					},
				},
			},
			Decoy: config.DecoyConfig{
				Mode:       "static",
				Body:       "rate limited",
				StatusCode: 429,
			},
		},
		Logger:  testLogger(),
		Metrics: metrics.New(),
	}

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// First 2 requests should pass
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("request %d should pass, got %d", i+1, rr.Code)
		}
	}

	// Third request should be rate limited
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("third request should be rate limited, got %d", rr.Code)
	}
}

// TestIntegrationRedirectDecoy tests redirect decoy
func TestIntegrationRedirectDecoy(t *testing.T) {
	cfg := Config{
		ProfileID: "test",
		Profile: config.ProfileConfig{
			ID: "test",
			Backends: []config.BackendConfig{
				{Name: "mock", URL: "http://127.0.0.1:59999", Weight: 10},
			},
			Rules: config.RulesConfig{
				Allow: &config.RuleGroup{
					Rule: &config.Rule{Type: "ip_allow", CIDRs: []string{"192.168.0.0/16"}},
				},
			},
			Decoy: config.DecoyConfig{
				Mode:       "redirect",
				RedirectTo: "https://example.com",
			},
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

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}

	if rr.Header().Get("Location") != "https://example.com" {
		t.Errorf("expected redirect to example.com, got %q", rr.Header().Get("Location"))
	}
}

// TestIntegrationMethodBlocking tests HTTP method blocking
func TestIntegrationMethodBlocking(t *testing.T) {
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
				Body:       "method not allowed",
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

	tests := []struct {
		method  string
		allowed bool
	}{
		{"GET", true},
		{"POST", true},
		{"DELETE", false},
		{"PUT", false},
	}

	for _, tc := range tests {
		req := httptest.NewRequest(tc.method, "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rr := httptest.NewRecorder()

		h.ServeHTTP(rr, req)

		if tc.allowed && rr.Code != http.StatusOK {
			t.Errorf("method %s should be allowed, got %d", tc.method, rr.Code)
		}
		if !tc.allowed && rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s should be blocked, got %d", tc.method, rr.Code)
		}
	}
}

// TestIntegrationPathBlocking tests path-based blocking
func TestIntegrationPathBlocking(t *testing.T) {
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
				Deny: &config.RuleGroup{
					Rule: &config.Rule{Type: "path_deny", Paths: []string{"^/admin", "^/debug"}},
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

	tests := []struct {
		path    string
		blocked bool
	}{
		{"/api/v1", false},
		{"/admin", true},
		{"/admin/users", true},
		{"/debug/pprof", true},
		{"/public", false},
	}

	for _, tc := range tests {
		req := httptest.NewRequest("GET", tc.path, nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rr := httptest.NewRecorder()

		h.ServeHTTP(rr, req)

		if tc.blocked && rr.Code != http.StatusForbidden {
			t.Errorf("path %s should be blocked, got %d", tc.path, rr.Code)
		}
		if !tc.blocked && rr.Code != http.StatusOK {
			t.Errorf("path %s should pass, got %d", tc.path, rr.Code)
		}
	}
}

// TestIntegrationBackendFailover tests failover to healthy backend
func TestIntegrationBackendFailover(t *testing.T) {
	// Create healthy backend
	healthyBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "healthy")
		w.WriteHeader(http.StatusOK)
	}))
	defer healthyBackend.Close()

	cfg := Config{
		ProfileID: "test",
		Profile: config.ProfileConfig{
			ID: "test",
			Backends: []config.BackendConfig{
				{Name: "healthy", URL: healthyBackend.URL, Weight: 10},
			},
			Decoy: config.DecoyConfig{
				Mode:       "static",
				Body:       "error",
				StatusCode: 502,
			},
		},
		Logger:  testLogger(),
		Metrics: metrics.New(),
	}

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// Make multiple requests - all should succeed
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rr := httptest.NewRecorder()

		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, rr.Code)
		}

		if rr.Header().Get("X-Backend") != "healthy" {
			t.Errorf("request %d: expected healthy backend", i+1)
		}
	}
}

// TestIntegrationXForwardedFor tests client IP extraction from X-Forwarded-For
func TestIntegrationXForwardedFor(t *testing.T) {
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

	// Request with X-Forwarded-For from allowed IP
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "192.168.1.50")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("request with X-Forwarded-For should pass, got %d", rr.Code)
	}

	// Request with X-Forwarded-For from denied IP
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	rr = httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("request with denied X-Forwarded-For should fail, got %d", rr.Code)
	}
}

// TestIntegrationCombinedRules tests AND logic with multiple rules
func TestIntegrationCombinedRulesAND(t *testing.T) {
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
					And: []config.Rule{
						{Type: "ip_allow", CIDRs: []string{"10.0.0.0/8"}},
						{Type: "method_allow", Methods: []string{"GET"}},
					},
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

	tests := []struct {
		ip      string
		method  string
		allowed bool
	}{
		{"10.0.0.1", "GET", true},      // Both conditions pass
		{"10.0.0.1", "POST", false},    // IP ok, method fails
		{"192.168.1.1", "GET", false},  // IP fails, method ok
		{"192.168.1.1", "POST", false}, // Both fail
	}

	for _, tc := range tests {
		req := httptest.NewRequest(tc.method, "/", nil)
		req.RemoteAddr = tc.ip + ":12345"
		rr := httptest.NewRecorder()

		h.ServeHTTP(rr, req)

		if tc.allowed && rr.Code != http.StatusOK {
			t.Errorf("IP=%s method=%s should pass, got %d", tc.ip, tc.method, rr.Code)
		}
		if !tc.allowed && rr.Code != http.StatusForbidden {
			t.Errorf("IP=%s method=%s should fail, got %d", tc.ip, tc.method, rr.Code)
		}
	}
}

// TestIntegrationNoBackends tests handling when no backends are configured
func TestIntegrationNoBackends(t *testing.T) {
	cfg := Config{
		ProfileID: "test",
		Profile: config.ProfileConfig{
			ID:       "test",
			Backends: []config.BackendConfig{},
			Decoy: config.DecoyConfig{
				Mode:       "static",
				Body:       "error",
				StatusCode: 502,
			},
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

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("expected 502 with no backends, got %d", rr.Code)
	}
}

// TestIntegrationLatencyMeasurement ensures requests complete in reasonable time
func TestIntegrationLatencyMeasurement(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
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

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()

	start := time.Now()
	h.ServeHTTP(rr, req)
	elapsed := time.Since(start)

	if elapsed < 10*time.Millisecond {
		t.Errorf("expected at least 10ms latency, got %v", elapsed)
	}

	if elapsed > 1*time.Second {
		t.Errorf("request took too long: %v", elapsed)
	}
}
