package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"shadowgate/internal/config"
)

func TestHandlerAllowForward(t *testing.T) {
	// Create a test backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	cfg := Config{
		ProfileID: "test",
		Profile: config.ProfileConfig{
			Rules: config.RulesConfig{
				Allow: &config.RuleGroup{
					And: []config.Rule{
						{Type: "ip_allow", CIDRs: []string{"0.0.0.0/0"}},
					},
				},
			},
			Backends: []config.BackendConfig{
				{Name: "primary", URL: backend.URL, Weight: 10},
			},
			Decoy: config.DecoyConfig{
				Mode:       "static",
				StatusCode: 200,
				Body:       "decoy",
			},
		},
	}

	handler, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	body, _ := io.ReadAll(rr.Body)
	if string(body) != "backend response" {
		t.Errorf("expected 'backend response', got %q", string(body))
	}
}

func TestHandlerDenyDecoy(t *testing.T) {
	cfg := Config{
		ProfileID: "test",
		Profile: config.ProfileConfig{
			Rules: config.RulesConfig{
				Allow: &config.RuleGroup{
					And: []config.Rule{
						{Type: "ip_allow", CIDRs: []string{"192.168.0.0/16"}},
					},
				},
			},
			Backends: []config.BackendConfig{
				{Name: "primary", URL: "http://127.0.0.1:9999", Weight: 10},
			},
			Decoy: config.DecoyConfig{
				Mode:       "static",
				StatusCode: 200,
				Body:       "decoy response",
			},
		},
	}

	handler, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// Request from IP not in allow list
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "8.8.8.8:12345"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	body, _ := io.ReadAll(rr.Body)
	if string(body) != "decoy response" {
		t.Errorf("expected 'decoy response', got %q", string(body))
	}
}

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		expected   string
	}{
		{
			name:       "from RemoteAddr",
			remoteAddr: "192.168.1.1:12345",
			expected:   "192.168.1.1",
		},
		{
			name:       "from X-Forwarded-For",
			remoteAddr: "127.0.0.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.1, 192.168.1.1"},
			expected:   "10.0.0.1",
		},
		{
			name:       "from X-Real-IP",
			remoteAddr: "127.0.0.1:12345",
			headers:    map[string]string{"X-Real-IP": "10.0.0.2"},
			expected:   "10.0.0.2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tc.remoteAddr
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			result := extractClientIP(req)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}
