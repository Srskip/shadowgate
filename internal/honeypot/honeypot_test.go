package honeypot

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHandler(t *testing.T) {
	h := NewHandler(nil)

	if h == nil {
		t.Fatal("expected non-nil handler")
	}

	if h.paths == nil {
		t.Error("expected paths to be initialized")
	}

	if h.hits == nil {
		t.Error("expected hits to be initialized")
	}
}

func TestAddPath(t *testing.T) {
	h := NewHandler(nil)

	err := h.AddPath("test", "^/admin", nil)
	if err != nil {
		t.Fatalf("failed to add path: %v", err)
	}

	if len(h.paths) != 1 {
		t.Errorf("expected 1 path, got %d", len(h.paths))
	}

	if h.paths[0].Name != "test" {
		t.Errorf("expected name 'test', got %q", h.paths[0].Name)
	}
}

func TestAddPathInvalidRegex(t *testing.T) {
	h := NewHandler(nil)

	err := h.AddPath("bad", "[invalid", nil)
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestCheck(t *testing.T) {
	h := NewHandler(nil)
	h.AddPath("admin", "^/admin", nil)
	h.AddPath("git", "^/\\.git", nil)

	tests := []struct {
		path    string
		matches bool
		name    string
	}{
		{"/admin", true, "admin"},
		{"/admin/login", true, "admin"},
		{"/administrator", true, "admin"},
		{"/.git/config", true, "git"},
		{"/api/v1", false, ""},
		{"/", false, ""},
		{"/public/admin.css", false, ""},
	}

	for _, tc := range tests {
		req := httptest.NewRequest("GET", tc.path, nil)
		p := h.Check(req)

		if tc.matches && p == nil {
			t.Errorf("expected %q to match, but didn't", tc.path)
		}

		if !tc.matches && p != nil {
			t.Errorf("expected %q not to match, but matched %q", tc.path, p.Name)
		}

		if tc.matches && p != nil && p.Name != tc.name {
			t.Errorf("expected match name %q, got %q", tc.name, p.Name)
		}
	}
}

func TestHandle(t *testing.T) {
	h := NewHandler(nil)
	h.AddPath("admin", "^/admin", nil)

	req := httptest.NewRequest("GET", "/admin", nil)
	rr := httptest.NewRecorder()

	path := h.Check(req)
	if path == nil {
		t.Fatal("expected path match")
	}

	h.Handle(rr, req, path, "10.0.0.1")

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}

	if rr.Body.String() != "404 page not found" {
		t.Errorf("unexpected body: %q", rr.Body.String())
	}
}

func TestRecordHit(t *testing.T) {
	h := NewHandler(nil)
	h.AddPath("admin", "^/admin", nil)

	req := httptest.NewRequest("GET", "/admin", nil)
	rr := httptest.NewRecorder()
	path := h.Check(req)

	// Record multiple hits
	h.Handle(rr, req, path, "10.0.0.1")
	h.Handle(rr, req, path, "10.0.0.1")
	h.Handle(rr, req, path, "10.0.0.2")

	stats := h.GetStats()

	adminStats := stats["admin"]
	if adminStats == nil {
		t.Fatal("expected admin stats")
	}

	if adminStats.Count != 3 {
		t.Errorf("expected 3 hits, got %d", adminStats.Count)
	}

	if adminStats.IPs["10.0.0.1"] != 2 {
		t.Errorf("expected 2 hits from 10.0.0.1, got %d", adminStats.IPs["10.0.0.1"])
	}

	if adminStats.IPs["10.0.0.2"] != 1 {
		t.Errorf("expected 1 hit from 10.0.0.2, got %d", adminStats.IPs["10.0.0.2"])
	}

	if adminStats.FirstSeen.IsZero() {
		t.Error("expected FirstSeen to be set")
	}

	if adminStats.LastSeen.IsZero() {
		t.Error("expected LastSeen to be set")
	}
}

func TestGetStatsReturnsCopy(t *testing.T) {
	h := NewHandler(nil)
	h.AddPath("test", "^/test", nil)

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	path := h.Check(req)
	h.Handle(rr, req, path, "10.0.0.1")

	stats1 := h.GetStats()
	stats2 := h.GetStats()

	// Modify stats1
	stats1["test"].Count = 999

	// stats2 should be unaffected
	if stats2["test"].Count == 999 {
		t.Error("GetStats should return a copy, not the original")
	}
}

func TestDefaultPaths(t *testing.T) {
	paths := DefaultPaths()

	if len(paths) == 0 {
		t.Fatal("expected default paths")
	}

	// Check a few expected paths exist
	found := map[string]bool{
		"admin-panel": false,
		"wp-admin":    false,
		"phpmyadmin":  false,
		"git-exposed": false,
	}

	for _, p := range paths {
		if _, ok := found[p.Name]; ok {
			found[p.Name] = true
		}
	}

	for name, exists := range found {
		if !exists {
			t.Errorf("expected default path %q not found", name)
		}
	}
}

func TestDefaultPathsPatternValidity(t *testing.T) {
	h := NewHandler(nil)

	for _, p := range DefaultPaths() {
		err := h.AddPath(p.Name, p.Pattern, nil)
		if err != nil {
			t.Errorf("default path %q has invalid pattern: %v", p.Name, err)
		}
	}
}

func TestCheckNoMatchEmptyPaths(t *testing.T) {
	h := NewHandler(nil)

	req := httptest.NewRequest("GET", "/anything", nil)
	p := h.Check(req)

	if p != nil {
		t.Error("expected no match with empty paths")
	}
}
