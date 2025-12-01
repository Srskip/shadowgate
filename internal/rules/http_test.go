package rules

import (
	"net/http/httptest"
	"testing"
)

func TestMethodRule(t *testing.T) {
	rule, err := NewMethodRule([]string{"GET", "POST"}, "allow")
	if err != nil {
		t.Fatalf("failed to create rule: %v", err)
	}

	tests := []struct {
		method  string
		matched bool
	}{
		{"GET", true},
		{"POST", true},
		{"DELETE", false},
		{"PUT", false},
	}

	for _, tc := range tests {
		req := httptest.NewRequest(tc.method, "/", nil)
		ctx := &Context{Request: req}
		result := rule.Evaluate(ctx)
		if result.Matched != tc.matched {
			t.Errorf("method %s: expected matched=%v, got %v", tc.method, tc.matched, result.Matched)
		}
	}
}

func TestPathRule(t *testing.T) {
	rule, err := NewPathRule([]string{"^/api/.*", "^/admin"}, "deny")
	if err != nil {
		t.Fatalf("failed to create rule: %v", err)
	}

	tests := []struct {
		path    string
		matched bool
	}{
		{"/api/users", true},
		{"/api/v1/data", true},
		{"/admin", true},
		{"/admin/login", true},
		{"/public", false},
		{"/", false},
	}

	for _, tc := range tests {
		req := httptest.NewRequest("GET", tc.path, nil)
		ctx := &Context{Request: req}
		result := rule.Evaluate(ctx)
		if result.Matched != tc.matched {
			t.Errorf("path %s: expected matched=%v, got %v", tc.path, tc.matched, result.Matched)
		}
	}
}

func TestHeaderRule(t *testing.T) {
	// Test header presence required
	rule, err := NewHeaderRule("Authorization", nil, true, "allow")
	if err != nil {
		t.Fatalf("failed to create rule: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	ctx := &Context{Request: req}
	result := rule.Evaluate(ctx)
	if result.Matched {
		t.Error("expected not matched when required header is missing")
	}

	req.Header.Set("Authorization", "Bearer token")
	result = rule.Evaluate(ctx)
	if !result.Matched {
		t.Error("expected matched when required header is present")
	}

	// Test header value pattern
	rule2, _ := NewHeaderRule("Content-Type", []string{"application/json"}, false, "allow")
	req2 := httptest.NewRequest("POST", "/", nil)
	req2.Header.Set("Content-Type", "application/json")
	ctx2 := &Context{Request: req2}
	result2 := rule2.Evaluate(ctx2)
	if !result2.Matched {
		t.Error("expected matched for matching content-type")
	}
}
