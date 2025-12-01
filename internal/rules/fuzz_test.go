package rules

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// FuzzIPRule tests IP rule with fuzzed CIDR inputs
func FuzzIPRule(f *testing.F) {
	// Seed corpus with valid and edge-case inputs
	f.Add("10.0.0.0/8")
	f.Add("192.168.1.1/32")
	f.Add("0.0.0.0/0")
	f.Add("::1/128")
	f.Add("2001:db8::/32")
	f.Add("invalid")
	f.Add("")
	f.Add("10.0.0.0/33")       // invalid prefix length
	f.Add("256.256.256.256/8") // invalid octets
	f.Add("10.0.0.1")          // single IP without prefix

	f.Fuzz(func(t *testing.T, cidr string) {
		// Should not panic regardless of input
		rule, err := NewIPRule([]string{cidr}, "allow")

		if err != nil {
			// Invalid input is expected to return error
			return
		}

		if rule == nil {
			t.Error("expected non-nil rule when no error")
			return
		}

		// Rule evaluation should not panic
		ctx := &Context{
			ClientIP: "10.0.0.1",
			Request:  httptest.NewRequest("GET", "/", nil),
		}
		rule.Evaluate(ctx)
	})
}

// FuzzIPRuleEvaluate tests IP rule evaluation with fuzzed client IPs
func FuzzIPRuleEvaluate(f *testing.F) {
	// Seed with various IP formats
	f.Add("10.0.0.1")
	f.Add("192.168.1.100")
	f.Add("::1")
	f.Add("2001:db8::1")
	f.Add("")
	f.Add("not-an-ip")
	f.Add("10.0.0.1:8080")
	f.Add("256.1.1.1")

	rule, _ := NewIPRule([]string{"10.0.0.0/8", "192.168.0.0/16"}, "allow")

	f.Fuzz(func(t *testing.T, clientIP string) {
		ctx := &Context{
			ClientIP: clientIP,
			Request:  httptest.NewRequest("GET", "/", nil),
		}

		// Should not panic
		result := rule.Evaluate(ctx)

		// Result should always be valid
		if result.Reason == "" && result.Matched {
			t.Error("matched result should have a reason")
		}
	})
}

// FuzzUserAgentRule tests UA rule with fuzzed regex patterns
func FuzzUserAgentRule(f *testing.F) {
	// Seed with valid and problematic regex patterns
	f.Add("Mozilla.*")
	f.Add("(?i)nmap")
	f.Add("[a-z]+")
	f.Add(".*")
	f.Add("")
	f.Add("[invalid")           // unclosed bracket
	f.Add("(?P<name>.*)")       // named group
	f.Add("(a{1000}){1000}")    // potential ReDoS
	f.Add("\\x00")              // null byte
	f.Add("(?i)(?:a|b|c|d|e)+") // complex alternation

	f.Fuzz(func(t *testing.T, pattern string) {
		// Should not panic regardless of pattern
		rule, err := NewUARule([]string{pattern}, "whitelist")

		if err != nil {
			// Invalid regex is expected to return error
			return
		}

		if rule == nil {
			t.Error("expected non-nil rule when no error")
			return
		}

		// Evaluation should not panic
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		ctx := &Context{
			ClientIP: "10.0.0.1",
			Request:  req,
		}
		rule.Evaluate(ctx)
	})
}

// FuzzUserAgentRuleEvaluate tests UA rule evaluation with fuzzed user agents
func FuzzUserAgentRuleEvaluate(f *testing.F) {
	// Seed with various user agent strings
	f.Add("Mozilla/5.0")
	f.Add("curl/7.64.1")
	f.Add("")
	f.Add("a]b[c")       // regex metacharacters in UA
	f.Add("\x00\x01\x02") // binary data
	f.Add(string(make([]byte, 10000))) // very long string

	rule, _ := NewUARule([]string{"(?i)nmap", "(?i)nikto"}, "blacklist")

	f.Fuzz(func(t *testing.T, userAgent string) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", userAgent)

		ctx := &Context{
			ClientIP: "10.0.0.1",
			Request:  req,
		}

		// Should not panic
		rule.Evaluate(ctx)
	})
}

// FuzzPathRule tests path rule with fuzzed path patterns
func FuzzPathRule(f *testing.F) {
	// Seed with various path patterns
	f.Add("^/admin")
	f.Add(".*\\.php$")
	f.Add("/api/v[0-9]+/")
	f.Add("")
	f.Add("[invalid")
	f.Add("(?i)/ADMIN")
	f.Add("\\x00")

	f.Fuzz(func(t *testing.T, pattern string) {
		rule, err := NewPathRule([]string{pattern}, "deny")

		if err != nil {
			return
		}

		if rule == nil {
			t.Error("expected non-nil rule when no error")
			return
		}

		req := httptest.NewRequest("GET", "/api/v1/users", nil)
		ctx := &Context{
			ClientIP: "10.0.0.1",
			Request:  req,
		}
		rule.Evaluate(ctx)
	})
}

// FuzzPathRuleEvaluate tests path rule evaluation with fuzzed paths
func FuzzPathRuleEvaluate(f *testing.F) {
	// Seed with various URL paths
	f.Add("/api/v1")
	f.Add("/admin")
	f.Add("/")
	f.Add("")
	f.Add("/../../../etc/passwd")
	f.Add("/path?query=value")
	f.Add("/path#fragment")
	f.Add(string(make([]byte, 10000))) // very long path

	rule, _ := NewPathRule([]string{"^/admin", "^/debug"}, "deny")

	f.Fuzz(func(t *testing.T, path string) {
		req := httptest.NewRequest("GET", "/", nil)
		req.URL.Path = path

		ctx := &Context{
			ClientIP: "10.0.0.1",
			Request:  req,
		}

		// Should not panic
		rule.Evaluate(ctx)
	})
}

// FuzzMethodRule tests method rule with fuzzed HTTP methods
func FuzzMethodRule(f *testing.F) {
	f.Add("GET")
	f.Add("POST")
	f.Add("PUT")
	f.Add("DELETE")
	f.Add("")
	f.Add("INVALID")
	f.Add("get")
	f.Add(string(make([]byte, 1000)))

	rule, _ := NewMethodRule([]string{"GET", "POST"}, "allow")

	f.Fuzz(func(t *testing.T, method string) {
		req := &http.Request{
			Method: method,
		}

		ctx := &Context{
			ClientIP: "10.0.0.1",
			Request:  req,
		}

		// Should not panic
		rule.Evaluate(ctx)
	})
}

// FuzzHeaderRule tests header rule with fuzzed header values
func FuzzHeaderRule(f *testing.F) {
	f.Add("X-Custom-Header", "value")
	f.Add("Authorization", "Bearer token123")
	f.Add("", "")
	f.Add("X-Test", string(make([]byte, 10000)))
	f.Add("\x00\x01", "binary")

	rule, _ := NewHeaderRule("X-Custom-Header", []string{".*"}, false, "allow")

	f.Fuzz(func(t *testing.T, headerName, headerValue string) {
		req := httptest.NewRequest("GET", "/", nil)
		if headerName != "" {
			req.Header.Set(headerName, headerValue)
		}

		ctx := &Context{
			ClientIP: "10.0.0.1",
			Request:  req,
		}

		// Should not panic
		rule.Evaluate(ctx)
	})
}

// FuzzRateLimitRule tests rate limit rule with rapid requests
func FuzzRateLimitRule(f *testing.F) {
	f.Add("10.0.0.1")
	f.Add("192.168.1.100")
	f.Add("")
	f.Add("::1")
	f.Add("invalid-ip")

	f.Fuzz(func(t *testing.T, clientIP string) {
		rule := NewRateLimitRule(10, 1000000000) // 10 requests per second

		ctx := &Context{
			ClientIP: clientIP,
			Request:  httptest.NewRequest("GET", "/", nil),
		}

		// Should not panic even with many requests
		for i := 0; i < 100; i++ {
			rule.Evaluate(ctx)
		}
	})
}
