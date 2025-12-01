package rules

import (
	"net/http/httptest"
	"testing"
)

func TestIPRuleAllow(t *testing.T) {
	rule, err := NewIPRule([]string{"10.0.0.0/8", "192.168.1.0/24"}, "allow")
	if err != nil {
		t.Fatalf("failed to create rule: %v", err)
	}

	tests := []struct {
		ip      string
		matched bool
	}{
		{"10.1.2.3", true},
		{"192.168.1.100", true},
		{"8.8.8.8", false},
		{"192.168.2.1", false},
	}

	for _, tc := range tests {
		ctx := &Context{ClientIP: tc.ip}
		result := rule.Evaluate(ctx)
		if result.Matched != tc.matched {
			t.Errorf("IP %s: expected matched=%v, got %v", tc.ip, tc.matched, result.Matched)
		}
	}
}

func TestIPRuleSingleIP(t *testing.T) {
	rule, err := NewIPRule([]string{"192.168.1.1"}, "allow")
	if err != nil {
		t.Fatalf("failed to create rule: %v", err)
	}

	ctx := &Context{ClientIP: "192.168.1.1"}
	result := rule.Evaluate(ctx)
	if !result.Matched {
		t.Error("expected single IP to match")
	}

	ctx = &Context{ClientIP: "192.168.1.2"}
	result = rule.Evaluate(ctx)
	if result.Matched {
		t.Error("expected different IP not to match")
	}
}

func TestUARuleWhitelist(t *testing.T) {
	rule, err := NewUARule([]string{".*Chrome.*", ".*Firefox.*"}, "whitelist")
	if err != nil {
		t.Fatalf("failed to create rule: %v", err)
	}

	tests := []struct {
		ua      string
		matched bool
	}{
		{"Mozilla/5.0 Chrome/91.0", true},
		{"Mozilla/5.0 Firefox/89.0", true},
		{"curl/7.68.0", false},
		{"python-requests/2.25.1", false},
	}

	for _, tc := range tests {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", tc.ua)
		ctx := &Context{Request: req}
		result := rule.Evaluate(ctx)
		if result.Matched != tc.matched {
			t.Errorf("UA %q: expected matched=%v, got %v", tc.ua, tc.matched, result.Matched)
		}
	}
}

func TestUARuleBlacklist(t *testing.T) {
	rule, err := NewUARule([]string{".*curl.*", ".*python.*"}, "blacklist")
	if err != nil {
		t.Fatalf("failed to create rule: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "curl/7.68.0")
	ctx := &Context{Request: req}
	result := rule.Evaluate(ctx)
	if !result.Matched {
		t.Error("expected curl to match blacklist")
	}
}

func TestEvaluatorAND(t *testing.T) {
	ipRule, _ := NewIPRule([]string{"10.0.0.0/8"}, "allow")
	uaRule, _ := NewUARule([]string{".*Chrome.*"}, "whitelist")

	group := &Group{
		And: []Rule{ipRule, uaRule},
	}

	eval := NewEvaluator()

	// Both match
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Chrome/91.0")
	ctx := &Context{ClientIP: "10.1.2.3", Request: req}
	result := eval.EvaluateGroup(group, ctx)
	if !result.Matched {
		t.Error("expected AND group to match when all rules match")
	}

	// Only IP matches
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "curl/7.68.0")
	ctx = &Context{ClientIP: "10.1.2.3", Request: req}
	result = eval.EvaluateGroup(group, ctx)
	if result.Matched {
		t.Error("expected AND group not to match when one rule fails")
	}
}

func TestEvaluatorOR(t *testing.T) {
	ipRule, _ := NewIPRule([]string{"10.0.0.0/8"}, "allow")
	uaRule, _ := NewUARule([]string{".*Chrome.*"}, "whitelist")

	group := &Group{
		Or: []Rule{ipRule, uaRule},
	}

	eval := NewEvaluator()

	// Only IP matches
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "curl/7.68.0")
	ctx := &Context{ClientIP: "10.1.2.3", Request: req}
	result := eval.EvaluateGroup(group, ctx)
	if !result.Matched {
		t.Error("expected OR group to match when one rule matches")
	}

	// Neither matches
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "curl/7.68.0")
	ctx = &Context{ClientIP: "8.8.8.8", Request: req}
	result = eval.EvaluateGroup(group, ctx)
	if result.Matched {
		t.Error("expected OR group not to match when no rules match")
	}
}

func TestParseTimeWindow(t *testing.T) {
	tw, err := ParseTimeWindow([]string{"mon", "tue", "wed"}, "09:00", "17:00")
	if err != nil {
		t.Fatalf("failed to parse time window: %v", err)
	}

	if len(tw.Days) != 3 {
		t.Errorf("expected 3 days, got %d", len(tw.Days))
	}
}
