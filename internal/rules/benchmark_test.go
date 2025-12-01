package rules

import (
	"net/http/httptest"
	"testing"
)

func BenchmarkIPRuleEvaluate(b *testing.B) {
	rule, _ := NewIPRule([]string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}, "allow")

	ctx := &Context{
		ClientIP: "10.0.0.50",
		Request:  httptest.NewRequest("GET", "/", nil),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.Evaluate(ctx)
	}
}

func BenchmarkIPRuleEvaluateNoMatch(b *testing.B) {
	rule, _ := NewIPRule([]string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}, "allow")

	ctx := &Context{
		ClientIP: "8.8.8.8",
		Request:  httptest.NewRequest("GET", "/", nil),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.Evaluate(ctx)
	}
}

func BenchmarkIPRuleManyNetworks(b *testing.B) {
	cidrs := make([]string, 100)
	for i := 0; i < 100; i++ {
		cidrs[i] = "10.0.0.0/8" // same network for simplicity
	}

	rule, _ := NewIPRule(cidrs, "allow")
	ctx := &Context{
		ClientIP: "10.0.0.50",
		Request:  httptest.NewRequest("GET", "/", nil),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.Evaluate(ctx)
	}
}

func BenchmarkUserAgentRuleMatch(b *testing.B) {
	rule, _ := NewUARule([]string{
		"(?i)nmap",
		"(?i)nikto",
		"(?i)sqlmap",
		"(?i)masscan",
	}, "blacklist")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "nmap/7.80")

	ctx := &Context{
		ClientIP: "10.0.0.1",
		Request:  req,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.Evaluate(ctx)
	}
}

func BenchmarkUserAgentRuleNoMatch(b *testing.B) {
	rule, _ := NewUARule([]string{
		"(?i)nmap",
		"(?i)nikto",
		"(?i)sqlmap",
		"(?i)masscan",
	}, "blacklist")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	ctx := &Context{
		ClientIP: "10.0.0.1",
		Request:  req,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.Evaluate(ctx)
	}
}

func BenchmarkPathRuleMatch(b *testing.B) {
	rule, _ := NewPathRule([]string{
		"^/admin",
		"^/debug",
		"^/api/internal",
	}, "deny")

	req := httptest.NewRequest("GET", "/admin/users", nil)
	ctx := &Context{
		ClientIP: "10.0.0.1",
		Request:  req,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.Evaluate(ctx)
	}
}

func BenchmarkMethodRule(b *testing.B) {
	rule, _ := NewMethodRule([]string{"GET", "POST", "PUT"}, "allow")

	req := httptest.NewRequest("GET", "/", nil)
	ctx := &Context{
		ClientIP: "10.0.0.1",
		Request:  req,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.Evaluate(ctx)
	}
}

func BenchmarkRateLimitRule(b *testing.B) {
	rule := NewRateLimitRule(1000, 1000000000) // 1000/sec

	ctx := &Context{
		ClientIP: "10.0.0.1",
		Request:  httptest.NewRequest("GET", "/", nil),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.Evaluate(ctx)
	}
}

func BenchmarkRateLimitRuleManySources(b *testing.B) {
	rule := NewRateLimitRule(1000, 1000000000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := &Context{
			ClientIP: "10.0.0.1", // same IP to stress the lock
			Request:  httptest.NewRequest("GET", "/", nil),
		}
		rule.Evaluate(ctx)
	}
}

func BenchmarkEvaluatorAND(b *testing.B) {
	ipRule, _ := NewIPRule([]string{"10.0.0.0/8"}, "allow")
	uaRule, _ := NewUARule([]string{"Mozilla.*"}, "whitelist")
	methodRule, _ := NewMethodRule([]string{"GET"}, "allow")

	group := &Group{
		And: []Rule{ipRule, uaRule, methodRule},
	}

	evaluator := NewEvaluator()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	ctx := &Context{
		ClientIP: "10.0.0.50",
		Request:  req,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evaluator.EvaluateGroup(group, ctx)
	}
}

func BenchmarkEvaluatorOR(b *testing.B) {
	ipRule1, _ := NewIPRule([]string{"10.0.0.0/8"}, "allow")
	ipRule2, _ := NewIPRule([]string{"192.168.0.0/16"}, "allow")
	ipRule3, _ := NewIPRule([]string{"172.16.0.0/12"}, "allow")

	group := &Group{
		Or: []Rule{ipRule1, ipRule2, ipRule3},
	}

	evaluator := NewEvaluator()

	ctx := &Context{
		ClientIP: "192.168.1.100", // matches second rule
		Request:  httptest.NewRequest("GET", "/", nil),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evaluator.EvaluateGroup(group, ctx)
	}
}

func BenchmarkHeaderRule(b *testing.B) {
	rule, _ := NewHeaderRule("Authorization", []string{"Bearer .*"}, true, "allow")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")

	ctx := &Context{
		ClientIP: "10.0.0.1",
		Request:  req,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.Evaluate(ctx)
	}
}
