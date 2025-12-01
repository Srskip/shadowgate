package decision

import (
	"net/http/httptest"
	"testing"

	"shadowgate/internal/rules"
)

func TestEngineAllowRulesMatch(t *testing.T) {
	ipRule, _ := rules.NewIPRule([]string{"10.0.0.0/8"}, "allow")
	allowRules := &rules.Group{And: []rules.Rule{ipRule}}

	engine := NewEngine(allowRules, nil)

	req := httptest.NewRequest("GET", "/", nil)
	decision := engine.Evaluate(req, "10.1.2.3")

	if decision.Action != AllowForward {
		t.Errorf("expected AllowForward, got %s", decision.Action)
	}
}

func TestEngineAllowRulesNoMatch(t *testing.T) {
	ipRule, _ := rules.NewIPRule([]string{"10.0.0.0/8"}, "allow")
	allowRules := &rules.Group{And: []rules.Rule{ipRule}}

	engine := NewEngine(allowRules, nil)

	req := httptest.NewRequest("GET", "/", nil)
	decision := engine.Evaluate(req, "8.8.8.8")

	if decision.Action != DenyDecoy {
		t.Errorf("expected DenyDecoy when allow rules don't match, got %s", decision.Action)
	}
}

func TestEngineDenyTakesPrecedence(t *testing.T) {
	allowIP, _ := rules.NewIPRule([]string{"10.0.0.0/8"}, "allow")
	denyIP, _ := rules.NewIPRule([]string{"10.1.0.0/16"}, "deny")

	allowRules := &rules.Group{And: []rules.Rule{allowIP}}
	denyRules := &rules.Group{And: []rules.Rule{denyIP}}

	engine := NewEngine(allowRules, denyRules)

	req := httptest.NewRequest("GET", "/", nil)
	// IP matches both allow (10.0.0.0/8) and deny (10.1.0.0/16)
	decision := engine.Evaluate(req, "10.1.2.3")

	if decision.Action != DenyDecoy {
		t.Errorf("expected deny to take precedence, got %s", decision.Action)
	}
}

func TestEngineNoRulesAllows(t *testing.T) {
	engine := NewEngine(nil, nil)

	req := httptest.NewRequest("GET", "/", nil)
	decision := engine.Evaluate(req, "any-ip")

	if decision.Action != AllowForward {
		t.Errorf("expected AllowForward when no rules, got %s", decision.Action)
	}
}

func TestActionString(t *testing.T) {
	tests := []struct {
		action   Action
		expected string
	}{
		{AllowForward, "allow_forward"},
		{DenyDecoy, "deny_decoy"},
		{Drop, "drop"},
		{Tarpit, "tarpit"},
		{Redirect, "redirect"},
	}

	for _, tc := range tests {
		if tc.action.String() != tc.expected {
			t.Errorf("expected %s, got %s", tc.expected, tc.action.String())
		}
	}
}
