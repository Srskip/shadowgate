package rules

import (
	"net/http"
)

// Result represents the outcome of rule evaluation
type Result struct {
	Matched bool
	Reason  string
	Labels  []string
}

// Context contains request information for rule evaluation
type Context struct {
	Request    *http.Request
	ClientIP   string
	TLSVersion uint16
	SNI        string
}

// Rule is the interface all rules must implement
type Rule interface {
	// Evaluate checks if the rule matches the given context
	Evaluate(ctx *Context) Result
	// Type returns the rule type identifier
	Type() string
}

// Evaluator evaluates rule groups with boolean logic
type Evaluator struct{}

// NewEvaluator creates a new rule evaluator
func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

// EvaluateGroup evaluates a group of rules with boolean logic
func (e *Evaluator) EvaluateGroup(group *Group, ctx *Context) Result {
	if group == nil {
		return Result{Matched: false}
	}

	// Handle AND logic
	if len(group.And) > 0 {
		for _, r := range group.And {
			result := r.Evaluate(ctx)
			if !result.Matched {
				return Result{Matched: false, Reason: result.Reason}
			}
		}
		return Result{Matched: true, Reason: "all AND conditions matched"}
	}

	// Handle OR logic
	if len(group.Or) > 0 {
		for _, r := range group.Or {
			result := r.Evaluate(ctx)
			if result.Matched {
				return Result{Matched: true, Reason: result.Reason, Labels: result.Labels}
			}
		}
		return Result{Matched: false, Reason: "no OR conditions matched"}
	}

	// Handle NOT logic
	if group.Not != nil {
		result := group.Not.Evaluate(ctx)
		return Result{
			Matched: !result.Matched,
			Reason:  "NOT: " + result.Reason,
		}
	}

	// Handle single rule
	if group.Single != nil {
		return group.Single.Evaluate(ctx)
	}

	return Result{Matched: false}
}

// Group represents a group of rules with boolean logic
type Group struct {
	And    []Rule
	Or     []Rule
	Not    Rule
	Single Rule
}
