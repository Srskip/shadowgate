package rules

import (
	"fmt"
	"regexp"
	"strings"
)

// MethodRule matches requests based on HTTP method
type MethodRule struct {
	methods map[string]bool
	mode    string // "allow" or "deny"
}

// NewMethodRule creates a new HTTP method rule
func NewMethodRule(methods []string, mode string) (*MethodRule, error) {
	if mode != "allow" && mode != "deny" {
		return nil, fmt.Errorf("invalid mode: %s", mode)
	}

	methodMap := make(map[string]bool)
	for _, m := range methods {
		methodMap[strings.ToUpper(m)] = true
	}

	return &MethodRule{
		methods: methodMap,
		mode:    mode,
	}, nil
}

// Evaluate checks if the HTTP method matches
func (r *MethodRule) Evaluate(ctx *Context) Result {
	if ctx.Request == nil {
		return Result{Matched: false, Reason: "no HTTP request"}
	}

	method := strings.ToUpper(ctx.Request.Method)
	matched := r.methods[method]

	return Result{
		Matched: matched,
		Reason:  fmt.Sprintf("method %s, %s list", method, r.mode),
		Labels:  []string{"method-" + r.mode, method},
	}
}

// Type returns the rule type
func (r *MethodRule) Type() string {
	return "method_" + r.mode
}

// PathRule matches requests based on URL path patterns
type PathRule struct {
	patterns []*regexp.Regexp
	mode     string // "allow" or "deny"
}

// NewPathRule creates a new path-based rule
func NewPathRule(patterns []string, mode string) (*PathRule, error) {
	if mode != "allow" && mode != "deny" {
		return nil, fmt.Errorf("invalid mode: %s", mode)
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", p, err)
		}
		compiled = append(compiled, re)
	}

	return &PathRule{
		patterns: compiled,
		mode:     mode,
	}, nil
}

// Evaluate checks if the URL path matches any pattern
func (r *PathRule) Evaluate(ctx *Context) Result {
	if ctx.Request == nil {
		return Result{Matched: false, Reason: "no HTTP request"}
	}

	path := ctx.Request.URL.Path
	for _, pattern := range r.patterns {
		if pattern.MatchString(path) {
			return Result{
				Matched: true,
				Reason:  fmt.Sprintf("path %q matched pattern %q (%s)", path, pattern.String(), r.mode),
				Labels:  []string{"path-" + r.mode},
			}
		}
	}

	return Result{
		Matched: false,
		Reason:  fmt.Sprintf("path %q did not match any %s pattern", path, r.mode),
	}
}

// Type returns the rule type
func (r *PathRule) Type() string {
	return "path_" + r.mode
}

// HeaderRule matches requests based on HTTP header presence/values
type HeaderRule struct {
	name     string
	patterns []*regexp.Regexp
	require  bool   // if true, header must be present
	mode     string // "allow" or "deny"
}

// NewHeaderRule creates a new header-based rule
func NewHeaderRule(name string, patterns []string, require bool, mode string) (*HeaderRule, error) {
	if mode != "allow" && mode != "deny" {
		return nil, fmt.Errorf("invalid mode: %s", mode)
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", p, err)
		}
		compiled = append(compiled, re)
	}

	return &HeaderRule{
		name:     name,
		patterns: compiled,
		require:  require,
		mode:     mode,
	}, nil
}

// Evaluate checks if the header matches configured patterns
func (r *HeaderRule) Evaluate(ctx *Context) Result {
	if ctx.Request == nil {
		return Result{Matched: false, Reason: "no HTTP request"}
	}

	value := ctx.Request.Header.Get(r.name)

	if value == "" {
		if r.require {
			return Result{
				Matched: false,
				Reason:  fmt.Sprintf("header %q required but not present", r.name),
				Labels:  []string{"missing-header-" + r.name},
			}
		}
		return Result{
			Matched: true,
			Reason:  fmt.Sprintf("header %q not present, not required", r.name),
		}
	}

	// If no patterns specified, just check presence
	if len(r.patterns) == 0 {
		return Result{
			Matched: true,
			Reason:  fmt.Sprintf("header %q is present", r.name),
			Labels:  []string{"header-present-" + r.name},
		}
	}

	for _, pattern := range r.patterns {
		if pattern.MatchString(value) {
			return Result{
				Matched: true,
				Reason:  fmt.Sprintf("header %q value matched pattern (%s)", r.name, r.mode),
				Labels:  []string{"header-" + r.mode + "-" + r.name},
			}
		}
	}

	return Result{
		Matched: false,
		Reason:  fmt.Sprintf("header %q value did not match any %s pattern", r.name, r.mode),
	}
}

// Type returns the rule type
func (r *HeaderRule) Type() string {
	return "header_" + r.mode
}
