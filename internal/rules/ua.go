package rules

import (
	"fmt"
	"regexp"
)

// UARule matches requests based on User-Agent header against regex patterns
type UARule struct {
	patterns []*regexp.Regexp
	mode     string // "whitelist" or "blacklist"
}

// NewUARule creates a new User-Agent based rule
func NewUARule(patterns []string, mode string) (*UARule, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern %q: %w", p, err)
		}
		compiled = append(compiled, re)
	}

	if mode != "whitelist" && mode != "blacklist" {
		return nil, fmt.Errorf("invalid mode: %s (must be 'whitelist' or 'blacklist')", mode)
	}

	return &UARule{
		patterns: compiled,
		mode:     mode,
	}, nil
}

// Evaluate checks if the User-Agent matches any configured pattern
func (r *UARule) Evaluate(ctx *Context) Result {
	ua := ctx.Request.Header.Get("User-Agent")

	for _, pattern := range r.patterns {
		if pattern.MatchString(ua) {
			return Result{
				Matched: true,
				Reason:  fmt.Sprintf("UA %q matched pattern %q (%s)", ua, pattern.String(), r.mode),
				Labels:  []string{"ua-" + r.mode},
			}
		}
	}

	return Result{
		Matched: false,
		Reason:  fmt.Sprintf("UA %q did not match any %s pattern", ua, r.mode),
	}
}

// Type returns the rule type
func (r *UARule) Type() string {
	return "ua_" + r.mode
}
