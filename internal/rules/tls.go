package rules

import (
	"crypto/tls"
	"fmt"
	"regexp"
)

// TLSVersionRule matches requests based on TLS version
type TLSVersionRule struct {
	minVersion uint16
	maxVersion uint16
}

// NewTLSVersionRule creates a new TLS version rule
func NewTLSVersionRule(minVersion, maxVersion string) (*TLSVersionRule, error) {
	min, err := parseTLSVersion(minVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid min version: %w", err)
	}

	max, err := parseTLSVersion(maxVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid max version: %w", err)
	}

	return &TLSVersionRule{
		minVersion: min,
		maxVersion: max,
	}, nil
}

func parseTLSVersion(v string) (uint16, error) {
	switch v {
	case "1.0", "TLS1.0":
		return tls.VersionTLS10, nil
	case "1.1", "TLS1.1":
		return tls.VersionTLS11, nil
	case "1.2", "TLS1.2":
		return tls.VersionTLS12, nil
	case "1.3", "TLS1.3":
		return tls.VersionTLS13, nil
	case "":
		return 0, nil
	default:
		return 0, fmt.Errorf("unknown TLS version: %s", v)
	}
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("unknown(%d)", v)
	}
}

// Evaluate checks if the TLS version is within the allowed range
func (r *TLSVersionRule) Evaluate(ctx *Context) Result {
	if ctx.TLSVersion == 0 {
		return Result{
			Matched: false,
			Reason:  "no TLS connection",
		}
	}

	inRange := true
	if r.minVersion > 0 && ctx.TLSVersion < r.minVersion {
		inRange = false
	}
	if r.maxVersion > 0 && ctx.TLSVersion > r.maxVersion {
		inRange = false
	}

	return Result{
		Matched: inRange,
		Reason:  fmt.Sprintf("TLS version %s, range [%s-%s]", tlsVersionString(ctx.TLSVersion), tlsVersionString(r.minVersion), tlsVersionString(r.maxVersion)),
		Labels:  []string{"tls-version", tlsVersionString(ctx.TLSVersion)},
	}
}

// Type returns the rule type
func (r *TLSVersionRule) Type() string {
	return "tls_version"
}

// SNIRule matches requests based on Server Name Indication
type SNIRule struct {
	patterns     []*regexp.Regexp
	requireSNI   bool
	mode         string // "allow" or "deny"
}

// NewSNIRule creates a new SNI-based rule
func NewSNIRule(patterns []string, requireSNI bool, mode string) (*SNIRule, error) {
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

	return &SNIRule{
		patterns:   compiled,
		requireSNI: requireSNI,
		mode:       mode,
	}, nil
}

// Evaluate checks if the SNI matches configured patterns
func (r *SNIRule) Evaluate(ctx *Context) Result {
	if ctx.SNI == "" {
		if r.requireSNI {
			return Result{
				Matched: false,
				Reason:  "SNI required but not present",
				Labels:  []string{"no-sni"},
			}
		}
		return Result{
			Matched: true,
			Reason:  "SNI not present, not required",
		}
	}

	for _, pattern := range r.patterns {
		if pattern.MatchString(ctx.SNI) {
			return Result{
				Matched: true,
				Reason:  fmt.Sprintf("SNI %q matched pattern %q (%s)", ctx.SNI, pattern.String(), r.mode),
				Labels:  []string{"sni-" + r.mode},
			}
		}
	}

	return Result{
		Matched: false,
		Reason:  fmt.Sprintf("SNI %q did not match any %s pattern", ctx.SNI, r.mode),
	}
}

// Type returns the rule type
func (r *SNIRule) Type() string {
	return "sni_" + r.mode
}
