package rules

import (
	"fmt"
	"strings"

	"shadowgate/internal/geoip"
)

// GeoRule matches requests based on geographic location
type GeoRule struct {
	countries map[string]bool
	mode      string // "allow" or "deny"
}

// NewGeoRule creates a new geography-based rule
func NewGeoRule(countryCodes []string, mode string) (*GeoRule, error) {
	if mode != "allow" && mode != "deny" {
		return nil, fmt.Errorf("invalid mode: %s (must be 'allow' or 'deny')", mode)
	}

	countries := make(map[string]bool)
	for _, code := range countryCodes {
		countries[strings.ToUpper(code)] = true
	}

	return &GeoRule{
		countries: countries,
		mode:      mode,
	}, nil
}

// Evaluate checks if the client IP is in the configured countries
func (r *GeoRule) Evaluate(ctx *Context) Result {
	db := geoip.GetGlobal()
	if db == nil {
		return Result{
			Matched: false,
			Reason:  "GeoIP database not loaded",
		}
	}

	code, name, err := db.LookupCountry(ctx.ClientIP)
	if err != nil {
		return Result{
			Matched: false,
			Reason:  fmt.Sprintf("GeoIP lookup failed: %v", err),
		}
	}

	matched := r.countries[code]
	return Result{
		Matched: matched,
		Reason:  fmt.Sprintf("IP %s is in %s (%s), %s list", ctx.ClientIP, name, code, r.mode),
		Labels:  []string{"geo-" + r.mode, "country-" + code},
	}
}

// Type returns the rule type
func (r *GeoRule) Type() string {
	return "geo_" + r.mode
}

// ASNRule matches requests based on Autonomous System Number
type ASNRule struct {
	asns map[uint]bool
	mode string // "allow" or "deny"
}

// NewASNRule creates a new ASN-based rule
func NewASNRule(asns []uint, mode string) (*ASNRule, error) {
	if mode != "allow" && mode != "deny" {
		return nil, fmt.Errorf("invalid mode: %s (must be 'allow' or 'deny')", mode)
	}

	asnMap := make(map[uint]bool)
	for _, asn := range asns {
		asnMap[asn] = true
	}

	return &ASNRule{
		asns: asnMap,
		mode: mode,
	}, nil
}

// Evaluate checks if the client IP belongs to configured ASNs
func (r *ASNRule) Evaluate(ctx *Context) Result {
	db := geoip.GetGlobal()
	if db == nil {
		return Result{
			Matched: false,
			Reason:  "GeoIP database not loaded",
		}
	}

	asn, org, err := db.LookupASN(ctx.ClientIP)
	if err != nil {
		return Result{
			Matched: false,
			Reason:  fmt.Sprintf("ASN lookup failed: %v", err),
		}
	}

	matched := r.asns[asn]
	return Result{
		Matched: matched,
		Reason:  fmt.Sprintf("IP %s is in AS%d (%s), %s list", ctx.ClientIP, asn, org, r.mode),
		Labels:  []string{"asn-" + r.mode, fmt.Sprintf("AS%d", asn)},
	}
}

// Type returns the rule type
func (r *ASNRule) Type() string {
	return "asn_" + r.mode
}
