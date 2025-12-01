package rules

import (
	"fmt"
	"net"
)

// IPRule matches requests based on client IP against CIDR ranges
type IPRule struct {
	networks []*net.IPNet
	mode     string // "allow" or "deny"
}

// NewIPRule creates a new IP-based rule
func NewIPRule(cidrs []string, mode string) (*IPRule, error) {
	networks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try parsing as single IP
			ip := net.ParseIP(cidr)
			if ip == nil {
				return nil, fmt.Errorf("invalid CIDR or IP: %s", cidr)
			}
			// Convert single IP to /32 or /128
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			network = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		networks = append(networks, network)
	}

	if mode != "allow" && mode != "deny" {
		return nil, fmt.Errorf("invalid mode: %s (must be 'allow' or 'deny')", mode)
	}

	return &IPRule{
		networks: networks,
		mode:     mode,
	}, nil
}

// Evaluate checks if the client IP matches any of the configured networks
func (r *IPRule) Evaluate(ctx *Context) Result {
	ip := net.ParseIP(ctx.ClientIP)
	if ip == nil {
		return Result{
			Matched: false,
			Reason:  fmt.Sprintf("invalid client IP: %s", ctx.ClientIP),
		}
	}

	for _, network := range r.networks {
		if network.Contains(ip) {
			return Result{
				Matched: true,
				Reason:  fmt.Sprintf("IP %s matched %s (%s)", ctx.ClientIP, network.String(), r.mode),
				Labels:  []string{"ip-" + r.mode},
			}
		}
	}

	return Result{
		Matched: false,
		Reason:  fmt.Sprintf("IP %s did not match any %s list", ctx.ClientIP, r.mode),
	}
}

// Type returns the rule type
func (r *IPRule) Type() string {
	return "ip_" + r.mode
}
