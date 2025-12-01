package honeypot

import (
	"net/http"
	"regexp"
	"sync"
	"time"

	"shadowgate/internal/decoy"
	"shadowgate/internal/logging"
)

// Path represents a honeypot path configuration
type Path struct {
	Pattern  *regexp.Regexp
	Name     string
	Decoy    decoy.Strategy
	LogLevel string // "aggressive" logs full request details
}

// Handler handles honeypot paths
type Handler struct {
	paths  []*Path
	logger *logging.Logger
	hits   map[string]*HitStats
	mu     sync.RWMutex
}

// HitStats tracks honeypot hits
type HitStats struct {
	Count     int64
	FirstSeen time.Time
	LastSeen  time.Time
	IPs       map[string]int
}

// NewHandler creates a new honeypot handler
func NewHandler(logger *logging.Logger) *Handler {
	return &Handler{
		paths:  make([]*Path, 0),
		logger: logger,
		hits:   make(map[string]*HitStats),
	}
}

// AddPath adds a honeypot path
func (h *Handler) AddPath(name, pattern string, d decoy.Strategy) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	h.paths = append(h.paths, &Path{
		Pattern:  re,
		Name:     name,
		Decoy:    d,
		LogLevel: "aggressive",
	})

	h.mu.Lock()
	h.hits[name] = &HitStats{
		IPs: make(map[string]int),
	}
	h.mu.Unlock()

	return nil
}

// Check checks if a request matches a honeypot path
func (h *Handler) Check(r *http.Request) *Path {
	for _, p := range h.paths {
		if p.Pattern.MatchString(r.URL.Path) {
			return p
		}
	}
	return nil
}

// Handle handles a honeypot hit
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request, path *Path, clientIP string) {
	h.recordHit(path.Name, clientIP)
	h.logHit(r, path, clientIP)

	if path.Decoy != nil {
		path.Decoy.Serve(w, r)
	} else {
		// Default: 404 with a plausible message
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 page not found"))
	}
}

func (h *Handler) recordHit(name, clientIP string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	stats := h.hits[name]
	if stats == nil {
		stats = &HitStats{
			IPs: make(map[string]int),
		}
		h.hits[name] = stats
	}

	now := time.Now()
	stats.Count++
	stats.LastSeen = now
	if stats.FirstSeen.IsZero() {
		stats.FirstSeen = now
	}
	stats.IPs[clientIP]++
}

func (h *Handler) logHit(r *http.Request, path *Path, clientIP string) {
	if h.logger == nil {
		return
	}

	fields := map[string]interface{}{
		"honeypot":    path.Name,
		"path":        r.URL.Path,
		"method":      r.Method,
		"client_ip":   clientIP,
		"user_agent":  r.Header.Get("User-Agent"),
		"referer":     r.Header.Get("Referer"),
		"host":        r.Host,
		"query":       r.URL.RawQuery,
	}

	// Aggressive logging includes all headers
	if path.LogLevel == "aggressive" {
		headers := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}
		fields["headers"] = headers
	}

	h.logger.Warn("honeypot hit", fields)
}

// GetStats returns honeypot statistics
func (h *Handler) GetStats() map[string]*HitStats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Return a copy
	result := make(map[string]*HitStats)
	for name, stats := range h.hits {
		ipsCopy := make(map[string]int)
		for ip, count := range stats.IPs {
			ipsCopy[ip] = count
		}
		result[name] = &HitStats{
			Count:     stats.Count,
			FirstSeen: stats.FirstSeen,
			LastSeen:  stats.LastSeen,
			IPs:       ipsCopy,
		}
	}
	return result
}

// DefaultPaths returns common honeypot paths
func DefaultPaths() []struct {
	Name    string
	Pattern string
} {
	return []struct {
		Name    string
		Pattern string
	}{
		{"admin-panel", "^/admin"},
		{"wp-admin", "^/wp-admin"},
		{"wp-login", "^/wp-login\\.php"},
		{"phpmyadmin", "(?i)^/phpmyadmin"},
		{"backup", "(?i)\\.(bak|backup|old|orig|sql|tar|zip|gz)$"},
		{"env-file", "^\\.env"},
		{"git-exposed", "^/\\.git"},
		{"config-files", "(?i)(config|settings|credentials)\\.(php|json|yml|yaml|xml|ini)$"},
		{"shell", "(?i)(shell|cmd|eval|exec|backdoor)\\.php"},
		{"api-debug", "^/api/(debug|test|dev)"},
	}
}
