package profile

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"shadowgate/internal/config"
	"shadowgate/internal/listener"
)

// Profile represents a complete traffic handling profile
type Profile struct {
	ID        string
	Config    config.ProfileConfig
	listeners []listener.Listener
	handler   http.Handler
	mu        sync.RWMutex
}

// Manager manages multiple profiles
type Manager struct {
	profiles map[string]*Profile
	mu       sync.RWMutex
}

// NewManager creates a new profile manager
func NewManager() *Manager {
	return &Manager{
		profiles: make(map[string]*Profile),
	}
}

// LoadFromConfig loads profiles from configuration
func (m *Manager) LoadFromConfig(cfg *config.Config, handlerFactory func(p *Profile) http.Handler) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, pc := range cfg.Profiles {
		profile := &Profile{
			ID:     pc.ID,
			Config: pc,
		}

		// Set the handler for this profile
		profile.handler = handlerFactory(profile)

		// Create listeners for this profile
		for _, lc := range pc.Listeners {
			var l listener.Listener
			switch lc.Protocol {
			case "http":
				l = listener.NewHTTPListener(listener.HTTPListenerConfig{
					Addr:    lc.Addr,
					Handler: profile.handler,
				})
			case "https":
				tlsCfg, err := listener.LoadTLSConfig(lc.TLS.CertFile, lc.TLS.KeyFile)
				if err != nil {
					return fmt.Errorf("profile %s: %w", pc.ID, err)
				}
				l = listener.NewHTTPListener(listener.HTTPListenerConfig{
					Addr:      lc.Addr,
					TLSConfig: tlsCfg,
					Handler:   profile.handler,
				})
			default:
				return fmt.Errorf("profile %s: unsupported protocol %s", pc.ID, lc.Protocol)
			}
			profile.listeners = append(profile.listeners, l)
		}

		m.profiles[pc.ID] = profile
	}

	return nil
}

// Start starts all profiles
func (m *Manager) Start(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for id, p := range m.profiles {
		for i, l := range p.listeners {
			if err := l.Start(ctx); err != nil {
				return fmt.Errorf("profile %s listener %d: %w", id, i, err)
			}
			fmt.Printf("Profile %s: listening on %s\n", id, l.Addr())
		}
	}
	return nil
}

// Stop stops all profiles gracefully
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lastErr error
	for id, p := range m.profiles {
		for i, l := range p.listeners {
			if err := l.Stop(ctx); err != nil {
				lastErr = fmt.Errorf("profile %s listener %d: %w", id, i, err)
			}
		}
	}
	return lastErr
}

// Get returns a profile by ID
func (m *Manager) Get(id string) (*Profile, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.profiles[id]
	return p, ok
}

// List returns all profile IDs
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]string, 0, len(m.profiles))
	for id := range m.profiles {
		ids = append(ids, id)
	}
	return ids
}

// GetBackendURL returns the primary backend URL for a profile
func (p *Profile) GetBackendURL() string {
	if len(p.Config.Backends) == 0 {
		return ""
	}
	// For now, return the first backend (weighted selection comes later)
	return p.Config.Backends[0].URL
}
