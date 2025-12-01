package profile

import (
	"context"
	"net/http"
	"testing"

	"shadowgate/internal/config"
)

func TestManagerLoadFromConfig(t *testing.T) {
	cfg := &config.Config{
		Profiles: []config.ProfileConfig{
			{
				ID: "test-profile",
				Listeners: []config.ListenerConfig{
					{Addr: "127.0.0.1:0", Protocol: "http"},
				},
				Backends: []config.BackendConfig{
					{Name: "primary", URL: "http://127.0.0.1:9000", Weight: 10},
				},
			},
		},
	}

	mgr := NewManager()
	err := mgr.LoadFromConfig(cfg, func(p *Profile) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})

	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if len(mgr.List()) != 1 {
		t.Errorf("expected 1 profile, got %d", len(mgr.List()))
	}

	p, ok := mgr.Get("test-profile")
	if !ok {
		t.Fatal("expected to find test-profile")
	}

	if p.ID != "test-profile" {
		t.Errorf("expected ID 'test-profile', got %q", p.ID)
	}

	if p.GetBackendURL() != "http://127.0.0.1:9000" {
		t.Errorf("unexpected backend URL: %s", p.GetBackendURL())
	}
}

func TestManagerStartStop(t *testing.T) {
	cfg := &config.Config{
		Profiles: []config.ProfileConfig{
			{
				ID: "test",
				Listeners: []config.ListenerConfig{
					{Addr: "127.0.0.1:0", Protocol: "http"},
				},
				Backends: []config.BackendConfig{
					{Name: "primary", URL: "http://127.0.0.1:9000"},
				},
			},
		},
	}

	mgr := NewManager()
	err := mgr.LoadFromConfig(cfg, func(p *Profile) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	ctx := context.Background()
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("failed to start: %v", err)
	}

	if err := mgr.Stop(ctx); err != nil {
		t.Fatalf("failed to stop: %v", err)
	}
}
