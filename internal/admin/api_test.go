package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"shadowgate/internal/metrics"
	"shadowgate/internal/proxy"
)

func TestHealthEndpoint(t *testing.T) {
	api := New(Config{
		Addr:    ":0",
		Version: "test",
	})

	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()

	api.handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp["status"] != "ok" {
		t.Errorf("expected status 'ok', got %q", resp["status"])
	}
}

func TestStatusEndpoint(t *testing.T) {
	api := New(Config{
		Addr:    ":0",
		Version: "1.0.0",
	})

	req := httptest.NewRequest("GET", "/status", nil)
	rr := httptest.NewRecorder()

	api.handleStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	var resp StatusResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Status != "running" {
		t.Errorf("expected status 'running', got %q", resp.Status)
	}

	if resp.Version != "1.0.0" {
		t.Errorf("expected version '1.0.0', got %q", resp.Version)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	m := metrics.New()
	m.RecordRequest("test", "10.0.0.1", "allow_forward", 10.0)

	api := New(Config{
		Addr:    ":0",
		Metrics: m,
	})

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()

	api.handleMetrics(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestBackendsEndpoint(t *testing.T) {
	api := New(Config{
		Addr: ":0",
	})

	pool := proxy.NewPool()
	b1, _ := proxy.NewBackend("backend1", "http://127.0.0.1:8001", 10)
	b2, _ := proxy.NewBackend("backend2", "http://127.0.0.1:8002", 5)
	pool.Add(b1)
	pool.Add(b2)

	b1.SetHealthy(false)

	api.RegisterPool("test-profile", pool)

	req := httptest.NewRequest("GET", "/backends", nil)
	rr := httptest.NewRecorder()

	api.handleBackends(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	var resp BackendsResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	profile, ok := resp.Profiles["test-profile"]
	if !ok {
		t.Fatal("expected test-profile in response")
	}

	if profile.Total != 2 {
		t.Errorf("expected 2 total backends, got %d", profile.Total)
	}

	if profile.Healthy != 1 {
		t.Errorf("expected 1 healthy backend, got %d", profile.Healthy)
	}
}

func TestReloadEndpoint(t *testing.T) {
	reloadCalled := false
	api := New(Config{
		Addr: ":0",
		ReloadFunc: func() error {
			reloadCalled = true
			return nil
		},
	})

	req := httptest.NewRequest("POST", "/reload", nil)
	rr := httptest.NewRecorder()

	api.handleReload(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	if !reloadCalled {
		t.Error("expected reload function to be called")
	}

	var resp ReloadResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if !resp.Success {
		t.Error("expected success to be true")
	}
}

func TestReloadEndpointWrongMethod(t *testing.T) {
	api := New(Config{
		Addr: ":0",
	})

	req := httptest.NewRequest("GET", "/reload", nil)
	rr := httptest.NewRecorder()

	api.handleReload(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rr.Code)
	}
}
