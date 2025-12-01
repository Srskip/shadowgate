package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBackendHealth(t *testing.T) {
	b, err := NewBackend("test", "http://127.0.0.1:8080", 10)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	// Should be healthy by default
	if !b.IsHealthy() {
		t.Error("expected backend to be healthy by default")
	}

	// Set unhealthy
	b.SetHealthy(false)
	if b.IsHealthy() {
		t.Error("expected backend to be unhealthy")
	}

	// Set healthy again
	b.SetHealthy(true)
	if !b.IsHealthy() {
		t.Error("expected backend to be healthy")
	}

	// Check status
	status := b.GetHealthStatus()
	if status.CheckCount != 2 {
		t.Errorf("expected 2 checks, got %d", status.CheckCount)
	}
	if status.FailCount != 1 {
		t.Errorf("expected 1 fail, got %d", status.FailCount)
	}
}

func TestPoolNextHealthy(t *testing.T) {
	pool := NewPool()

	b1, _ := NewBackend("b1", "http://127.0.0.1:8001", 10)
	b2, _ := NewBackend("b2", "http://127.0.0.1:8002", 10)
	b3, _ := NewBackend("b3", "http://127.0.0.1:8003", 10)

	pool.Add(b1)
	pool.Add(b2)
	pool.Add(b3)

	// All healthy - should round robin
	first := pool.NextHealthy()
	if first == nil {
		t.Fatal("expected a backend")
	}

	// Mark b1 unhealthy
	b1.SetHealthy(false)

	// Should skip b1
	for i := 0; i < 10; i++ {
		b := pool.NextHealthy()
		if b.Name == "b1" {
			t.Error("should not return unhealthy b1")
		}
	}

	// Mark all unhealthy - should still return something (fallback)
	b2.SetHealthy(false)
	b3.SetHealthy(false)

	b := pool.NextHealthy()
	if b == nil {
		t.Error("should return fallback backend when all unhealthy")
	}
}

func TestPoolHealthyCount(t *testing.T) {
	pool := NewPool()

	b1, _ := NewBackend("b1", "http://127.0.0.1:8001", 10)
	b2, _ := NewBackend("b2", "http://127.0.0.1:8002", 10)

	pool.Add(b1)
	pool.Add(b2)

	if pool.HealthyCount() != 2 {
		t.Errorf("expected 2 healthy, got %d", pool.HealthyCount())
	}

	b1.SetHealthy(false)

	if pool.HealthyCount() != 1 {
		t.Errorf("expected 1 healthy, got %d", pool.HealthyCount())
	}
}

func TestHealthChecker(t *testing.T) {
	// Create a test server
	healthy := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if healthy {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()

	pool := NewPool()
	b, _ := NewBackend("test", server.URL, 10)
	pool.Add(b)

	config := HealthConfig{
		Enabled:  true,
		Interval: 50 * time.Millisecond,
		Timeout:  1 * time.Second,
		Path:     "/",
	}

	hc := NewHealthChecker(pool, config)
	hc.Start()
	defer hc.Stop()

	// Wait for initial check
	time.Sleep(100 * time.Millisecond)

	if !b.IsHealthy() {
		t.Error("expected backend to be healthy")
	}

	// Make server unhealthy
	healthy = false

	// Wait for check
	time.Sleep(100 * time.Millisecond)

	if b.IsHealthy() {
		t.Error("expected backend to be unhealthy")
	}
}

func TestGetHealthStatuses(t *testing.T) {
	pool := NewPool()

	b1, _ := NewBackend("b1", "http://127.0.0.1:8001", 10)
	b2, _ := NewBackend("b2", "http://127.0.0.1:8002", 10)

	pool.Add(b1)
	pool.Add(b2)

	b1.SetHealthy(false)

	statuses := pool.GetHealthStatuses()

	if len(statuses) != 2 {
		t.Errorf("expected 2 statuses, got %d", len(statuses))
	}

	if statuses["b1"].Healthy {
		t.Error("expected b1 to be unhealthy")
	}

	if !statuses["b2"].Healthy {
		t.Error("expected b2 to be healthy")
	}
}

func TestPoolNextWeighted(t *testing.T) {
	pool := NewPool()

	// b1 has weight 10, b2 has weight 1
	b1, _ := NewBackend("b1", "http://127.0.0.1:8001", 10)
	b2, _ := NewBackend("b2", "http://127.0.0.1:8002", 1)

	pool.Add(b1)
	pool.Add(b2)

	// Count selections over many iterations
	counts := map[string]int{"b1": 0, "b2": 0}
	for i := 0; i < 110; i++ {
		b := pool.NextWeighted()
		counts[b.Name]++
	}

	// b1 should be selected roughly 10x more than b2
	// With 110 iterations and weights 10:1, expect ~100:10
	if counts["b1"] < 80 {
		t.Errorf("expected b1 to be selected more often, got %d", counts["b1"])
	}

	// Mark b1 unhealthy - should only return b2
	b1.SetHealthy(false)

	for i := 0; i < 10; i++ {
		b := pool.NextWeighted()
		if b.Name != "b2" {
			t.Errorf("expected only b2 when b1 unhealthy, got %s", b.Name)
		}
	}
}
