package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewBackend(t *testing.T) {
	b, err := NewBackend("test", "http://127.0.0.1:8080", 10)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	if b.Name != "test" {
		t.Errorf("expected name 'test', got %q", b.Name)
	}

	if b.Weight != 10 {
		t.Errorf("expected weight 10, got %d", b.Weight)
	}
}

func TestNewBackendInvalidURL(t *testing.T) {
	_, err := NewBackend("test", "://invalid", 10)
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestBackendServeHTTP(t *testing.T) {
	// Create a test backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend response"))
	}))
	defer backendServer.Close()

	b, err := NewBackend("test", backendServer.URL, 10)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	// Create a test request
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	b.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	body, _ := io.ReadAll(rr.Body)
	if string(body) != "backend response" {
		t.Errorf("expected 'backend response', got %q", string(body))
	}
}

func TestPoolRoundRobin(t *testing.T) {
	pool := NewPool()

	b1, _ := NewBackend("b1", "http://127.0.0.1:8001", 10)
	b2, _ := NewBackend("b2", "http://127.0.0.1:8002", 10)
	b3, _ := NewBackend("b3", "http://127.0.0.1:8003", 10)

	pool.Add(b1)
	pool.Add(b2)
	pool.Add(b3)

	if pool.Len() != 3 {
		t.Errorf("expected 3 backends, got %d", pool.Len())
	}

	// Test round-robin
	names := make([]string, 6)
	for i := 0; i < 6; i++ {
		names[i] = pool.Next().Name
	}

	expected := []string{"b1", "b2", "b3", "b1", "b2", "b3"}
	for i, name := range names {
		if name != expected[i] {
			t.Errorf("position %d: expected %s, got %s", i, expected[i], name)
		}
	}
}

func TestPoolGet(t *testing.T) {
	pool := NewPool()

	b1, _ := NewBackend("primary", "http://127.0.0.1:8001", 10)
	b2, _ := NewBackend("secondary", "http://127.0.0.1:8002", 5)

	pool.Add(b1)
	pool.Add(b2)

	found := pool.Get("primary")
	if found == nil || found.Name != "primary" {
		t.Error("expected to find 'primary' backend")
	}

	notFound := pool.Get("nonexistent")
	if notFound != nil {
		t.Error("expected nil for nonexistent backend")
	}
}

func TestPoolEmpty(t *testing.T) {
	pool := NewPool()

	if pool.Next() != nil {
		t.Error("expected nil from empty pool")
	}
}
