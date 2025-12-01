package listener

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestHTTPListener(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	listener := NewHTTPListener(HTTPListenerConfig{
		Addr:    "127.0.0.1:0", // Use port 0 to get a random available port
		Handler: handler,
	})

	ctx := context.Background()
	if err := listener.Start(ctx); err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Stop(ctx)

	// Give the server a moment to start
	time.Sleep(50 * time.Millisecond)

	// Get the actual bound address
	addr := listener.Addr()
	t.Logf("Listener bound to: %s", addr)

	// Make a test request
	resp, err := http.Get("http://" + addr)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "OK" {
		t.Errorf("expected body 'OK', got %q", string(body))
	}
}

func TestHTTPListenerStop(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener := NewHTTPListener(HTTPListenerConfig{
		Addr:    "127.0.0.1:18081",
		Handler: handler,
	})

	ctx := context.Background()
	if err := listener.Start(ctx); err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}

	// Stop should not error
	if err := listener.Stop(ctx); err != nil {
		t.Errorf("failed to stop listener: %v", err)
	}
}
