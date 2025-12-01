package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkPoolNext(b *testing.B) {
	pool := NewPool()
	for i := 0; i < 5; i++ {
		backend, _ := NewBackend("backend", "http://127.0.0.1:8080", 10)
		pool.Add(backend)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.Next()
	}
}

func BenchmarkPoolNextHealthy(b *testing.B) {
	pool := NewPool()
	for i := 0; i < 5; i++ {
		backend, _ := NewBackend("backend", "http://127.0.0.1:8080", 10)
		pool.Add(backend)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.NextHealthy()
	}
}

func BenchmarkPoolNextWeighted(b *testing.B) {
	pool := NewPool()

	backend1, _ := NewBackend("b1", "http://127.0.0.1:8081", 10)
	backend2, _ := NewBackend("b2", "http://127.0.0.1:8082", 5)
	backend3, _ := NewBackend("b3", "http://127.0.0.1:8083", 1)

	pool.Add(backend1)
	pool.Add(backend2)
	pool.Add(backend3)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.NextWeighted()
	}
}

func BenchmarkBackendIsHealthy(b *testing.B) {
	backend, _ := NewBackend("test", "http://127.0.0.1:8080", 10)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		backend.IsHealthy()
	}
}

func BenchmarkBackendSetHealthy(b *testing.B) {
	backend, _ := NewBackend("test", "http://127.0.0.1:8080", 10)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		backend.SetHealthy(i%2 == 0)
	}
}

func BenchmarkPoolHealthyCount(b *testing.B) {
	pool := NewPool()
	for i := 0; i < 10; i++ {
		backend, _ := NewBackend("backend", "http://127.0.0.1:8080", 10)
		if i%3 == 0 {
			backend.SetHealthy(false)
		}
		pool.Add(backend)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.HealthyCount()
	}
}

func BenchmarkPoolGetHealthStatuses(b *testing.B) {
	pool := NewPool()
	for i := 0; i < 10; i++ {
		backend, _ := NewBackend("backend", "http://127.0.0.1:8080", 10)
		pool.Add(backend)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.GetHealthStatuses()
	}
}

func BenchmarkBackendServeHTTP(b *testing.B) {
	// Create a test backend server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	backend, _ := NewBackend("test", server.URL, 10)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		backend.ServeHTTP(rr, req)
	}
}

func BenchmarkPoolNextParallel(b *testing.B) {
	pool := NewPool()
	for i := 0; i < 5; i++ {
		backend, _ := NewBackend("backend", "http://127.0.0.1:8080", 10)
		pool.Add(backend)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pool.Next()
		}
	})
}

func BenchmarkPoolNextHealthyParallel(b *testing.B) {
	pool := NewPool()
	for i := 0; i < 5; i++ {
		backend, _ := NewBackend("backend", "http://127.0.0.1:8080", 10)
		pool.Add(backend)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pool.NextHealthy()
		}
	})
}
