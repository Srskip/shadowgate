package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"sync"
	"time"

	"shadowgate/internal/metrics"
	"shadowgate/internal/proxy"
)

// API provides administrative endpoints
type API struct {
	addr       string
	server     *http.Server
	metrics    *metrics.Metrics
	pools      map[string]*proxy.Pool
	poolsMu    sync.RWMutex
	reloadFunc func() error
	startTime  time.Time
	version    string
}

// Config configures the Admin API
type Config struct {
	Addr       string
	Metrics    *metrics.Metrics
	ReloadFunc func() error
	Version    string
}

// New creates a new Admin API
func New(cfg Config) *API {
	api := &API{
		addr:       cfg.Addr,
		metrics:    cfg.Metrics,
		pools:      make(map[string]*proxy.Pool),
		reloadFunc: cfg.ReloadFunc,
		startTime:  time.Now(),
		version:    cfg.Version,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", api.handleHealth)
	mux.HandleFunc("/status", api.handleStatus)
	mux.HandleFunc("/metrics", api.handleMetrics)
	mux.HandleFunc("/backends", api.handleBackends)
	mux.HandleFunc("/reload", api.handleReload)

	api.server = &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return api
}

// RegisterPool registers a backend pool for status reporting
func (a *API) RegisterPool(profileID string, pool *proxy.Pool) {
	a.poolsMu.Lock()
	defer a.poolsMu.Unlock()
	a.pools[profileID] = pool
}

// Start starts the Admin API server
func (a *API) Start() error {
	go func() {
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Log error but don't crash
		}
	}()
	return nil
}

// Stop stops the Admin API server
func (a *API) Stop(ctx context.Context) error {
	return a.server.Shutdown(ctx)
}

// StatusResponse represents the status endpoint response
type StatusResponse struct {
	Status    string        `json:"status"`
	Version   string        `json:"version"`
	Uptime    string        `json:"uptime"`
	GoVersion string        `json:"go_version"`
	NumCPU    int           `json:"num_cpu"`
	Goroutines int          `json:"goroutines"`
	Memory    MemoryStats   `json:"memory"`
}

// MemoryStats contains memory statistics
type MemoryStats struct {
	Alloc      uint64 `json:"alloc_bytes"`
	TotalAlloc uint64 `json:"total_alloc_bytes"`
	Sys        uint64 `json:"sys_bytes"`
	NumGC      uint32 `json:"num_gc"`
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	resp := StatusResponse{
		Status:     "running",
		Version:    a.version,
		Uptime:     time.Since(a.startTime).Round(time.Second).String(),
		GoVersion:  runtime.Version(),
		NumCPU:     runtime.NumCPU(),
		Goroutines: runtime.NumGoroutine(),
		Memory: MemoryStats{
			Alloc:      mem.Alloc,
			TotalAlloc: mem.TotalAlloc,
			Sys:        mem.Sys,
			NumGC:      mem.NumGC,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (a *API) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.metrics == nil {
		http.Error(w, "Metrics not available", http.StatusServiceUnavailable)
		return
	}

	a.metrics.Handler()(w, r)
}

// BackendsResponse represents the backends endpoint response
type BackendsResponse struct {
	Profiles map[string]ProfileBackends `json:"profiles"`
}

// ProfileBackends represents backends for a profile
type ProfileBackends struct {
	Total   int                          `json:"total"`
	Healthy int                          `json:"healthy"`
	Backends []BackendStatus             `json:"backends"`
}

// BackendStatus represents a backend's status
type BackendStatus struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Weight      int       `json:"weight"`
	Healthy     bool      `json:"healthy"`
	LastCheck   time.Time `json:"last_check,omitempty"`
	LastHealthy time.Time `json:"last_healthy,omitempty"`
	CheckCount  int64     `json:"check_count"`
	FailCount   int64     `json:"fail_count"`
}

func (a *API) handleBackends(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	a.poolsMu.RLock()
	defer a.poolsMu.RUnlock()

	resp := BackendsResponse{
		Profiles: make(map[string]ProfileBackends),
	}

	for profileID, pool := range a.pools {
		statuses := pool.GetHealthStatuses()
		backends := make([]BackendStatus, 0, len(statuses))

		for name, status := range statuses {
			b := pool.Get(name)
			if b == nil {
				continue
			}
			backends = append(backends, BackendStatus{
				Name:        name,
				URL:         b.URL.String(),
				Weight:      b.Weight,
				Healthy:     status.Healthy,
				LastCheck:   status.LastCheck,
				LastHealthy: status.LastHealthy,
				CheckCount:  status.CheckCount,
				FailCount:   status.FailCount,
			})
		}

		resp.Profiles[profileID] = ProfileBackends{
			Total:    pool.Len(),
			Healthy:  pool.HealthyCount(),
			Backends: backends,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ReloadResponse represents the reload endpoint response
type ReloadResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func (a *API) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.reloadFunc == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ReloadResponse{
			Success: false,
			Message: "Reload not configured",
		})
		return
	}

	err := a.reloadFunc()
	resp := ReloadResponse{Success: err == nil}
	if err != nil {
		resp.Message = err.Error()
	} else {
		resp.Message = "Configuration reloaded successfully"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
