package decoy

import (
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"
)

// Strategy defines the decoy behavior
type Strategy interface {
	Serve(w http.ResponseWriter, r *http.Request)
}

// StaticDecoy serves static content
type StaticDecoy struct {
	StatusCode  int
	Body        []byte
	ContentType string
	Headers     map[string]string
}

// NewStaticDecoy creates a static decoy from inline content
func NewStaticDecoy(statusCode int, body string, contentType string) *StaticDecoy {
	if contentType == "" {
		contentType = "text/html; charset=utf-8"
	}
	return &StaticDecoy{
		StatusCode:  statusCode,
		Body:        []byte(body),
		ContentType: contentType,
		Headers:     make(map[string]string),
	}
}

// NewStaticDecoyFromFile creates a static decoy from a file
func NewStaticDecoyFromFile(statusCode int, filePath string, contentType string) (*StaticDecoy, error) {
	body, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read decoy file: %w", err)
	}

	if contentType == "" {
		contentType = detectContentType(filePath)
	}

	return &StaticDecoy{
		StatusCode:  statusCode,
		Body:        body,
		ContentType: contentType,
		Headers:     make(map[string]string),
	}, nil
}

// Serve serves the static decoy content
func (d *StaticDecoy) Serve(w http.ResponseWriter, r *http.Request) {
	for k, v := range d.Headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", d.ContentType)
	w.WriteHeader(d.StatusCode)
	w.Write(d.Body)
}

// RedirectDecoy sends a redirect response
type RedirectDecoy struct {
	StatusCode int    // 301, 302, 307, 308
	Location   string
}

// NewRedirectDecoy creates a redirect decoy
func NewRedirectDecoy(statusCode int, location string) *RedirectDecoy {
	if statusCode < 300 || statusCode > 308 {
		statusCode = http.StatusFound // default to 302
	}
	return &RedirectDecoy{
		StatusCode: statusCode,
		Location:   location,
	}
}

// Serve sends the redirect response
func (d *RedirectDecoy) Serve(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, d.Location, d.StatusCode)
}

// TarpitDecoy delays the response
type TarpitDecoy struct {
	MinDelay time.Duration
	MaxDelay time.Duration
	inner    Strategy
}

// NewTarpitDecoy creates a tarpit decoy
func NewTarpitDecoy(minDelay, maxDelay time.Duration, inner Strategy) *TarpitDecoy {
	return &TarpitDecoy{
		MinDelay: minDelay,
		MaxDelay: maxDelay,
		inner:    inner,
	}
}

// Serve delays and then serves the inner response
func (d *TarpitDecoy) Serve(w http.ResponseWriter, r *http.Request) {
	delay := d.MinDelay
	if d.MaxDelay > d.MinDelay {
		delay += time.Duration(rand.Int63n(int64(d.MaxDelay - d.MinDelay)))
	}
	time.Sleep(delay)

	if d.inner != nil {
		d.inner.Serve(w, r)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

// DropDecoy silently drops the connection by not responding
type DropDecoy struct{}

// Serve hijacks and closes the connection
func (d *DropDecoy) Serve(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		// Can't hijack, just close without response
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	conn.Close()
}

func detectContentType(filePath string) string {
	switch {
	case hasExtension(filePath, ".html", ".htm"):
		return "text/html; charset=utf-8"
	case hasExtension(filePath, ".json"):
		return "application/json"
	case hasExtension(filePath, ".xml"):
		return "application/xml"
	case hasExtension(filePath, ".txt"):
		return "text/plain; charset=utf-8"
	case hasExtension(filePath, ".css"):
		return "text/css"
	case hasExtension(filePath, ".js"):
		return "application/javascript"
	default:
		return "application/octet-stream"
	}
}

func hasExtension(path string, exts ...string) bool {
	for _, ext := range exts {
		if len(path) >= len(ext) && path[len(path)-len(ext):] == ext {
			return true
		}
	}
	return false
}
