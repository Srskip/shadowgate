package decoy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStaticDecoy(t *testing.T) {
	decoy := NewStaticDecoy(http.StatusOK, "<html>Test</html>", "text/html")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	decoy.Serve(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	body, _ := io.ReadAll(rr.Body)
	if string(body) != "<html>Test</html>" {
		t.Errorf("unexpected body: %q", string(body))
	}

	if rr.Header().Get("Content-Type") != "text/html" {
		t.Errorf("unexpected content-type: %s", rr.Header().Get("Content-Type"))
	}
}

func TestStaticDecoyDefaultContentType(t *testing.T) {
	decoy := NewStaticDecoy(http.StatusOK, "test", "")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	decoy.Serve(rr, req)

	if rr.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("expected default content-type, got: %s", rr.Header().Get("Content-Type"))
	}
}

func TestRedirectDecoy(t *testing.T) {
	decoy := NewRedirectDecoy(http.StatusFound, "https://example.com")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	decoy.Serve(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected status 302, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location != "https://example.com" {
		t.Errorf("expected redirect to example.com, got %s", location)
	}
}

func TestRedirectDecoyDefaultStatus(t *testing.T) {
	// Invalid status should default to 302
	decoy := NewRedirectDecoy(999, "https://example.com")

	if decoy.StatusCode != http.StatusFound {
		t.Errorf("expected default 302, got %d", decoy.StatusCode)
	}
}

func TestTarpitDecoy(t *testing.T) {
	inner := NewStaticDecoy(http.StatusOK, "delayed", "")
	decoy := NewTarpitDecoy(50*time.Millisecond, 100*time.Millisecond, inner)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	start := time.Now()
	decoy.Serve(rr, req)
	elapsed := time.Since(start)

	if elapsed < 50*time.Millisecond {
		t.Errorf("expected at least 50ms delay, got %v", elapsed)
	}

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestDetectContentType(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"file.html", "text/html; charset=utf-8"},
		{"file.htm", "text/html; charset=utf-8"},
		{"file.json", "application/json"},
		{"file.xml", "application/xml"},
		{"file.txt", "text/plain; charset=utf-8"},
		{"file.css", "text/css"},
		{"file.js", "application/javascript"},
		{"file.bin", "application/octet-stream"},
	}

	for _, tc := range tests {
		result := detectContentType(tc.path)
		if result != tc.expected {
			t.Errorf("path %s: expected %s, got %s", tc.path, tc.expected, result)
		}
	}
}
