package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewLogger(t *testing.T) {
	logger, err := New(Config{
		Level:  "info",
		Output: "stdout",
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestLogLevels(t *testing.T) {
	var buf bytes.Buffer

	logger := &Logger{
		output: &buf,
		level:  LevelInfo,
	}

	// Debug should be filtered
	logger.Debug("debug message", nil)
	if buf.Len() > 0 {
		t.Error("debug message should be filtered at info level")
	}

	// Info should pass
	logger.Info("info message", nil)
	if buf.Len() == 0 {
		t.Error("info message should be logged")
	}

	// Parse the log entry
	var entry Entry
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("failed to parse log entry: %v", err)
	}

	if entry.Level != "info" {
		t.Errorf("expected level 'info', got %q", entry.Level)
	}
	if entry.Message != "info message" {
		t.Errorf("expected message 'info message', got %q", entry.Message)
	}
}

func TestLogWithFields(t *testing.T) {
	var buf bytes.Buffer

	logger := &Logger{
		output: &buf,
		level:  LevelDebug,
	}

	fields := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	}
	logger.Info("test message", fields)

	var entry Entry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log entry: %v", err)
	}

	if entry.Fields["key1"] != "value1" {
		t.Errorf("expected field key1='value1', got %v", entry.Fields["key1"])
	}
	if entry.Fields["key2"].(float64) != 42 {
		t.Errorf("expected field key2=42, got %v", entry.Fields["key2"])
	}
}

func TestLogRequest(t *testing.T) {
	var buf bytes.Buffer

	logger := &Logger{
		output: &buf,
		level:  LevelInfo,
	}

	req := RequestLog{
		Timestamp:  time.Now().UTC(),
		ProfileID:  "test-profile",
		ClientIP:   "10.0.0.1",
		Method:     "GET",
		Path:       "/api/test",
		UserAgent:  "Mozilla/5.0",
		Action:     "allow_forward",
		Reason:     "IP in allow list",
		Labels:     []string{"allowed"},
		StatusCode: 200,
		Duration:   15.5,
	}

	logger.LogRequest(req)

	var logged RequestLog
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("failed to parse request log: %v", err)
	}

	if logged.ProfileID != "test-profile" {
		t.Errorf("expected profile_id 'test-profile', got %q", logged.ProfileID)
	}
	if logged.ClientIP != "10.0.0.1" {
		t.Errorf("expected client_ip '10.0.0.1', got %q", logged.ClientIP)
	}
	if logged.Action != "allow_forward" {
		t.Errorf("expected action 'allow_forward', got %q", logged.Action)
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected Level
	}{
		{"debug", LevelDebug},
		{"info", LevelInfo},
		{"warn", LevelWarn},
		{"error", LevelError},
		{"unknown", LevelInfo}, // default
		{"", LevelInfo},        // default
	}

	for _, tc := range tests {
		result := ParseLevel(tc.input)
		if result != tc.expected {
			t.Errorf("ParseLevel(%q): expected %v, got %v", tc.input, tc.expected, result)
		}
	}
}

func TestLevelString(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{LevelDebug, "debug"},
		{LevelInfo, "info"},
		{LevelWarn, "warn"},
		{LevelError, "error"},
	}

	for _, tc := range tests {
		if tc.level.String() != tc.expected {
			t.Errorf("expected %q, got %q", tc.expected, tc.level.String())
		}
	}
}
