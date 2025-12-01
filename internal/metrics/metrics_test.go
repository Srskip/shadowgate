package metrics

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestMetricsRecordRequest(t *testing.T) {
	m := New()

	m.RecordRequest("profile1", "10.0.0.1", "allow_forward", 15.5)
	m.RecordRequest("profile1", "10.0.0.2", "deny_decoy", 10.0)
	m.RecordRequest("profile2", "10.0.0.1", "allow_forward", 20.0)

	snapshot := m.GetSnapshot()

	if snapshot.TotalRequests != 3 {
		t.Errorf("expected 3 total requests, got %d", snapshot.TotalRequests)
	}

	if snapshot.AllowedRequests != 2 {
		t.Errorf("expected 2 allowed requests, got %d", snapshot.AllowedRequests)
	}

	if snapshot.DeniedRequests != 1 {
		t.Errorf("expected 1 denied request, got %d", snapshot.DeniedRequests)
	}

	if snapshot.UniqueIPs != 2 {
		t.Errorf("expected 2 unique IPs, got %d", snapshot.UniqueIPs)
	}

	if snapshot.ProfileRequests["profile1"] != 2 {
		t.Errorf("expected 2 requests for profile1, got %d", snapshot.ProfileRequests["profile1"])
	}

	if snapshot.ProfileRequests["profile2"] != 1 {
		t.Errorf("expected 1 request for profile2, got %d", snapshot.ProfileRequests["profile2"])
	}
}

func TestMetricsRuleHits(t *testing.T) {
	m := New()

	m.RecordRuleHit("ip_allow")
	m.RecordRuleHit("ip_allow")
	m.RecordRuleHit("ua_whitelist")

	snapshot := m.GetSnapshot()

	if snapshot.RuleHits["ip_allow"] != 2 {
		t.Errorf("expected 2 ip_allow hits, got %d", snapshot.RuleHits["ip_allow"])
	}

	if snapshot.RuleHits["ua_whitelist"] != 1 {
		t.Errorf("expected 1 ua_whitelist hit, got %d", snapshot.RuleHits["ua_whitelist"])
	}
}

func TestMetricsHandler(t *testing.T) {
	m := New()
	m.RecordRequest("test", "10.0.0.1", "allow_forward", 10.0)

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()

	m.Handler()(rr, req)

	if rr.Code != 200 {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	var snapshot Snapshot
	if err := json.NewDecoder(rr.Body).Decode(&snapshot); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if snapshot.TotalRequests != 1 {
		t.Errorf("expected 1 total request in response, got %d", snapshot.TotalRequests)
	}
}

func TestMetricsReset(t *testing.T) {
	m := New()

	m.RecordRequest("test", "10.0.0.1", "allow_forward", 10.0)
	m.Reset()

	snapshot := m.GetSnapshot()

	if snapshot.TotalRequests != 0 {
		t.Errorf("expected 0 total requests after reset, got %d", snapshot.TotalRequests)
	}

	if snapshot.UniqueIPs != 0 {
		t.Errorf("expected 0 unique IPs after reset, got %d", snapshot.UniqueIPs)
	}
}
