package geoip

import (
	"testing"
)

func TestDBNilReader(t *testing.T) {
	db := &DB{reader: nil}

	// LookupCountry should fail with nil reader
	_, _, err := db.LookupCountry("8.8.8.8")
	if err == nil {
		t.Error("expected error for nil reader")
	}

	// LookupASN should fail with nil reader
	_, _, err = db.LookupASN("8.8.8.8")
	if err == nil {
		t.Error("expected error for nil reader")
	}
}

func TestInvalidIP(t *testing.T) {
	db := &DB{reader: nil}

	// Test with completely invalid IP
	_, _, err := db.LookupCountry("not-an-ip")
	if err == nil {
		t.Error("expected error for invalid IP")
	}

	_, _, err = db.LookupASN("not-an-ip")
	if err == nil {
		t.Error("expected error for invalid IP")
	}

	// Test with empty string
	_, _, err = db.LookupCountry("")
	if err == nil {
		t.Error("expected error for empty IP")
	}
}

func TestCloseNilDB(t *testing.T) {
	db := &DB{reader: nil}

	// Close should not panic with nil reader
	err := db.Close()
	if err != nil {
		t.Errorf("expected no error closing nil db, got: %v", err)
	}
}

func TestOpenInvalidPath(t *testing.T) {
	_, err := Open("/nonexistent/path/to/db.mmdb")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestGlobalDBOperations(t *testing.T) {
	// Initially should be nil
	db := GetGlobal()
	if db != nil {
		t.Error("expected global DB to be nil initially")
	}

	// Loading invalid path should fail
	err := LoadGlobal("/nonexistent/path.mmdb")
	if err == nil {
		t.Error("expected error loading invalid path")
	}

	// Close should work even with nil global
	err = CloseGlobal()
	if err != nil {
		t.Errorf("expected no error closing nil global, got: %v", err)
	}
}

func TestInfoStruct(t *testing.T) {
	info := &Info{
		CountryCode: "US",
		CountryName: "United States",
		ASN:         15169,
		ASNOrg:      "Google LLC",
	}

	if info.CountryCode != "US" {
		t.Errorf("expected US, got %s", info.CountryCode)
	}

	if info.ASN != 15169 {
		t.Errorf("expected 15169, got %d", info.ASN)
	}
}

func TestLookupWithNilDB(t *testing.T) {
	db := &DB{reader: nil}

	// Lookup should return empty info without panicking
	info, err := db.Lookup("8.8.8.8")
	if err != nil {
		t.Errorf("Lookup should not return error: %v", err)
	}

	// Info should be empty but not nil
	if info == nil {
		t.Error("expected non-nil info")
	}

	if info.CountryCode != "" {
		t.Error("expected empty country code with nil reader")
	}
}
