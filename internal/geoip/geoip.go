package geoip

import (
	"fmt"
	"net"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

// DB wraps the MaxMind GeoIP2 database
type DB struct {
	reader *geoip2.Reader
	mu     sync.RWMutex
}

// Info contains GeoIP lookup results
type Info struct {
	CountryCode string
	CountryName string
	ASN         uint
	ASNOrg      string
}

// Open opens a GeoIP database file
func Open(path string) (*DB, error) {
	reader, err := geoip2.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open GeoIP database: %w", err)
	}
	return &DB{reader: reader}, nil
}

// Close closes the database
func (db *DB) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.reader != nil {
		return db.reader.Close()
	}
	return nil
}

// LookupCountry looks up country information for an IP
func (db *DB) LookupCountry(ipStr string) (string, string, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if db.reader == nil {
		return "", "", fmt.Errorf("database not loaded")
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", "", fmt.Errorf("invalid IP address: %s", ipStr)
	}

	record, err := db.reader.Country(ip)
	if err != nil {
		return "", "", err
	}

	return record.Country.IsoCode, record.Country.Names["en"], nil
}

// LookupASN looks up ASN information for an IP
func (db *DB) LookupASN(ipStr string) (uint, string, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if db.reader == nil {
		return 0, "", fmt.Errorf("database not loaded")
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, "", fmt.Errorf("invalid IP address: %s", ipStr)
	}

	record, err := db.reader.ASN(ip)
	if err != nil {
		return 0, "", err
	}

	return record.AutonomousSystemNumber, record.AutonomousSystemOrganization, nil
}

// Lookup performs a full lookup returning all available info
func (db *DB) Lookup(ipStr string) (*Info, error) {
	info := &Info{}

	// Try country lookup
	code, name, err := db.LookupCountry(ipStr)
	if err == nil {
		info.CountryCode = code
		info.CountryName = name
	}

	// Try ASN lookup
	asn, org, err := db.LookupASN(ipStr)
	if err == nil {
		info.ASN = asn
		info.ASNOrg = org
	}

	return info, nil
}

// Global instance for convenience
var globalDB *DB
var globalMu sync.RWMutex

// LoadGlobal loads the global GeoIP database
func LoadGlobal(path string) error {
	globalMu.Lock()
	defer globalMu.Unlock()

	if globalDB != nil {
		globalDB.Close()
	}

	db, err := Open(path)
	if err != nil {
		return err
	}
	globalDB = db
	return nil
}

// GetGlobal returns the global database instance
func GetGlobal() *DB {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalDB
}

// CloseGlobal closes the global database
func CloseGlobal() error {
	globalMu.Lock()
	defer globalMu.Unlock()
	if globalDB != nil {
		err := globalDB.Close()
		globalDB = nil
		return err
	}
	return nil
}
