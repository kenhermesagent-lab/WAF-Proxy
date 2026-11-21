// Package geoip resolves IP addresses to country, coordinates and ASN.
package geoip

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Location is the resolved data for one address.
type Location struct {
	Country string
	City    string
	Lat     float64
	Lon     float64
	ASN     int
	Org     string
}

type cityRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

type asnRecord struct {
	ASN int    `maxminddb:"autonomous_system_number"`
	Org string `maxminddb:"autonomous_system_organization"`
}

// Geo holds optional MMDB readers. A missing database disables that field but
// never fails the process.
type Geo struct {
	mu       sync.RWMutex
	city     *maxminddb.Reader
	asn      *maxminddb.Reader
	cityPath string
	asnPath  string
}

// Open loads whichever databases exist in dir. Recognised names:
// GeoLite2-City.mmdb, GeoLite2-ASN.mmdb, dbip-city-lite.mmdb, dbip-asn-lite.mmdb.
func Open(dir string) *Geo {
	g := &Geo{
		cityPath: firstExisting(dir, "GeoLite2-City.mmdb", "dbip-city-lite.mmdb", "DBIP-City-Lite.mmdb"),
		asnPath:  firstExisting(dir, "GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb", "DBIP-ASN-Lite.mmdb"),
	}
	g.mu.Lock()
	g.loadLocked()
	g.mu.Unlock()
	return g
}

func firstExisting(dir string, names ...string) string {
	for _, n := range names {
		p := filepath.Join(dir, n)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func (g *Geo) loadLocked() {
	if g.city != nil {
		_ = g.city.Close()
		g.city = nil
	}
	if g.asn != nil {
		_ = g.asn.Close()
		g.asn = nil
	}
	if g.cityPath != "" {
		if r, err := maxminddb.Open(g.cityPath); err == nil {
			g.city = r
		}
	}
	if g.asnPath != "" {
		if r, err := maxminddb.Open(g.asnPath); err == nil {
			g.asn = r
		}
	}
}

// Reload reopens the databases, used after an update.
func (g *Geo) Reload() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cityPath = firstExisting(filepath.Dir(orPath(g.cityPath, ".")), "GeoLite2-City.mmdb", "dbip-city-lite.mmdb", "DBIP-City-Lite.mmdb")
	g.asnPath = firstExisting(filepath.Dir(orPath(g.asnPath, ".")), "GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb", "DBIP-ASN-Lite.mmdb")
	g.loadLocked()
	if g.cityPath == "" && g.asnPath == "" {
		return errors.New("no GeoIP database found")
	}
	return nil
}

func orPath(p, fallback string) string {
	if p == "" {
		return fallback
	}
	return p
}

// Available reports whether country/coordinates can be resolved.
func (g *Geo) Available() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.city != nil || g.asn != nil
}

// ASNAvailable reports whether ASN lookups are possible.
func (g *Geo) ASNAvailable() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.asn != nil
}

// Paths returns the loaded database paths for the status page.
func (g *Geo) Paths() (city, asn string) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.cityPath, g.asnPath
}

// Lookup resolves an address. Missing databases simply leave fields zero.
func (g *Geo) Lookup(addr netip.Addr) Location {
	var loc Location
	if !addr.IsValid() {
		return loc
	}
	addr = addr.Unmap()
	g.mu.RLock()
	city, asn := g.city, g.asn
	g.mu.RUnlock()

	if city != nil {
		var rec cityRecord
		if err := city.Lookup(addr).Decode(&rec); err == nil {
			loc.Country = rec.Country.ISOCode
			loc.Lat = rec.Location.Latitude
			loc.Lon = rec.Location.Longitude
			loc.City = rec.City.Names["en"]
		}
	}
	if asn != nil {
		var rec asnRecord
		if err := asn.Lookup(addr).Decode(&rec); err == nil {
			loc.ASN = rec.ASN
			loc.Org = rec.Org
		}
	}
	return loc
}
