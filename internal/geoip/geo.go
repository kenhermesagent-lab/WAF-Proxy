// Package geoip resolves IP addresses to country, coordinates and ASN.
package geoip

import (
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

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
	dir      string

	installMu  sync.Mutex
	installing bool
	installErr string
	client     *http.Client
	baseURL    string
	now        func() time.Time
}

// Open loads whichever databases exist in dir. A console-installed DB-IP Lite
// database takes precedence over a manually supplied GeoLite2 file.
func Open(dir string) *Geo {
	g := &Geo{dir: dir}
	g.mu.Lock()
	g.discoverLocked()
	g.loadLocked()
	g.mu.Unlock()
	return g
}

func (g *Geo) discoverLocked() {
	g.cityPath = firstExisting(g.dir, "dbip-city-lite.mmdb", "DBIP-City-Lite.mmdb", "GeoLite2-City.mmdb")
	g.asnPath = firstExisting(g.dir, "dbip-asn-lite.mmdb", "DBIP-ASN-Lite.mmdb", "GeoLite2-ASN.mmdb")
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
	g.discoverLocked()
	g.loadLocked()
	if g.cityPath == "" && g.asnPath == "" {
		return errors.New("no GeoIP database found")
	}
	return nil
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
	// Hold the read lock while the readers are used: Reload closes and replaces
	// them under the write lock.
	g.mu.RLock()
	defer g.mu.RUnlock()
	city, asn := g.city, g.asn

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
