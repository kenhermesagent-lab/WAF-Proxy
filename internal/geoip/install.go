package geoip

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Attribution is required by the DB-IP Lite licence, which is CC BY 4.0.
const Attribution = "IP Geolocation by DB-IP (https://db-ip.com)"

const (
	maxCompressedDB = 200 << 20
	maxExpandedDB   = 1 << 30
)

// Status is the installer and loader state shown in Settings.
type Status struct {
	Available   bool       `json:"available"`
	City        bool       `json:"city"`
	ASN         bool       `json:"asn"`
	CityPath    string     `json:"city_path,omitempty"`
	ASNPath     string     `json:"asn_path,omitempty"`
	CityUpdated *time.Time `json:"city_updated,omitempty"`
	ASNUpdated  *time.Time `json:"asn_updated,omitempty"`
	Installing  bool       `json:"installing"`
	LastError   string     `json:"last_error,omitempty"`
	Attribution string     `json:"attribution"`
}

// StartInstall downloads the current DB-IP Lite city and ASN databases in the
// background. It returns false when an install is already running.
func (g *Geo) StartInstall() bool {
	g.installMu.Lock()
	if g.installing {
		g.installMu.Unlock()
		return false
	}
	g.installing = true
	g.installErr = ""
	g.installMu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		err := g.install(ctx)
		g.installMu.Lock()
		g.installing = false
		if err != nil {
			g.installErr = err.Error()
		}
		g.installMu.Unlock()
	}()
	return true
}

// Install downloads and validates both databases before replacing either live
// file, so a failed download cannot leave GeoIP with half an update.
func (g *Geo) Install(ctx context.Context) error {
	g.installMu.Lock()
	if g.installing {
		g.installMu.Unlock()
		return errors.New("a GeoIP install is already running")
	}
	g.installing = true
	g.installErr = ""
	g.installMu.Unlock()
	defer func() {
		g.installMu.Lock()
		g.installing = false
		g.installMu.Unlock()
	}()
	return g.install(ctx)
}

func (g *Geo) install(ctx context.Context) error {
	if g.dir == "" {
		return errors.New("GeoIP data directory is not configured")
	}
	if err := os.MkdirAll(g.dir, 0o750); err != nil {
		return fmt.Errorf("create GeoIP directory: %w", err)
	}
	city, err := g.download(ctx, "dbip-city-lite", "city")
	if err != nil {
		g.setInstallError(err)
		return err
	}
	asn, err := g.download(ctx, "dbip-asn-lite", "asn")
	if err != nil {
		_ = os.Remove(city)
		g.setInstallError(err)
		return err
	}
	if err := replaceFile(city, filepath.Join(g.dir, "dbip-city-lite.mmdb")); err != nil {
		_ = os.Remove(city)
		_ = os.Remove(asn)
		g.setInstallError(err)
		return err
	}
	if err := replaceFile(asn, filepath.Join(g.dir, "dbip-asn-lite.mmdb")); err != nil {
		_ = os.Remove(asn)
		g.setInstallError(err)
		return err
	}
	if err := g.Reload(); err != nil {
		g.setInstallError(err)
		return err
	}
	g.installMu.Lock()
	g.installErr = ""
	g.installMu.Unlock()
	return nil
}

func (g *Geo) setInstallError(err error) {
	g.installMu.Lock()
	g.installErr = err.Error()
	g.installMu.Unlock()
}

func (g *Geo) download(ctx context.Context, base, label string) (string, error) {
	client := g.client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	var lastErr error
	for _, period := range g.periods() {
		url := fmt.Sprintf("%s/free/%s-%s.mmdb.gz", g.downloadBase(), base, period)
		path, err := g.fetchMMDB(ctx, client, url, label)
		if err == nil {
			return path, nil
		}
		if errors.Is(err, errNotFound) {
			lastErr = err
			continue
		}
		return "", err
	}
	if lastErr == nil {
		lastErr = errors.New("no download period available")
	}
	return "", lastErr
}

var errNotFound = errors.New("database not published")

func (g *Geo) downloadBase() string {
	if g.baseURL != "" {
		return g.baseURL
	}
	return "https://download.db-ip.com"
}

func (g *Geo) periods() []string {
	now := time.Now().UTC()
	if g.now != nil {
		now = g.now().UTC()
	}
	periods := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		periods = append(periods, now.AddDate(0, -i, 0).Format("2006-01"))
	}
	return periods
}

func (g *Geo) fetchMMDB(ctx context.Context, client *http.Client, url, label string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "wafproxy-geoip/1.0")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download %s database: %w", label, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s database: HTTP %d", label, resp.StatusCode)
	}

	tmp, err := os.CreateTemp(g.dir, ".geoip-*")
	if err != nil {
		return "", fmt.Errorf("create temporary database: %w", err)
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()

	gz, err := gzip.NewReader(io.LimitReader(resp.Body, maxCompressedDB))
	if err != nil {
		tmp.Close()
		return "", fmt.Errorf("decode %s database: %w", label, err)
	}
	written, copyErr := io.Copy(tmp, io.LimitReader(gz, maxExpandedDB+1))
	closeErr := gz.Close()
	if copyErr != nil {
		tmp.Close()
		return "", fmt.Errorf("read %s database: %w", label, copyErr)
	}
	if closeErr != nil {
		tmp.Close()
		return "", fmt.Errorf("finish %s database: %w", label, closeErr)
	}
	if written == 0 || written > maxExpandedDB {
		tmp.Close()
		return "", fmt.Errorf("%s database has an unexpected size", label)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close %s database: %w", label, err)
	}
	reader, err := maxminddb.Open(tmpPath)
	if err != nil {
		return "", fmt.Errorf("%s database is not a valid MMDB file: %w", label, err)
	}
	_ = reader.Close()
	if err := os.Chmod(tmpPath, 0o640); err != nil {
		return "", fmt.Errorf("secure %s database: %w", label, err)
	}
	ok = true
	return tmpPath, nil
}

func replaceFile(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("install GeoIP database: %w", err)
	}
	return nil
}

// Status reports the loaded files and any install failure.
func (g *Geo) Status() Status {
	g.installMu.Lock()
	st := Status{Installing: g.installing, LastError: g.installErr, Attribution: Attribution}
	g.installMu.Unlock()

	g.mu.RLock()
	st.Available = g.city != nil || g.asn != nil
	st.City = g.city != nil
	st.ASN = g.asn != nil
	st.CityPath = g.cityPath
	st.ASNPath = g.asnPath
	st.CityUpdated = fileTime(g.cityPath)
	st.ASNUpdated = fileTime(g.asnPath)
	g.mu.RUnlock()
	return st
}

func fileTime(path string) *time.Time {
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	t := info.ModTime().UTC()
	return &t
}
