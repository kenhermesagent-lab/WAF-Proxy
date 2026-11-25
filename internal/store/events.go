package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// InsertEvents writes a batch of events in one transaction.
func (s *Store) InsertEvents(events []model.Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(`INSERT INTO events(ts, proxy_id, host, src_ip, country, city, asn, lat, lon, method, path,
		query, status, bytes_in, bytes_out, latency_ms, stage, rule_id, rule_msg, action, ua, sample)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range events {
		if _, err := stmt.Exec(stamp(e.TS), e.ProxyID, e.Host, e.SrcIP, e.Country, trim(e.City, 96), e.ASN, e.Lat, e.Lon, e.Method, trim(e.Path, 512),
			trim(e.Query, 512), e.Status, e.BytesIn, e.BytesOut, e.LatencyMS, e.Stage, e.RuleID, trim(e.RuleMsg, 256), e.Action,
			trim(e.UA, 256), maxInt(e.Sample, 1)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// EventFilter selects events for the log and globe views.
type EventFilter struct {
	From        time.Time
	To          time.Time
	ProxyID     *int64
	SrcIP       string
	Country     string
	Stage       string
	Action      string
	Host        string
	Limit       int
	Offset      int
	BlockedOnly bool
}

// QueryEvents returns matching events newest first.
func (s *Store) QueryEvents(f EventFilter) ([]model.Event, int, error) {
	conds, args := s.eventWhere(f)
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE `+conds, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	args = append(args, limit, maxInt(f.Offset, 0))
	rows, err := s.db.Query(`SELECT id, ts, proxy_id, host, src_ip, country, asn, lat, lon, method, path, query, status,
		bytes_in, bytes_out, latency_ms, stage, rule_id, rule_msg, action, ua, sample
		FROM events WHERE `+conds+` ORDER BY id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []model.Event{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *e)
	}
	return out, total, rows.Err()
}

// eventWhere limits a filter to this store's site. Events carry no site of
// their own; the proxy that recorded them does.
func (s *Store) eventWhere(f EventFilter) (string, []any) {
	conds, args := eventWhere(f)
	conds += ` AND ` + eventSiteSQL
	args = append(args, s.site, s.site, s.site, s.defaultSite)
	return conds, args
}

// eventSiteSQL owns an event through its proxy, and gives events that never
// reached one to the default site so an install's history stays visible.
const eventSiteSQL = `(? = 0 OR proxy_id IN (SELECT id FROM proxies WHERE site_id = ?)
	OR (proxy_id IS NULL AND ? = ?))`

func eventWhere(f EventFilter) (string, []any) {
	where := []string{"ts >= ?", "ts <= ?"}
	args := []any{stamp(orTime(f.From, time.Now().Add(-24*time.Hour))), stamp(orTime(f.To, time.Now()))}
	if f.ProxyID != nil {
		where = append(where, "proxy_id = ?")
		args = append(args, *f.ProxyID)
	}
	if f.SrcIP != "" {
		where = append(where, "src_ip = ?")
		args = append(args, f.SrcIP)
	}
	if f.Country != "" {
		where = append(where, "country = ?")
		args = append(args, f.Country)
	}
	if f.Stage != "" {
		where = append(where, "stage = ?")
		args = append(args, f.Stage)
	}
	if f.Action != "" {
		where = append(where, "action = ?")
		args = append(args, f.Action)
	}
	if f.Host != "" {
		where = append(where, "host = ?")
		args = append(args, f.Host)
	}
	if f.BlockedOnly {
		where = append(where, "action IN ('block','ban','challenge')")
	}
	return strings.Join(where, " AND "), args
}

// EachEvent streams up to limit matching events to fn for a CSV download. It
// uses the same filters as the log view but bypasses the interactive page cap,
// so a 100k-row export never has to exist in memory at once.
func (s *Store) EachEvent(f EventFilter, limit int, fn func(model.Event) error) error {
	if limit <= 0 {
		limit = 10000
	}
	if limit > 100000 {
		limit = 100000
	}
	conds, args := s.eventWhere(f)
	args = append(args, limit)
	rows, err := s.db.Query(`SELECT id, ts, proxy_id, host, src_ip, country, asn, lat, lon, method, path, query, status,
		bytes_in, bytes_out, latency_ms, stage, rule_id, rule_msg, action, ua, sample
		FROM events WHERE `+conds+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return err
		}
		if err := fn(*e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// IPSummary aggregates one source address for the IP explorer.
type IPSummary struct {
	IP        string    `json:"ip"`
	Country   string    `json:"country"`
	ASN       int       `json:"asn"`
	Requests  int64     `json:"requests"`
	Blocked   int64     `json:"blocked"`
	BytesOut  int64     `json:"bytes_out"`
	Hosts     int       `json:"hosts"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

const ipAggregate = `SELECT src_ip, MAX(country), MAX(asn), COUNT(*),
	COALESCE(SUM(CASE WHEN action IN ('block','ban','challenge') THEN 1 ELSE 0 END),0),
	COALESCE(SUM(bytes_out),0), COUNT(DISTINCT host), MIN(ts), MAX(ts)
	FROM events WHERE `

func scanIPSummary(row interface{ Scan(...any) error }) (IPSummary, error) {
	var out IPSummary
	var first, last string
	err := row.Scan(&out.IP, &out.Country, &out.ASN, &out.Requests, &out.Blocked,
		&out.BytesOut, &out.Hosts, &first, &last)
	if err != nil {
		return IPSummary{}, err
	}
	out.FirstSeen = parseStamp(first)
	out.LastSeen = parseStamp(last)
	return out, nil
}

// IPSummaries lists the busiest matching source addresses. q is an IP prefix.
func (s *Store) IPSummaries(f EventFilter, q string, limit int) ([]IPSummary, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	conds, args := s.eventWhere(f)
	if q = strings.TrimSpace(q); q != "" {
		esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q)
		conds += ` AND src_ip LIKE ? ESCAPE '\'`
		args = append(args, esc+"%")
	}
	args = append(args, limit)
	rows, err := s.db.Query(ipAggregate+conds+` GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IPSummary{}
	for rows.Next() {
		sum, err := scanIPSummary(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sum)
	}
	return out, rows.Err()
}

// IPSummary aggregates exactly one address; a missing address yields a zero
// summary so the detail view can still show ban state.
func (s *Store) IPSummary(ip string, from, to time.Time) (IPSummary, error) {
	conds, args := s.eventWhere(EventFilter{From: from, To: to, SrcIP: ip})
	sum, err := scanIPSummary(s.db.QueryRow(ipAggregate+conds+` GROUP BY src_ip`, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return IPSummary{IP: ip}, nil
	}
	return sum, err
}

func scanEvent(row interface{ Scan(...any) error }) (*model.Event, error) {
	var e model.Event
	var ts string
	var proxyID *int64
	if err := row.Scan(&e.ID, &ts, &proxyID, &e.Host, &e.SrcIP, &e.Country, &e.ASN, &e.Lat, &e.Lon, &e.Method, &e.Path,
		&e.Query, &e.Status, &e.BytesIn, &e.BytesOut, &e.LatencyMS, &e.Stage, &e.RuleID, &e.RuleMsg, &e.Action,
		&e.UA, &e.Sample); err != nil {
		return nil, err
	}
	e.TS = parseStamp(ts)
	e.ProxyID = proxyID
	return &e, nil
}

// EventTotals is a filtered window's aggregate, independent of how many rows a
// caller fetched.
type EventTotals struct {
	Total   int
	Blocked int
	Sources int
	Hosts   int
}

func (s *Store) EventTotals(f EventFilter) (EventTotals, error) {
	conds, args := s.eventWhere(f)
	var t EventTotals
	err := s.db.QueryRow(`SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN action IN ('block','ban','challenge') THEN 1 ELSE 0 END),0),
		COUNT(DISTINCT src_ip), COUNT(DISTINCT host) FROM events WHERE `+conds, args...).
		Scan(&t.Total, &t.Blocked, &t.Sources, &t.Hosts)
	return t, err
}

// DeleteEventsBefore drops events older than the retention window.
func (s *Store) DeleteEventsBefore(t time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM events WHERE ts < ? AND `+eventSiteSQL,
		stamp(t), s.site, s.site, s.site, s.defaultSite)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountEvents returns the number of stored events.
func (s *Store) CountEvents() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE `+eventSiteSQL,
		s.site, s.site, s.site, s.defaultSite).Scan(&n)
	return n, err
}

// NamedCount is an aggregated counter for dashboards.
type NamedCount struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// TopBy returns the highest-count values of a whitelisted column since a time.
func (s *Store) TopBy(column string, since time.Time, limit int) ([]NamedCount, error) {
	allowed := map[string]string{
		"src_ip":  "src_ip",
		"country": "country",
		"host":    "host",
		"stage":   "stage",
		"rule_id": "rule_id",
		"action":  "action",
	}
	col, ok := allowed[column]
	if !ok {
		return nil, fmt.Errorf("topby: unsupported column %q", column)
	}
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	rows, err := s.db.Query(`SELECT `+col+`, COUNT(*) AS n FROM events
		WHERE ts >= ? AND `+col+` <> '' AND `+eventSiteSQL+`
		GROUP BY `+col+` ORDER BY n DESC LIMIT ?`, stamp(since), s.site, s.site, s.site, s.defaultSite, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NamedCount{}
	for rows.Next() {
		var c NamedCount
		if err := rows.Scan(&c.Name, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Totals summarises traffic since a point in time.
type Totals struct {
	Requests int64 `json:"requests"`
	Blocked  int64 `json:"blocked"`
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
	SrcIPs   int64 `json:"src_ips"`
}

// Summary computes the dashboard totals.
func (s *Store) Summary(since time.Time) (Totals, error) {
	var t Totals
	err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN action IN ('block','ban','challenge') THEN 1 ELSE 0 END),0),
		COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0), COUNT(DISTINCT src_ip)
		FROM events WHERE ts >= ?`, stamp(since)).
		Scan(&t.Requests, &t.Blocked, &t.BytesIn, &t.BytesOut, &t.SrcIPs)
	return t, err
}

// GlobePoint is one aggregated attack arc for the globe view.
type GlobePoint struct {
	Country  string  `json:"country"`
	City     string  `json:"city,omitempty"`
	Host     string  `json:"host"`
	Category string  `json:"category"`
	Count    int64   `json:"count"`
	LastSeen string  `json:"last_seen"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
}

// Globe returns attacks grouped by country, city, host and category since a
// time. Splitting by city is what lets the map show city dots at depth; a
// database without city data simply groups on an empty city.
func (s *Store) Globe(since time.Time) ([]GlobePoint, error) {
	rows, err := s.db.Query(`SELECT country, city, host, stage, COUNT(*), MAX(ts), AVG(lat), AVG(lon)
		FROM events WHERE ts >= ? AND action IN ('block','ban','challenge') AND country <> ''
		AND `+eventSiteSQL+`
		GROUP BY country, city, host, stage ORDER BY COUNT(*) DESC LIMIT 300`,
		stamp(since), s.site, s.site, s.site, s.defaultSite)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GlobePoint{}
	for rows.Next() {
		var p GlobePoint
		if err := rows.Scan(&p.Country, &p.City, &p.Host, &p.Category, &p.Count, &p.LastSeen, &p.Lat, &p.Lon); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GlobeHit is a single blocked request on the globe, newest first, so the
// console can draw each hit as it lands instead of only the window aggregate.
type GlobeHit struct {
	ID       int64   `json:"id"`
	TS       string  `json:"ts"`
	Country  string  `json:"country"`
	Host     string  `json:"host"`
	Category string  `json:"category"`
	Status   int     `json:"status"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
}

// RecentHits returns individual blocked events since a time. The same filter
// as Globe applies, so the live arcs and the aggregate dots agree.
func (s *Store) RecentHits(since time.Time, limit int) ([]GlobeHit, error) {
	if limit <= 0 || limit > 200 {
		limit = 60
	}
	rows, err := s.db.Query(`SELECT id, ts, country, host, stage, status, lat, lon
		FROM events WHERE ts >= ? AND action IN ('block','ban','challenge') AND country <> ''
		AND `+eventSiteSQL+`
		ORDER BY ts DESC, id DESC LIMIT ?`, stamp(since), s.site, s.site, s.site, s.defaultSite, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GlobeHit{}
	for rows.Next() {
		var h GlobeHit
		if err := rows.Scan(&h.ID, &h.TS, &h.Country, &h.Host, &h.Category, &h.Status, &h.Lat, &h.Lon); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// RollupFlows aggregates the previous hour into the flows table.
func (s *Store) RollupFlows(hour time.Time) error {
	h := hour.UTC().Truncate(time.Hour)
	end := h.Add(time.Hour)
	_, err := s.db.Exec(`INSERT INTO flows(hour, proxy_id, reqs, bytes_in, bytes_out, blocked)
		SELECT ?, COALESCE(proxy_id, 0), COUNT(*), COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0),
		       COALESCE(SUM(CASE WHEN action IN ('block','ban','challenge') THEN 1 ELSE 0 END),0)
		FROM events WHERE ts >= ? AND ts < ? GROUP BY COALESCE(proxy_id, 0)
		ON CONFLICT(hour, proxy_id) DO UPDATE SET reqs = excluded.reqs, bytes_in = excluded.bytes_in,
			bytes_out = excluded.bytes_out, blocked = excluded.blocked`,
		stamp(h), stamp(h), stamp(end))
	return err
}

// ListFlows returns the last n hourly rollups.
func (s *Store) ListFlows(limit int) ([]model.Flow, error) {
	if limit <= 0 || limit > 1680 {
		limit = 168
	}
	rows, err := s.db.Query(`SELECT hour, proxy_id, reqs, bytes_in, bytes_out, blocked
		FROM flows WHERE (? = 0 OR proxy_id IN (SELECT id FROM proxies WHERE site_id = ?))
		ORDER BY hour DESC LIMIT ?`, s.site, s.site, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Flow{}
	for rows.Next() {
		var f model.Flow
		var hour string
		if err := rows.Scan(&hour, &f.ProxyID, &f.Reqs, &f.BytesIn, &f.BytesOut, &f.Blocked); err != nil {
			return nil, err
		}
		f.Hour = parseStamp(hour)
		out = append(out, f)
	}
	return out, rows.Err()
}

// DBStats returns approximate storage usage in bytes.
func (s *Store) DBStats() (int64, error) {
	var pageCount, pageSize int64
	if err := s.db.QueryRow(`PRAGMA page_count`).Scan(&pageCount); err != nil {
		return 0, err
	}
	if err := s.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		return 0, err
	}
	return pageCount * pageSize, nil
}

func orTime(t, fallback time.Time) time.Time {
	if t.IsZero() {
		return fallback
	}
	return t
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
