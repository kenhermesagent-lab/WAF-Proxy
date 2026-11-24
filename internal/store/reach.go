package store

import "time"

// sensitiveEndpoint matches the paths an application authenticates or
// administers through. The attack map is otherwise only about traffic that was
// refused; this is the handful of endpoints where a request that got through
// matters more than the ones that did not.
const sensitiveEndpoint = `(LOWER(path) LIKE '%login%' OR LOWER(path) LIKE '%logon%'
	OR LOWER(path) LIKE '%signin%' OR LOWER(path) LIKE '%sign-in%' OR LOWER(path) LIKE '%sign_in%'
	OR LOWER(path) LIKE '%/auth%' OR LOWER(path) LIKE '%oauth%' OR LOWER(path) LIKE '%/sso%'
	OR LOWER(path) LIKE '%/saml%' OR LOWER(path) LIKE '%/admin%' OR LOWER(path) LIKE '%wp-login%'
	OR LOWER(path) LIKE '%wp-admin%' OR LOWER(path) LIKE '%phpmyadmin%' OR LOWER(path) LIKE '%adminer%'
	OR LOWER(path) LIKE '%/token%' OR LOWER(path) LIKE '%/session%' OR LOWER(path) LIKE '%/console%'
	OR LOWER(path) LIKE '%/manage%' OR LOWER(path) LIKE '%/setup%' OR LOWER(path) LIKE '%/install%'
	OR LOWER(path) LIKE '%xmlrpc%' OR LOWER(path) LIKE '%/actuator%' OR LOWER(path) LIKE '%/server-status%')`

// ReachRow is one endpoint that allowed requests arrived at, split by source
// country so the globe can draw the ones that got through as arcs.
type ReachRow struct {
	Host     string  `json:"host"`
	Path     string  `json:"path"`
	Method   string  `json:"method"`
	Status   int     `json:"status"`
	Country  string  `json:"country"`
	Count    int64   `json:"count"`
	LastSeen string  `json:"last_seen"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
}

// ReachSource is a client address that reached a sensitive endpoint. It is the
// half of the picture a blocked-only feed never shows: who was allowed in.
type ReachSource struct {
	IP       string `json:"ip"`
	Country  string `json:"country"`
	ASN      int    `json:"asn"`
	Count    int64  `json:"count"`
	LastSeen string `json:"last_seen"`
}

// NearMiss is a detection that fired without blocking: a WAF profile in detect
// mode, a logged feed match, or a logged bundle rule. Each of these would have
// been a refusal under a stricter setting.
type NearMiss struct {
	Stage    string `json:"stage"`
	RuleID   string `json:"rule_id"`
	RuleMsg  string `json:"rule_msg"`
	Host     string `json:"host"`
	Path     string `json:"path"`
	Country  string `json:"country"`
	Count    int64  `json:"count"`
	LastSeen string `json:"last_seen"`
}

// Reach is the exposure half of the attack map: what was allowed through, which
// application endpoints it landed on, who sent it, and which detections fired
// without blocking.
type Reach struct {
	Since     time.Time     `json:"since"`
	Allowed   int64         `json:"allowed"`
	Reached   int64         `json:"reached"`
	Endpoints []ReachRow    `json:"endpoints"`
	Sources   []ReachSource `json:"sources"`
	NearMiss  []NearMiss    `json:"near_miss"`
}

// ReachSnapshot aggregates the allowed side of a window. Queries are bounded by
// the same ts index as the globe, and the path match runs on the rows the
// console would otherwise draw, so the two views cannot disagree.
func (s *Store) ReachSnapshot(since time.Time) (Reach, error) {
	out := Reach{Since: since, Endpoints: []ReachRow{}, Sources: []ReachSource{}, NearMiss: []NearMiss{}}
	err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN `+sensitiveEndpoint+`
		AND status >= 200 AND status < 500 THEN 1 ELSE 0 END),0)
		FROM events WHERE ts >= ? AND action = 'allow' AND `+eventSiteSQL,
		stamp(since), s.site, s.site, s.site, s.defaultSite).Scan(&out.Allowed, &out.Reached)
	if err != nil {
		return out, err
	}

	rows, err := s.db.Query(`SELECT host, path, method, status, country, COUNT(*), MAX(ts), AVG(lat), AVG(lon)
		FROM events WHERE ts >= ? AND action = 'allow' AND status >= 200 AND status < 500
		AND `+sensitiveEndpoint+` AND `+eventSiteSQL+`
		GROUP BY host, path, method, status, country
		ORDER BY COUNT(*) DESC, MAX(ts) DESC LIMIT 40`,
		stamp(since), s.site, s.site, s.site, s.defaultSite)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var r ReachRow
		if err := rows.Scan(&r.Host, &r.Path, &r.Method, &r.Status, &r.Country, &r.Count, &r.LastSeen, &r.Lat, &r.Lon); err != nil {
			return out, err
		}
		out.Endpoints = append(out.Endpoints, r)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}

	rows, err = s.db.Query(`SELECT src_ip, MAX(country), MAX(asn), COUNT(*), MAX(ts)
		FROM events WHERE ts >= ? AND action = 'allow' AND status >= 200 AND status < 500
		AND `+sensitiveEndpoint+` AND `+eventSiteSQL+`
		GROUP BY src_ip ORDER BY COUNT(*) DESC, MAX(ts) DESC LIMIT 8`,
		stamp(since), s.site, s.site, s.site, s.defaultSite)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var r ReachSource
		if err := rows.Scan(&r.IP, &r.Country, &r.ASN, &r.Count, &r.LastSeen); err != nil {
			return out, err
		}
		out.Sources = append(out.Sources, r)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}

	// A logged verdict is a detection that did not block. Grouping by rule keeps
	// the list readable: one row per technique, not one per request.
	rows, err = s.db.Query(`SELECT stage, rule_id, rule_msg, MAX(host), MAX(path), MAX(country), COUNT(*), MAX(ts)
		FROM events WHERE ts >= ? AND action = 'log' AND `+eventSiteSQL+`
		GROUP BY stage, rule_id, rule_msg
		ORDER BY COUNT(*) DESC, MAX(ts) DESC LIMIT 10`,
		stamp(since), s.site, s.site, s.site, s.defaultSite)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var n NearMiss
		if err := rows.Scan(&n.Stage, &n.RuleID, &n.RuleMsg, &n.Host, &n.Path, &n.Country, &n.Count, &n.LastSeen); err != nil {
			return out, err
		}
		out.NearMiss = append(out.NearMiss, n)
	}
	return out, rows.Err()
}
