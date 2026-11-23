import sys

def edit(path, pairs):
    s = open(path).read()
    for old, new in pairs:
        n = s.count(old)
        if n != 1:
            print("!!", path, n, repr(old[:70]))
            sys.exit(1)
        s = s.replace(old, new)
    open(path, "w").write(s)
    print("ok", path)


edit("internal/store/anomaly.go", [
    ("""	res, err := s.db.Exec(`INSERT INTO anomaly_events(kind, proxy_id, proxy_host, window_start,
		window_seconds, value, baseline, detail, state, created_at, last_seen)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)`,
		e.Kind, e.ProxyID, e.ProxyHost, stamp(e.WindowStart), e.WindowSeconds, e.Value, e.Baseline,
		e.Detail, stamp(time.Now()), stamp(time.Now()))""",
     """	res, err := s.db.Exec(`INSERT INTO anomaly_events(kind, proxy_id, proxy_host, window_start,
		window_seconds, value, baseline, detail, state, created_at, last_seen, site_id)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?,
			COALESCE((SELECT site_id FROM proxies WHERE id = ?), ?))`,
		e.Kind, e.ProxyID, e.ProxyHost, stamp(e.WindowStart), e.WindowSeconds, e.Value, e.Baseline,
		e.Detail, stamp(time.Now()), stamp(time.Now()), e.ProxyID, s.site)"""),

    ("""	rows, err := s.db.Query(`SELECT `+anomalyColumns+` FROM anomaly_events ORDER BY id DESC LIMIT ?`, limit)""",
     """	rows, err := s.db.Query(`SELECT `+anomalyColumns+` FROM anomaly_events
		WHERE (? = 0 OR site_id = ?) ORDER BY id DESC LIMIT ?`, s.site, s.site, limit)"""),

    ("""	return scanAnomaly(s.db.QueryRow(`SELECT `+anomalyColumns+` FROM anomaly_events WHERE id = ?`, id))""",
     """	return scanAnomaly(s.db.QueryRow(`SELECT `+anomalyColumns+` FROM anomaly_events
		WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site))"""),

    ("""		WHERE kind = ? AND proxy_id = ? AND state = 'open' AND last_seen > ? ORDER BY id DESC LIMIT 1`,
		kind, proxyID, stamp(since))""",
     """		WHERE kind = ? AND proxy_id = ? AND state = 'open' AND last_seen > ?
		AND (? = 0 OR site_id = ?) ORDER BY id DESC LIMIT 1`,
		kind, proxyID, stamp(since), s.site, s.site)"""),

    ("""	_, err := s.db.Exec(`UPDATE anomaly_events SET value = ?, last_seen = ? WHERE id = ?`,
		value, stamp(time.Now()), id)""",
     """	_, err := s.db.Exec(`UPDATE anomaly_events SET value = ?, last_seen = ?
		WHERE id = ? AND (? = 0 OR site_id = ?)`, value, stamp(time.Now()), id, s.site, s.site)"""),

    ("""		WHERE id = ? AND state = 'open'`, truncate(user, 64), stamp(time.Now()), id)""",
     """		WHERE id = ? AND state = 'open' AND (? = 0 OR site_id = ?)`,
		truncate(user, 64), stamp(time.Now()), id, s.site, s.site)"""),

    ("""	rows, err := s.db.Query(`SELECT proxy_id, COUNT(*) FROM gate_failures WHERE ts > ? GROUP BY proxy_id`,
		stamp(since))""",
     """	rows, err := s.db.Query(`SELECT proxy_id, COUNT(*) FROM gate_failures
		WHERE ts > ? AND (? = 0 OR site_id = ?) GROUP BY proxy_id`, stamp(since), s.site, s.site)"""),
])

edit("internal/store/gate.go", [
    ("""	_, err := s.db.Exec(`INSERT INTO gate_failures(ip, proxy_id, username, reason, ts) VALUES(?, ?, ?, ?, ?)`,
		ip, proxyID, truncate(username, 190), truncate(reason, 40), stamp(time.Now()))""",
     """	_, err := s.db.Exec(`INSERT INTO gate_failures(ip, proxy_id, username, reason, ts, site_id)
		VALUES(?, ?, ?, ?, ?, COALESCE((SELECT site_id FROM proxies WHERE id = ?), ?))`,
		ip, proxyID, truncate(username, 190), truncate(reason, 40), stamp(time.Now()), proxyID, s.site)"""),

    ("""		FROM gate_failures WHERE ts >= ? AND ts <= ?
		GROUP BY ip, username, proxy_id
		ORDER BY MAX(ts) DESC LIMIT ?`, stamp(from), stamp(to), limit)""",
     """		FROM gate_failures WHERE ts >= ? AND ts <= ? AND (? = 0 OR site_id = ?)
		GROUP BY ip, username, proxy_id
		ORDER BY MAX(ts) DESC LIMIT ?`, stamp(from), stamp(to), s.site, s.site, limit)"""),

    ("""	err = s.db.QueryRow(`SELECT COUNT(*) FROM gate_failures WHERE ip = ? AND ts > ?`,
		ip, stamp(now.Add(-10*time.Minute))).Scan(&last10m)""",
     """	err = s.db.QueryRow(`SELECT COUNT(*) FROM gate_failures WHERE ip = ? AND ts > ? AND (? = 0 OR site_id = ?)`,
		ip, stamp(now.Add(-10*time.Minute)), s.site, s.site).Scan(&last10m)"""),

    ("""	err = s.db.QueryRow(`SELECT COUNT(*) FROM gate_failures WHERE ip = ? AND ts > ?`,
		ip, stamp(now.Add(-24*time.Hour))).Scan(&last24h)""",
     """	err = s.db.QueryRow(`SELECT COUNT(*) FROM gate_failures WHERE ip = ? AND ts > ? AND (? = 0 OR site_id = ?)`,
		ip, stamp(now.Add(-24*time.Hour)), s.site, s.site).Scan(&last24h)"""),

    ("""	err = s.db.QueryRow(`SELECT COUNT(DISTINCT date(ts)) FROM gate_failures WHERE ip = ? AND ts > ?`,
		ip, stamp(now.Add(-7*24*time.Hour))).Scan(&distinctDays)""",
     """	err = s.db.QueryRow(`SELECT COUNT(DISTINCT date(ts)) FROM gate_failures
		WHERE ip = ? AND ts > ? AND (? = 0 OR site_id = ?)`,
		ip, stamp(now.Add(-7*24*time.Hour)), s.site, s.site).Scan(&distinctDays)"""),

    ("""	_, err := s.db.Exec(`DELETE FROM gate_failures WHERE ip = ?`, ip)""",
     """	_, err := s.db.Exec(`DELETE FROM gate_failures WHERE ip = ? AND (? = 0 OR site_id = ?)`, ip, s.site, s.site)"""),

    ("""	_, err := s.db.Exec(`DELETE FROM gate_failures WHERE ts < ?`, stamp(before))""",
     """	_, err := s.db.Exec(`DELETE FROM gate_failures WHERE ts < ? AND (? = 0 OR site_id = ?)`,
		stamp(before), s.site, s.site)"""),
])

edit("internal/store/policies.go", [
    ("""	if _, err := tx.Exec(`DELETE FROM gate_sessions WHERE username = ?`, username); err != nil {""",
     """	if _, err := tx.Exec(`DELETE FROM gate_sessions WHERE username = ? AND (? = 0 OR site_id = ?)`,
		username, s.site, s.site); err != nil {"""),
])

edit("internal/store/logviews.go", [
    ("""	rows, err := s.db.Query(`SELECT name, query, updated_by, updated_at FROM log_views ORDER BY name`)""",
     """	rows, err := s.db.Query(`SELECT name, query, updated_by, updated_at FROM log_views
		WHERE (? = 0 OR site_id = ?) ORDER BY name`, s.site, s.site)"""),

    ("""	_, err := s.db.Exec(`INSERT INTO log_views(name, query, updated_by, updated_at) VALUES(?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET query = excluded.query, updated_by = excluded.updated_by,
			updated_at = excluded.updated_at`, name, query, by, stamp(time.Now()))""",
     """	_, err := s.db.Exec(`INSERT INTO log_views(name, query, updated_by, updated_at, site_id) VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(site_id, name) DO UPDATE SET query = excluded.query, updated_by = excluded.updated_by,
			updated_at = excluded.updated_at`, name, query, by, stamp(time.Now()), s.site)"""),

    ("""	res, err := s.db.Exec(`DELETE FROM log_views WHERE name = ?`, name)""",
     """	res, err := s.db.Exec(`DELETE FROM log_views WHERE name = ? AND (? = 0 OR site_id = ?)`, name, s.site, s.site)"""),
])

edit("internal/store/sites.go", [
    ("""	_, err = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_proxies_site ON proxies(site_id)`)
	return err""",
     """	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_proxies_site ON proxies(site_id)`); err != nil {
		return err
	}
	// A saved log view's name is only unique inside its site. Older databases
	// key on the name alone, so the table is rebuilt once.
	var keyed int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('log_views')
		WHERE name = 'site_id' AND pk > 0`).Scan(&keyed); err != nil {
		return err
	}
	if keyed == 0 {
		if _, err := s.db.Exec(`CREATE TABLE log_views_sites (
			name TEXT NOT NULL,
			query TEXT NOT NULL,
			updated_by TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL,
			site_id INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY(site_id, name)
		)`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO log_views_sites(name, query, updated_by, updated_at, site_id)
			SELECT name, query, updated_by, updated_at, site_id FROM log_views`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`DROP TABLE log_views`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`ALTER TABLE log_views_sites RENAME TO log_views`); err != nil {
			return err
		}
	}
	return nil"""),
])
