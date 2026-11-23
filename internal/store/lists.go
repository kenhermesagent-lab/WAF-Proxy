package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

const accessListColumns = `id, kind, name, ips, countries, created_at`

func scanAccessList(row interface{ Scan(...any) error }) (*model.AccessList, error) {
	var l model.AccessList
	var created string
	err := row.Scan(&l.ID, &l.Kind, &l.Name, &l.IPs, &l.Countries, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	l.CreatedAt = parseStamp(created)
	return &l, nil
}

// ListAccessLists returns every named blocklist and whitelist.
func (s *Store) ListAccessLists() ([]model.AccessList, error) {
	rows, err := s.db.Query(`SELECT ` + accessListColumns + ` FROM access_lists WHERE (? = 0 OR site_id = ?) ORDER BY kind DESC, name`, s.site, s.site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AccessList{}
	for rows.Next() {
		l, err := scanAccessList(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *l)
	}
	return out, rows.Err()
}

// GetAccessList loads one list.
func (s *Store) GetAccessList(id int64) (*model.AccessList, error) {
	return scanAccessList(s.db.QueryRow(`SELECT `+accessListColumns+` FROM access_lists WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site))
}

// CreateAccessList inserts a list. Names are unique across both kinds so an
// operator never has to guess which "Office" a profile refers to.
func (s *Store) CreateAccessList(l *model.AccessList) error {
	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM access_lists WHERE name = ?`, l.Name).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return ErrDuplicate
	}
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now()
	}
	res, err := s.db.Exec(`INSERT INTO access_lists(kind, name, ips, countries, created_at, site_id) VALUES(?, ?, ?, ?, ?, ?)`,
		l.Kind, l.Name, l.IPs, l.Countries, stamp(l.CreatedAt), s.site)
	if err != nil {
		return err
	}
	l.ID, err = res.LastInsertId()
	return err
}

// UpdateAccessList writes the entries. The name and kind are immutable, so a
// profile that references the list keeps its meaning.
func (s *Store) UpdateAccessList(l *model.AccessList) error {
	_, err := s.db.Exec(`UPDATE access_lists SET ips = ?, countries = ? WHERE id = ? AND site_id = ?`, l.IPs, l.Countries, l.ID, s.site)
	return err
}

// AccessListInUse counts the access profiles that attach a list.
func (s *Store) AccessListInUse(id int64) (int, error) {
	profiles, err := s.ListAccessProfiles()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, a := range profiles {
		for _, ref := range a.ListIDs {
			if ref == id {
				n++
				break
			}
		}
	}
	return n, nil
}

// DeleteAccessList removes a list. Profiles keep their row; the engine ignores
// an id that no longer resolves, and the console flags it.
func (s *Store) DeleteAccessList(id int64) error {
	_, err := s.db.Exec(`DELETE FROM access_lists WHERE id = ? AND site_id = ?`, id, s.site)
	return err
}
