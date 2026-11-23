package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

const agentLinkColumns = `id, name, endpoint, secret, enabled, created_at`

func scanAgentLink(row interface{ Scan(...any) error }) (*model.AgentLink, error) {
	var a model.AgentLink
	var enabled int
	var created string
	err := row.Scan(&a.ID, &a.Name, &a.Endpoint, &a.Secret, &enabled, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.Enabled = i2b(enabled)
	a.HasSecret = a.Secret != ""
	a.CreatedAt = parseStamp(created)
	return &a, nil
}

// ListAgentLinks returns the configured agent webhooks.
func (s *Store) ListAgentLinks() ([]model.AgentLink, error) {
	rows, err := s.db.Query(`SELECT ` + agentLinkColumns + ` FROM agent_links WHERE (? = 0 OR site_id = ?) ORDER BY name`, s.site, s.site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AgentLink{}
	for rows.Next() {
		a, err := scanAgentLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// GetAgentLink loads one link.
func (s *Store) GetAgentLink(id int64) (*model.AgentLink, error) {
	return scanAgentLink(s.db.QueryRow(`SELECT `+agentLinkColumns+` FROM agent_links WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site))
}

// CreateAgentLink inserts a link and returns its ID.
func (s *Store) CreateAgentLink(a *model.AgentLink) (int64, error) {
	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM agent_links WHERE name = ?`, a.Name).Scan(&exists); err != nil {
		return 0, err
	}
	if exists > 0 {
		return 0, ErrDuplicate
	}
	res, err := s.db.Exec(`INSERT INTO agent_links(name, endpoint, secret, enabled, created_at, site_id) VALUES(?, ?, ?, ?, ?, ?)`,
		a.Name, a.Endpoint, a.Secret, b2i(a.Enabled), stamp(time.Now()), s.site)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateAgentLink writes the mutable fields of a link.
func (s *Store) UpdateAgentLink(a *model.AgentLink) error {
	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM agent_links WHERE name = ? AND id <> ?`, a.Name, a.ID).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return ErrDuplicate
	}
	_, err := s.db.Exec(`UPDATE agent_links SET name = ?, endpoint = ?, secret = ?, enabled = ? WHERE id = ? AND (? = 0 OR site_id = ?)`,
		a.Name, a.Endpoint, a.Secret, b2i(a.Enabled), a.ID, s.site, s.site)
	return err
}

// DeleteAgentLink removes a link.
func (s *Store) DeleteAgentLink(id int64) error {
	_, err := s.db.Exec(`DELETE FROM agent_links WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site)
	return err
}
