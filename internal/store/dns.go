package store

import (
	"database/sql"
	"errors"
	"time"
)

// DNSCredential is an encrypted credential set for a DNS provider.
type DNSCredential struct {
	ID        int64     `json:"id"`
	Provider  string    `json:"provider"`
	Label     string    `json:"label"`
	CredsEnc  string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

// UpsertDNSCredential stores credentials for a provider, replacing the previous
// set for that provider.
func (s *Store) UpsertDNSCredential(provider, label, enc string) error {
	_, err := s.db.Exec(`DELETE FROM dns_credentials WHERE provider = ?`, provider)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO dns_credentials(provider, label, creds_enc, created_at)
		VALUES(?, ?, ?, ?)`, provider, label, enc, stamp(time.Now()))
	return err
}

// DNSCredentialFor returns the encrypted credentials for a provider.
func (s *Store) DNSCredentialFor(provider string) (string, error) {
	var enc string
	err := s.db.QueryRow(`SELECT creds_enc FROM dns_credentials WHERE provider = ? ORDER BY id DESC LIMIT 1`, provider).Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return enc, err
}

// ListDNSCredentials returns credential metadata without secrets.
func (s *Store) ListDNSCredentials() ([]DNSCredential, error) {
	rows, err := s.db.Query(`SELECT id, provider, label, created_at FROM dns_credentials ORDER BY provider`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DNSCredential{}
	for rows.Next() {
		var c DNSCredential
		var created string
		if err := rows.Scan(&c.ID, &c.Provider, &c.Label, &created); err != nil {
			return nil, err
		}
		c.CreatedAt = parseStamp(created)
		out = append(out, c)
	}
	return out, rows.Err()
}
