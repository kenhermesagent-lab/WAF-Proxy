package model

import "time"

// Site is one tenant: a named group of hostnames with its own administrators,
// settings, history and backup, served by the same process as every other site.
type Site struct {
	ID          int64     `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	ConsoleHost string    `json:"console_host"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}
