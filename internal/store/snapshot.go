package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Snapshot is a consistent copy of every table that crosses the HA link. The
// local class (events, flows, schema bookkeeping) is deliberately absent.
type Snapshot struct {
	SchemaVersion string               `json:"schema_version"`
	CreatedAt     string               `json:"created_at"`
	Tables        map[string]TableDump `json:"tables"`
}

// TableDump keeps column names with the rows, so a standby with the same schema
// applies values by name instead of relying on column order.
type TableDump struct {
	Columns []string  `json:"columns"`
	Rows    [][]Value `json:"rows"`
}

// Value is one typed SQLite value. JSON alone cannot distinguish NULL, the
// empty string and an empty blob, so every cell carries its kind.
type Value struct {
	Kind  string  `json:"k"`
	Int   int64   `json:"i,omitempty"`
	Float float64 `json:"f,omitempty"`
	Text  string  `json:"t,omitempty"`
	Blob  []byte  `json:"b,omitempty"`
}

// ReplicatedTables lists the tables a snapshot carries, sorted for stable
// output and for a readable error when one is missing.
func ReplicatedTables() []string {
	out := make([]string, 0, len(TableClasses))
	for name, class := range TableClasses {
		if class != ClassLocal {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// SchemaVersion exposes the migration level a snapshot must match.
func SchemaVersion() string { return schemaVersion }

// Snapshot reads every replicated table inside one read transaction, so a
// concurrent write cannot produce a half-applied configuration.
func (s *Store) Snapshot() (*Snapshot, error) {
	tx, err := s.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	snap := &Snapshot{SchemaVersion: schemaVersion, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Tables: map[string]TableDump{}}
	existing, err := existingTables(tx)
	if err != nil {
		return nil, err
	}
	for _, table := range ReplicatedTables() {
		if !existing[table] {
			// Some tables are created only when a feature ran on this node; a
			// snapshot carries what exists instead of inventing empty tables.
			continue
		}
		dump, err := readTable(tx, table)
		if err != nil {
			return nil, fmt.Errorf("snapshot %s: %w", table, err)
		}
		snap.Tables[table] = dump
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return snap, nil
}

func existingTables(tx *sql.Tx) (map[string]bool, error) {
	rows, err := tx.Query(`SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

func readTable(tx *sql.Tx, table string) (TableDump, error) {
	rows, err := tx.Query(`SELECT * FROM ` + quoteIdent(table))
	if err != nil {
		return TableDump{}, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return TableDump{}, err
	}
	dump := TableDump{Columns: cols}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return TableDump{}, err
		}
		row := make([]Value, len(vals))
		for i, v := range vals {
			row[i] = encodeValue(v)
		}
		dump.Rows = append(dump.Rows, row)
	}
	return dump, rows.Err()
}

// Restore replaces every replicated table in one transaction. Foreign keys are
// deferred to commit, because the tables reference each other and any delete
// order would otherwise fail halfway through.
func (s *Store) Restore(snap *Snapshot) error {
	if snap == nil {
		return errors.New("store: no snapshot")
	}
	if snap.SchemaVersion != schemaVersion {
		return fmt.Errorf("store: snapshot schema %q does not match this node's %q", snap.SchemaVersion, schemaVersion)
	}
	for name := range snap.Tables {
		class, ok := ClassOf(name)
		if !ok {
			return fmt.Errorf("store: snapshot names unknown table %q", name)
		}
		if class == ClassLocal {
			return fmt.Errorf("store: snapshot must not carry local table %q", name)
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`PRAGMA defer_foreign_keys = ON`); err != nil {
		return err
	}
	tables := make([]string, 0, len(snap.Tables))
	for name := range snap.Tables {
		tables = append(tables, name)
	}
	sort.Strings(tables)
	for _, table := range tables {
		dump := snap.Tables[table]
		if _, err := tx.Exec(`DELETE FROM ` + quoteIdent(table)); err != nil {
			return fmt.Errorf("store: clear %s: %w", table, err)
		}
		if len(dump.Rows) == 0 {
			continue
		}
		if len(dump.Columns) == 0 {
			return fmt.Errorf("store: table %q has rows but no columns", table)
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(dump.Columns)), ",")
		query := `INSERT INTO ` + quoteIdent(table) + ` (` + joinIdents(dump.Columns) + `) VALUES (` + placeholders + `)`
		stmt, err := tx.Prepare(query)
		if err != nil {
			return fmt.Errorf("store: prepare %s: %w", table, err)
		}
		for _, row := range dump.Rows {
			if len(row) != len(dump.Columns) {
				_ = stmt.Close()
				return fmt.Errorf("store: %s row has %d values for %d columns", table, len(row), len(dump.Columns))
			}
			args := make([]any, len(row))
			for i, v := range row {
				args[i] = decodeValue(v)
			}
			if _, err := stmt.Exec(args...); err != nil {
				_ = stmt.Close()
				return fmt.Errorf("store: insert into %s: %w", table, err)
			}
		}
		if err := stmt.Close(); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SnapshotCounts is the per-table row count used in logs and the sync CLI.
func (s *Snapshot) SnapshotCounts() map[string]int {
	out := make(map[string]int, len(s.Tables))
	for name, dump := range s.Tables {
		out[name] = len(dump.Rows)
	}
	return out
}

// MarshalSnapshot encodes a snapshot for the HA link. Compression and sealing
// happen in the ha package; this is only the plain form.
func MarshalSnapshot(snap *Snapshot) ([]byte, error) { return json.Marshal(snap) }

func encodeValue(v any) Value {
	switch x := v.(type) {
	case nil:
		return Value{Kind: "null"}
	case int64:
		return Value{Kind: "int", Int: x}
	case int:
		return Value{Kind: "int", Int: int64(x)}
	case float64:
		return Value{Kind: "float", Float: x}
	case bool:
		if x {
			return Value{Kind: "int", Int: 1}
		}
		return Value{Kind: "int"}
	case string:
		return Value{Kind: "text", Text: x}
	case []byte:
		return Value{Kind: "blob", Blob: x}
	case time.Time:
		return Value{Kind: "text", Text: x.UTC().Format(time.RFC3339Nano)}
	default:
		return Value{Kind: "text", Text: fmt.Sprint(x)}
	}
}

func decodeValue(v Value) any {
	switch v.Kind {
	case "null":
		return nil
	case "int":
		return v.Int
	case "float":
		return v.Float
	case "blob":
		return v.Blob
	default:
		return v.Text
	}
}

func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func joinIdents(cols []string) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = quoteIdent(c)
	}
	return strings.Join(parts, ",")
}
