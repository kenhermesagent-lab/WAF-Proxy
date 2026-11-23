package store

import (
	"strings"
	"testing"
)

// A new table must be classified before it can ship: an unclassified table
// would silently disappear from a snapshot or be streamed by accident.
func TestEveryTableIsClassified(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	rows, err := st.db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var missing []string
	seen := 0
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		seen++
		if _, ok := ClassOf(name); !ok {
			missing = append(missing, name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if seen == 0 {
		t.Fatal("no tables found; the schema did not apply")
	}
	if len(missing) > 0 {
		t.Fatalf("unclassified tables: %s", strings.Join(missing, ", "))
	}
}
