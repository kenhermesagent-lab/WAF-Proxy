package ha

import (
	"strings"
	"testing"
	"time"
)

func TestFlapGuardParksTheFourthMove(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g := NewFlapGuard(3)
	g.Now = func() time.Time { return now }
	for i := 1; i <= 3; i++ {
		if err := g.Check(); err != nil {
			t.Fatalf("move %d refused: %v", i, err)
		}
		g.Record()
	}
	err := g.Check()
	if err == nil || !strings.Contains(err.Error(), "parked") {
		t.Fatalf("fourth move = %v", err)
	}
	now = now.Add(time.Hour + time.Second)
	if err := g.Check(); err != nil {
		t.Fatalf("the window did not slide: %v", err)
	}
}

func TestFlapGuardDefaultsToOneHoursBudget(t *testing.T) {
	g := NewFlapGuard(0)
	if g.Max != DefaultMaxMovesPerHour || g.Window != time.Hour {
		t.Fatalf("guard = %+v", g)
	}
}
