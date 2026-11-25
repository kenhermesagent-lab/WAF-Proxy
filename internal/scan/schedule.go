package scan

// schedule.go decides when a site's scan runs. It never starts work itself: the
// active node's loop and the manual button both hand it a RunFunc, so a scan
// started by a schedule and one started by an operator take the same path.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// Cadences a site can choose.
const (
	CadenceDaily   = "daily"
	CadenceWeekly  = "weekly"
	CadenceMonthly = "monthly"
)

// Trigger names why a scan started.
const (
	TriggerSchedule = "schedule"
	TriggerConfig   = "config"
	TriggerUpgrade  = "upgrade"
	TriggerKEV      = "kev"
)

// Input is one site's schedule plus what its last run recorded.
type Input struct {
	Schedule model.ScanSchedule
	LastRun  *time.Time
	// Signature is what the last run recorded: the proxy configuration hash,
	// the fingerprint hash and the WAF-Proxy version. Empty means never run.
	Signature string
}

// RunFunc executes one scan.
type RunFunc func(ctx context.Context, siteID int64, trigger, signature string) error

// Scheduler decides whether a scan is due and starts it on the leader only.
type Scheduler struct {
	Leader     bool
	Now        func() time.Time
	Signature  func(siteID int64) (string, error)
	Run        RunFunc
	RecordSkip func(siteID int64, reason string) error
}

// Result is one site's decision.
type Result struct {
	SiteID int64  `json:"site_id"`
	Ran    bool   `json:"ran"`
	Reason string `json:"reason"`
}

// Tick runs every site whose cadence window has opened.
func (s *Scheduler) Tick(ctx context.Context, inputs []Input) ([]Result, error) {
	out := make([]Result, 0, len(inputs))
	for _, in := range inputs {
		res, err := s.decide(ctx, in, "")
		if err != nil {
			return out, err
		}
		out = append(out, res)
	}
	return out, nil
}

// TriggerNow runs one site's scan for a reason other than its cadence. A KEV
// trigger runs even when the configuration is unchanged, because the feed is
// what changed and patching is now urgent.
func (s *Scheduler) TriggerNow(ctx context.Context, in Input, trigger string) (Result, error) {
	return s.decide(ctx, in, trigger)
}

func (s *Scheduler) decide(ctx context.Context, in Input, trigger string) (Result, error) {
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	if !in.Schedule.Enabled && trigger == "" {
		return Result{SiteID: in.Schedule.SiteID, Reason: "the schedule is off"}, nil
	}
	if trigger == "" {
		if !Due(in.Schedule, now, in.LastRun) {
			return Result{SiteID: in.Schedule.SiteID, Reason: "not due yet"}, nil
		}
		trigger = TriggerSchedule
	}
	if !s.Leader {
		return s.skip(in.Schedule.SiteID, "not the leader: only the active node runs scans")
	}
	if s.Signature != nil {
		signature, err := s.Signature(in.Schedule.SiteID)
		if err != nil {
			return Result{}, err
		}
		if in.Signature != "" && signature == in.Signature && trigger != TriggerKEV {
			return s.skip(in.Schedule.SiteID,
				"nothing changed since the last run: same proxy config, fingerprint and WAF-Proxy version")
		}
		in.Signature = signature
	}
	if s.Run == nil {
		return Result{}, fmt.Errorf("scan: no run function is configured")
	}
	if err := s.Run(ctx, in.Schedule.SiteID, trigger, in.Signature); err != nil {
		return Result{SiteID: in.Schedule.SiteID, Reason: "the run failed: " + shortError(err)}, err
	}
	return Result{SiteID: in.Schedule.SiteID, Ran: true, Reason: trigger}, nil
}

func (s *Scheduler) skip(siteID int64, reason string) (Result, error) {
	if s.RecordSkip != nil {
		if err := s.RecordSkip(siteID, reason); err != nil {
			return Result{}, err
		}
	}
	return Result{SiteID: siteID, Reason: reason}, nil
}

// Due reports whether the current cadence window has opened and the last run
// predates it. The opening moves by at most fifteen minutes, derived from the
// site, so many sites do not scan on the same minute.
func Due(s model.ScanSchedule, now time.Time, last *time.Time) bool {
	start, ok := windowStart(s, now)
	if !ok {
		return false
	}
	start = start.Add(jitter(s.SiteID))
	if now.Before(start) {
		return false
	}
	return last == nil || last.Before(start)
}

func windowStart(s model.ScanSchedule, now time.Time) (time.Time, bool) {
	if s.Hour < 0 || s.Hour > 23 {
		return time.Time{}, false
	}
	at := func(day int) time.Time {
		return time.Date(now.Year(), now.Month(), day, s.Hour, 0, 0, 0, now.Location())
	}
	switch s.Cadence {
	case CadenceDaily, "":
		return at(now.Day()), true
	case CadenceWeekly:
		if s.Day < 0 || s.Day > 6 {
			return time.Time{}, false
		}
		back := (int(now.Weekday()) - s.Day + 7) % 7
		return at(now.Day()).AddDate(0, 0, -back), true
	case CadenceMonthly:
		if s.Day < 1 || s.Day > 28 {
			return time.Time{}, false
		}
		if now.Day() < s.Day {
			// The latest window is last month's day.
			return at(s.Day).AddDate(0, -1, 0), true
		}
		return at(s.Day), true
	}
	return time.Time{}, false
}

// jitter is stable per site, so a restart does not move a schedule's minute.
func jitter(siteID int64) time.Duration {
	if siteID <= 0 {
		return 0
	}
	return time.Duration(siteID%31-15) * time.Minute
}

// NewKEVEntries returns the entries that appeared since the previous snapshot.
func NewKEVEntries(prev, next *KEV) []KEVEntry {
	if next == nil {
		return nil
	}
	out := make([]KEVEntry, 0)
	for id, entry := range next.Entries {
		if prev != nil {
			if _, seen := prev.Entries[id]; seen {
				continue
			}
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CVEID < out[j].CVEID })
	return out
}

// KEVMatchesWatched returns the new entries whose product names a component the
// site runs, which is when an unscheduled scan is worth it.
func KEVMatchesWatched(added []KEVEntry, watched []Component) []KEVEntry {
	out := make([]KEVEntry, 0)
	for _, entry := range added {
		for _, c := range watched {
			if productMatches(entry.Product, c.Product, c.Label) {
				out = append(out, entry)
				break
			}
		}
	}
	return out
}

// productMatches compares a KEV vendor product name with a fingerprint label.
// Short names are ignored so a two-letter product cannot match everything.
func productMatches(kevProduct string, names ...string) bool {
	product := strings.ToLower(strings.TrimSpace(kevProduct))
	if product == "" {
		return false
	}
	for _, name := range names {
		want := strings.ToLower(strings.TrimSpace(name))
		if len(want) >= 3 && strings.Contains(product, want) {
			return true
		}
	}
	return false
}
