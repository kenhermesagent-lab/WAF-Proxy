package main

// security_loop.go runs the security scanner on a schedule. Only the active node
// starts it, the same way certificate renewal and feed fetching are leader-only:
// two nodes scanning the same published path would double the traffic and the
// gate's failure budget.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/config"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/internalca"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/scan"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/siteres"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/version"
)

// securityLoop ticks the schedules and keeps the KEV snapshot fresh on the
// active node. The first schedule check runs a minute after startup so a
// window missed while the service was down is not lost.
func securityLoop(ctx context.Context, res *siteres.Set, box *crypto.Box, log *slog.Logger, cfg *config.Config) {
	schedule := time.NewTicker(15 * time.Minute)
	defer schedule.Stop()
	kev := time.NewTicker(24 * time.Hour)
	defer kev.Stop()
	first := time.NewTimer(time.Minute)
	defer first.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
			runSchedules(ctx, res, box, log, cfg)
		case <-schedule.C:
			runSchedules(ctx, res, box, log, cfg)
		case <-kev.C:
			syncKEVAndTrigger(ctx, res, box, log, cfg)
		}
	}
}

// bundleList snapshots the sites first. Each holds the set's lock, and a scan
// takes minutes, so running it inside the callback would block every site.
func bundleList(res *siteres.Set) []*siteres.Bundle {
	var out []*siteres.Bundle
	res.Each(func(b *siteres.Bundle) { out = append(out, b) })
	return out
}

func runSchedules(ctx context.Context, res *siteres.Set, box *crypto.Box, log *slog.Logger, cfg *config.Config) {
	for _, b := range bundleList(res) {
		sched, err := b.Store.ScanSchedule(b.Site.ID)
		if err != nil || sched == nil || !sched.Enabled {
			continue
		}
		var last *time.Time
		if runs, err := b.Store.ListScanRuns(1); err == nil && len(runs) > 0 {
			last = &runs[0].StartedAt
		}
		scheduler := securityScheduler(b, box, log, cfg)
		inputs := []scan.Input{{Schedule: *sched, LastRun: last, Signature: sched.Signature}}
		if _, err := scheduler.Tick(ctx, inputs); err != nil {
			log.Warn("security schedule", "site", b.Site.Slug, "err", err)
		}
	}
}

// syncKEVAndTrigger refreshes the snapshot and scans the sites whose open
// findings name a product the new entries affect.
func syncKEVAndTrigger(ctx context.Context, res *siteres.Set, box *crypto.Box, log *slog.Logger, cfg *config.Config) {
	st := res.Default().Store.Unscoped()
	prev, _ := scan.LoadKEV(st)
	next, changed, err := scan.NewKEVClient().Refresh(ctx, prev)
	if err != nil {
		_ = st.RecordVulnFailure(scan.KEVSource, err.Error())
		log.Warn("KEV refresh failed", "err", err)
		return
	}
	if err := next.Save(st); err != nil {
		log.Warn("KEV snapshot not saved", "err", err)
		return
	}
	if !changed {
		return
	}
	added := scan.NewKEVEntries(prev, next)
	if len(added) == 0 {
		return
	}
	for _, b := range bundleList(res) {
		saved, err := b.Store.ScanSchedule(b.Site.ID)
		if err != nil || saved == nil || !hasTrigger(saved.Triggers, scan.TriggerKEV) {
			continue
		}
		open, err := b.Store.ListScanFindings("open", "")
		if err != nil || len(open) == 0 {
			continue
		}
		watched := make([]scan.Component, 0, len(open))
		for _, f := range open {
			if f.Product != "" {
				watched = append(watched, scan.Component{Product: f.Product, Label: f.Product})
			}
		}
		if len(scan.KEVMatchesWatched(added, watched)) == 0 {
			continue
		}
		scheduler := securityScheduler(b, box, log, cfg)
		if _, err := scheduler.TriggerNow(ctx, scan.Input{Schedule: *saved, Signature: saved.Signature}, scan.TriggerKEV); err != nil {
			log.Warn("KEV-triggered scan", "site", b.Site.Slug, "err", err)
		}
	}
}

func hasTrigger(triggers []string, want string) bool {
	for _, trigger := range triggers {
		if trigger == want {
			return true
		}
	}
	return false
}

func securityScheduler(b *siteres.Bundle, box *crypto.Box, log *slog.Logger, cfg *config.Config) *scan.Scheduler {
	return &scan.Scheduler{
		Leader: true,
		Signature: func(int64) (string, error) {
			return securitySignature(b)
		},
		Run: func(ctx context.Context, siteID int64, trigger, signature string) error {
			if scan.Paused(b.Store) {
				return errors.New("security scanning is paused")
			}
			proxies, err := b.Store.ListProxies()
			if err != nil {
				return err
			}
			listen := ""
			var roots *x509.CertPool
			if cfg != nil {
				listen = cfg.ListenWAN
				roots = internalca.RootsFor(cfg.DataDir)
			}
			base := scan.ListenerBase(listen)
			deps := scan.ExecuteDeps{
				Store: b.Store, Box: box, Notify: b.Notify, PerSecond: scan.ProbesPerSecond(b.Store),
				ConsoleHost: b.Site.ConsoleHost, Bans: b.Bans, Trust: b.ScanTrust,
				WANFallback: func(string) string { return base },
				WANRoots:    roots,
			}
			for _, p := range proxies {
				if !p.Enabled || p.Maintenance {
					continue
				}
				if _, err := scan.Execute(ctx, deps, p, trigger, "scheduler"); err != nil {
					log.Warn("scheduled scan", "site", b.Site.Slug, "host", p.Hostname, "err", err)
				}
			}
			return b.Store.SetScanSignature(siteID, signature)
		},
		RecordSkip: func(siteID int64, reason string) error {
			now := time.Now()
			_, err := b.Store.CreateScanRun(&model.ScanRun{
				SiteID: siteID, Trigger: scan.TriggerSchedule, StartedAt: now, EndedAt: &now, Skipped: reason,
			})
			return err
		},
	}
}

// securitySignature is what the last run saw: the site's proxy records and this
// build's version.
func securitySignature(b *siteres.Bundle) (string, error) {
	proxies, err := b.Store.ListProxies()
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(proxies)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append(raw, version.Version...))
	return hex.EncodeToString(sum[:]), nil
}
