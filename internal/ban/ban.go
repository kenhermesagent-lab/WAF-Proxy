// Package ban manages temporary and permanent IP bans.
package ban

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/netmatch"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// Record is an active ban held in memory.
type Record struct {
	CIDR      string
	Reason    string
	Source    string
	Permanent bool
	CreatedAt time.Time
	ExpiresAt *time.Time
}

// Expired reports whether a temporary ban has lapsed.
func (r Record) Expired(now time.Time) bool {
	return !r.Permanent && r.ExpiresAt != nil && now.After(*r.ExpiresAt)
}

// Engine keeps bans in a prefix map and mirrors them to SQLite and nftables.
type Engine struct {
	st     *store.Store
	log    *slog.Logger
	kernel *Kernel

	mu    sync.RWMutex
	table *netmatch.Map[Record]

	// OnAdd is invoked for every newly applied ban, used for notifications.
	OnAdd func(Record)

	now func() time.Time
}

// New loads existing bans and prepares kernel sync.
func New(st *store.Store, log *slog.Logger, kernel *Kernel) (*Engine, error) {
	e := &Engine{
		st:     st,
		log:    log,
		kernel: kernel,
		table:  netmatch.New[Record](),
		now:    time.Now,
	}
	if err := e.load(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Engine) load() error {
	bans, err := e.st.ListBans(false)
	if err != nil {
		return err
	}
	e.mu.Lock()
	for _, b := range bans {
		rec := Record{
			CIDR: b.CIDR, Reason: b.Reason, Source: b.Source, Permanent: b.Permanent,
			CreatedAt: b.CreatedAt, ExpiresAt: b.ExpiresAt,
		}
		if rec.Expired(e.now()) {
			continue
		}
		if err := e.table.AddCIDR(b.CIDR, rec); err != nil {
			e.log.Warn("skip unparsable ban", "cidr", b.CIDR, "err", err)
		}
	}
	e.mu.Unlock()
	if e.kernel != nil {
		if err := e.kernel.Sync(e.snapshot()); err != nil {
			e.log.Warn("kernel ban sync unavailable; using proxy-level enforcement", "err", err)
		}
	}
	e.log.Info("ban engine loaded", "active", e.table.Len())
	return nil
}

// Start runs the expiry sweeper.
func (e *Engine) Start(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.purgeExpired()
			e.reconcile()
		}
	}
}

// reconcile reloads the in-memory table from SQLite so a ban removed by the
// one-shot `wafproxy unban` CLI takes effect without restarting the process.
func (e *Engine) reconcile() {
	// Hold the engine lock across the read and the swap so a concurrent Add
	// cannot write the database and the old table between the two steps.
	e.mu.Lock()
	defer e.mu.Unlock()
	bans, err := e.st.ListBans(false)
	if err != nil {
		return
	}
	fresh := netmatch.New[Record]()
	for _, b := range bans {
		rec := Record{
			CIDR: b.CIDR, Reason: b.Reason, Source: b.Source, Permanent: b.Permanent,
			CreatedAt: b.CreatedAt, ExpiresAt: b.ExpiresAt,
		}
		if rec.Expired(e.now()) {
			continue
		}
		if err := fresh.AddCIDR(b.CIDR, rec); err != nil {
			continue
		}
	}
	e.table.ReplaceWith(fresh)
}

func (e *Engine) purgeExpired() {
	now := e.now()
	expired := []string{}
	e.mu.Lock()
	e.table.Range(func(p netip.Prefix, r Record) bool {
		if r.Expired(now) {
			expired = append(expired, p.String())
			e.table.RemovePrefix(p)
		}
		return true
	})
	e.mu.Unlock()
	for _, cidr := range expired {
		_, _ = e.st.DeleteBanByCIDR(cidr)
		if e.kernel != nil {
			_ = e.kernel.Remove(cidr)
		}
	}
	if len(expired) > 0 {
		e.log.Info("expired bans removed", "count", len(expired))
	}
}

// Add creates or refreshes a ban. A ttl of zero creates a permanent ban.
func (e *Engine) Add(cidr, reason, source, createdBy string, ttl time.Duration) (Record, error) {
	p, err := netmatch.ParsePrefix(cidr)
	if err != nil {
		return Record{}, err
	}
	rec := Record{CIDR: p.String(), Reason: reason, Source: source, CreatedAt: e.now()}
	if ttl > 0 {
		exp := e.now().Add(ttl)
		rec.ExpiresAt = &exp
	} else {
		rec.Permanent = true
	}
	// Preserve permanence when a permanent ban is refreshed by a temp one.
	if existing, ok := e.table.Match(p.Addr()); ok && existing.CIDR == rec.CIDR && existing.Permanent {
		rec.Permanent = true
		rec.ExpiresAt = nil
	}
	b := &model.Ban{
		CIDR: rec.CIDR, Reason: rec.Reason, Source: rec.Source, Permanent: rec.Permanent,
		CreatedBy: createdBy, CreatedAt: rec.CreatedAt, ExpiresAt: rec.ExpiresAt,
	}
	if _, err := e.st.AddBan(b); err != nil {
		return Record{}, err
	}
	e.mu.Lock()
	e.table.AddPrefix(p, rec)
	e.mu.Unlock()
	if e.kernel != nil {
		if err := e.kernel.Add(rec.CIDR); err != nil {
			e.log.Debug("kernel ban add failed", "cidr", rec.CIDR, "err", err)
		}
	}
	if e.OnAdd != nil {
		go e.OnAdd(rec)
	}
	return rec, nil
}

// SetStealth applies kernel-level ICMP handling for the WAN interface.
func (e *Engine) SetStealth(ignorePing bool, wanIface string) {
	if e.kernel == nil {
		return
	}
	if err := e.kernel.SetStealth(ignorePing, wanIface); err != nil {
		e.log.Debug("kernel stealth update failed", "err", err)
	}
}

// RemoveIfSource removes a ban only when it was created by the given source,
// so a CrowdSec decision deletion cannot lift a manual or WAF ban.
func (e *Engine) RemoveIfSource(cidr, source string) {
	p, err := netmatch.ParsePrefix(cidr)
	if err != nil {
		return
	}
	rec, ok := e.table.Match(p.Addr())
	if !ok || rec.Source != source {
		return
	}
	_ = e.Remove(rec.CIDR)
}

// Promote makes an existing ban permanent.
func (e *Engine) Promote(cidr string) error {
	p, err := netmatch.ParsePrefix(cidr)
	if err != nil {
		return err
	}
	e.mu.Lock()
	rec, ok := e.table.Match(p.Addr())
	if ok {
		rec.Permanent = true
		rec.ExpiresAt = nil
		e.table.AddPrefix(p, rec)
	}
	e.mu.Unlock()
	bans, err := e.st.ListBans(true)
	if err != nil {
		return err
	}
	for _, b := range bans {
		if b.CIDR == p.String() {
			if err := e.st.PromoteBan(b.ID); err != nil {
				return err
			}
			break
		}
	}
	return nil
}

// Remove deletes a ban by CIDR.
func (e *Engine) Remove(cidr string) error {
	p, err := netmatch.ParsePrefix(cidr)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.table.RemovePrefix(p)
	e.mu.Unlock()
	if _, err := e.st.DeleteBanByCIDR(p.String()); err != nil {
		return err
	}
	if e.kernel != nil {
		_ = e.kernel.Remove(p.String())
	}
	return nil
}

// Match returns the ban covering an address, if any.
func (e *Engine) Match(addr netip.Addr) (Record, bool) {
	rec, ok := e.table.Match(addr)
	if !ok {
		return Record{}, false
	}
	if rec.Expired(e.now()) {
		return Record{}, false
	}
	return rec, true
}

// Count returns the number of active bans.
func (e *Engine) Count() int { return e.table.Len() }

// List returns all active bans from the database.
func (e *Engine) List(includeExpired bool) ([]model.Ban, error) {
	return e.st.ListBans(includeExpired)
}

// NoteHit increments the hit counter for the CIDR covering addr.
func (e *Engine) NoteHit(addr netip.Addr) {
	if rec, ok := e.table.Match(addr); ok {
		e.st.IncrementBanHits(rec.CIDR)
	}
}

func (e *Engine) snapshot() []Record {
	out := []Record{}
	e.table.Range(func(_ netip.Prefix, r Record) bool {
		out = append(out, r)
		return true
	})
	return out
}

// KernelStatus reports whether kernel-level blocking is active.
func (e *Engine) KernelStatus() (bool, string) {
	if e.kernel == nil {
		return false, "disabled"
	}
	return e.kernel.Status()
}
