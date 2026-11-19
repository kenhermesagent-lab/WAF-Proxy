// Command wafproxy runs the WAF reverse proxy and its admin API.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/acme"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/api"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/botguard"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/config"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/crowdsec"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/gate"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/intel"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/notify"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/plex"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/policy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/proxy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/version"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/webui"
)

func main() {
	// Emergency recovery path: `docker exec wafproxy unban <ip>` works even
	// when the admin GUI is unreachable or the operator is locked out.
	if len(os.Args) > 1 && os.Args[1] == "unban" {
		if err := unbanCLI(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "unban:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func unbanCLI(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: wafproxy unban <ip|cidr>")
	}
	log := newLogger()
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	engine, err := ban.New(st, log, ban.NewKernel(log))
	if err != nil {
		return err
	}
	if err := engine.Remove(args[0]); err != nil {
		return err
	}
	fmt.Printf("ban for %s removed; the running proxy reconciles within 30s\n", args[0])
	return nil
}

func run() error {
	log := newLogger()
	log.Info("starting", "version", version.Version, "commit", version.Commit)

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	box, err := wfcrypto.New(cfg.MasterKey)
	if err != nil {
		return err
	}

	kv, err := st.Settings()
	if err != nil {
		return err
	}
	wanIface, lanIface := kv["wan_iface"], kv["lan_iface"]
	// Listener addresses are chosen in the setup wizard and stored in the
	// database; the environment only supplies the first-boot fallback.
	if v := strings.TrimSpace(kv["wan_port"]); v != "" {
		cfg.ListenWAN = net.JoinHostPort(strings.TrimSpace(kv["wan_ip"]), v)
	}
	if v := strings.TrimSpace(kv["gui_port"]); v != "" {
		cfg.ListenGUI = net.JoinHostPort(strings.TrimSpace(kv["lan_ip"]), v)
	}

	geo := geoip.Open(cfg.DataDir)
	if geo.Available() {
		log.Info("geoip database loaded")
	} else {
		log.Warn("no GeoIP database found; country and ASN policy will be unavailable")
	}

	met := metrics.New(wanIface, lanIface)
	kernel := ban.NewKernel(log)
	bans, err := ban.New(st, log, kernel)
	if err != nil {
		return err
	}
	feeds := intel.New(st, log, 32<<20)
	profiles, err := st.ListProfiles()
	if err != nil {
		return err
	}
	wafs := waf.NewSet(profiles, log)
	certs := acme.New(st, box, log)
	notifier := notify.New(st, box, log)

	bans.OnAdd = func(rec ban.Record) {
		kind := "Temporary ban"
		event := "ban"
		immediate := false
		if rec.Permanent {
			kind = "Permanent ban"
			event = "permanent_ban"
			immediate = true
		}
		text := fmt.Sprintf("%s: %s — %s (source: %s)", kind, rec.CIDR, rec.Reason, rec.Source)
		// A temporary ban must not suppress the permanent-ban alert for the same
		// address through the 24 hour dedupe window.
		dedupe := "ban:" + rec.CIDR
		if rec.Permanent {
			dedupe = "permanent-ban:" + rec.CIDR
		}
		notifier.Enqueue(event, text, dedupe, immediate)
	}

	gateEngine := gate.New(st, box, bans, log)
	gateEngine.OnBan = func(ip, reason string, permanent bool) {
		kind := "Temporary ban"
		if permanent {
			kind = "Permanent ban"
		}
		notifier.Enqueue("gate", fmt.Sprintf("%s: %s — access gate (%s)", kind, ip, reason), "gate:"+ip, permanent)
	}
	bots := botguard.New(cfg.MasterKey, bans, st, log)
	cs := crowdsec.New(cfg.CrowdSecURL, cfg.CrowdSecKey, bans, log)
	if cs != nil {
		log.Info("crowdsec bouncer enabled", "lapi", cfg.CrowdSecURL)
	}

	pol, err := policy.New(st, bans, feeds, geo, wafs, log)
	if err != nil {
		return err
	}
	px, err := proxy.New(proxy.Deps{
		Store: st, Policy: pol, Gate: gateEngine, Bots: bots, Bans: bans,
		Geo: geo, Metrics: met, Log: log,
	})
	if err != nil {
		return err
	}
	px.SetCertProvider(certs)
	cur := pol.CurrentSettings()
	px.SetBodyLimit(cur.MaxBody)
	bans.SetStealth(cur.StealthPing, cur.WANIface)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := px.Reload(ctx); err != nil {
		return err
	}

	plexMgr := plex.New(log)
	// The relay bypasses the request pipeline, so banned addresses have to be
	// refused here as well or they could still stream through the Plex port.
	plexMgr.SetBans(func(addr netip.Addr) bool {
		_, banned := bans.Match(addr)
		return banned
	})
	if err := plexMgr.Apply(plexConfigFromSettings(kv)); err != nil {
		log.Warn("plex forwarder not started", "err", err)
	}
	defer plexMgr.Close()

	apiServer := api.New(st, box, cfg, px, pol, bans, feeds, certs, cs, met, notifier, geo, log)
	apiServer.SetPlex(plexMgr)
	restartCh := make(chan struct{}, 1)
	apiServer.SetRestart(func() {
		select {
		case restartCh <- struct{}{}:
		default:
		}
	})
	gui := http.NewServeMux()
	gui.Handle("/api/", apiServer.Handler())
	// The SPA lives outside the API mux, so apply the same hardening headers.
	gui.Handle("/", api.SecurityHeaders(webui.Handler()))

	guiSrv := &http.Server{
		Addr:              cfg.ListenGUI,
		Handler:           gui,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}

	met.Start(ctx)
	go apiServer.Start(ctx)
	go gateEngine.Start(ctx)
	go bots.Start(ctx)
	go feeds.Start(ctx)
	go pol.Start(ctx)
	go bans.Start(ctx)
	go certs.RenewLoop(ctx)
	notifier.Start(ctx)
	cs.Start(ctx)
	go retentionLoop(ctx, st, log)
	go certWatch(ctx, st, certs, notifier, log)

	go func() {
		log.Info("admin interface listening", "addr", cfg.ListenGUI)
		if err := guiSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("admin listener failed", "err", err)
			cancel()
		}
	}()

	proxyErr := make(chan error, 1)
	go func() { proxyErr <- px.Run(ctx, cfg.ListenWAN) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Info("shutting down", "signal", s.String())
	case <-restartCh:
		// Docker's restart policy (unless-stopped in the shipped compose file)
		// starts the container again with the listeners rebuilt.
		log.Info("restart requested; exiting for the container supervisor")
	case err := <-proxyErr:
		if err != nil {
			log.Error("proxy listener failed", "err", err)
		}
	}
	cancel()
	shutdownCtx, done := context.WithTimeout(context.Background(), 8*time.Second)
	defer done()
	_ = guiSrv.Shutdown(shutdownCtx)
	return nil
}

// plexConfigFromSettings rebuilds the saved Plex forwarder configuration.
func plexConfigFromSettings(kv map[string]string) plex.Config {
	port := plex.DefaultPort
	if v, err := strconv.Atoi(kv["plex_port"]); err == nil && v > 0 {
		port = v
	}
	maxConns := plex.DefaultMaxConns
	if v, err := strconv.Atoi(kv["plex_max_conns"]); err == nil && v > 0 {
		maxConns = v
	}
	allow := []string{}
	for _, part := range strings.Split(kv["plex_allow"], ",") {
		if part = strings.TrimSpace(part); part != "" {
			allow = append(allow, part)
		}
	}
	return plex.Config{
		Enabled:  kv["plex_enabled"] == "1",
		ListenIP: kv["plex_listen_ip"],
		Port:     port,
		Upstream: kv["plex_upstream"],
		Allow:    allow,
		MaxConns: maxConns,
	}
}

func newLogger() *slog.Logger {
	level := slog.LevelInfo
	switch os.Getenv("WAFPROXY_LOG_LEVEL") {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

func retentionLoop(ctx context.Context, st *store.Store, log *slog.Logger) {
	run := func() {
		kv, err := st.Settings()
		if err != nil {
			return
		}
		days := 7
		if v, err := strconv.Atoi(kv["retention_days"]); err == nil && v >= 1 && v <= 30 {
			days = v
		}
		cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
		if n, err := st.DeleteEventsBefore(cutoff); err == nil && n > 0 {
			log.Info("retention applied", "deleted_events", n, "days", days)
		}
		_ = st.RollupFlows(time.Now().Add(-time.Hour))
		_ = st.PurgeBans()
		_ = st.PurgeSessions()
		_ = st.PurgeGateFailures(time.Now().Add(-30 * 24 * time.Hour))
		if bytes, err := st.DBStats(); err == nil {
			log.Debug("database size", "bytes", bytes)
		}
	}
	run()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

func certWatch(ctx context.Context, st *store.Store, certs *acme.Manager, nt *notify.Manager, log *slog.Logger) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			list, err := st.ListCerts()
			if err != nil {
				continue
			}
			for _, c := range list {
				if c.ExpiresAt == nil {
					continue
				}
				days := int(time.Until(*c.ExpiresAt).Hours() / 24)
				if days <= 7 {
					nt.Enqueue("cert", fmt.Sprintf("Certificate for %s expires in %d days", c.Domains, days),
						"cert:"+c.Domains, true)
				}
			}
		}
	}
}
