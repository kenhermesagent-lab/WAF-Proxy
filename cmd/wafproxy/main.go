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
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/agentlink"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/anomaly"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/api"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/botguard"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/config"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/crowdsec"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/gate"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/intel"
	mcpgw "github.com/kenhermesagent-lab/waf-proxy-docker/internal/mcp"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/notify"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/policy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/proxy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/streaming"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/tailnet"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/updates"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/uptime"
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
	tailscaleIP := cfg.TailscaleIP
	tailscaleAdmin := kv["tailscale_admin_enabled"] == "1"
	tailscaleProxy := kv["tailscale_proxy_enabled"] == "1"
	tailscaleDNSPref := kv["tailscale_dns_enabled"] != "0"
	tailscaleDNS := tailscaleDNSPref && tailscaleProxy
	wanIface, lanIface := kv["wan_iface"], kv["lan_iface"]
	// The native installer records the interfaces in the environment. They are
	// used until the wizard exists and are copied into the database by setup,
	// so the dashboard and stealth rules agree with the bind addresses.
	if strings.TrimSpace(wanIface) == "" {
		wanIface = cfg.WANIface
	}
	if strings.TrimSpace(lanIface) == "" {
		lanIface = cfg.LANIface
	}
	// Listener addresses are chosen in the setup wizard and stored in the
	// database; the environment only supplies the first-boot fallback.
	fallbackWAN, fallbackGUI := cfg.ListenWAN, cfg.ListenGUI
	if v := strings.TrimSpace(kv["wan_port"]); v != "" {
		cfg.ListenWAN = net.JoinHostPort(strings.TrimSpace(kv["wan_ip"]), v)
	}
	if v := strings.TrimSpace(kv["gui_port"]); v != "" {
		cfg.ListenGUI = net.JoinHostPort(strings.TrimSpace(kv["lan_ip"]), v)
	}
	// A stored address disappears when the host moves networks or its DHCP
	// lease changes. Binding it would fail, the process would exit and the
	// restart policy would loop with no way back into the GUI, so fall back to
	// the first-boot address and log why. A single-NIC host stores the same
	// address for both, which is valid here.
	if !config.IsLocalAddress(cfg.ListenWAN) {
		log.Error("stored WAN address is not configured on this host; using the first-boot address",
			"configured", cfg.ListenWAN, "fallback", fallbackWAN)
		cfg.ListenWAN = fallbackWAN
	}
	if !config.IsLocalAddress(cfg.ListenGUI) {
		log.Error("stored GUI address is not configured on this host; using the first-boot address",
			"configured", cfg.ListenGUI, "fallback", fallbackGUI)
		cfg.ListenGUI = fallbackGUI
		// The first-boot fallback is normally ":8080" (every interface), which
		// exposes the admin login on the WAN until the stored address is fixed.
		if host, _, err := net.SplitHostPort(cfg.ListenGUI); err == nil {
			if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
				log.Warn("admin GUI is bound to all interfaces until the stored address is fixed in Settings",
					"gui", cfg.ListenGUI)
			}
		}
	}

	tailAdminAddr, tailProxyAddr := "", ""
	tailAdminErr, tailProxyErr := "", ""
	if tailscaleAdmin {
		switch {
		case tailscaleIP == "":
			tailAdminErr = "Tailscale is not connected; admin tailnet listener not started"
			log.Warn(tailAdminErr)
		case wildcardBind(cfg.ListenGUI):
			tailAdminErr = "LAN admin listener uses a wildcard bind; set a concrete LAN address before enabling Tailscale admin access"
			log.Error(tailAdminErr, "addr", cfg.ListenGUI)
		default:
			tailAdminAddr = net.JoinHostPort(tailscaleIP, strconv.Itoa(portOf(cfg.ListenGUI, 8443)))
		}
	}
	if tailscaleProxy {
		switch {
		case tailscaleIP == "":
			tailProxyErr = "Tailscale is not connected; proxy tailnet listener not started"
			log.Warn(tailProxyErr)
		case wildcardBind(cfg.ListenWAN):
			tailProxyErr = "WAN listener uses a wildcard bind; set a concrete WAN address before enabling Tailscale proxy access"
			log.Error(tailProxyErr, "addr", cfg.ListenWAN)
		default:
			tailProxyAddr = net.JoinHostPort(tailscaleIP, strconv.Itoa(portOf(cfg.ListenWAN, 443)))
		}
	}
	if tailAdminAddr != "" && tailAdminAddr == tailProxyAddr {
		tailProxyErr = "admin and proxy tailnet listeners cannot share a port"
		log.Error(tailProxyErr, "addr", tailProxyAddr)
		tailProxyAddr = ""
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
	uptimeMon := uptime.New(st, notifier, log)

	// Assigned once the listeners exist; the ban callback needs it to cut
	// streams that were already running when the ban landed.
	var streams *streaming.Manager

	bans.OnAdd = func(rec ban.Record) {
		kind := "Temporary ban"
		if rec.Permanent {
			kind = "Permanent ban"
		}
		// The routing class comes from the ban source, so a CrowdSec decision is
		// muted by its own toggle and never by the temporary-ban one.
		event := notify.BanClass(rec.Source, rec.Permanent)
		immediate := rec.Permanent
		text := fmt.Sprintf("%s: %s — %s (source: %s)", kind, rec.CIDR, rec.Reason, rec.Source)
		// A temporary ban must not suppress the permanent-ban alert for the same
		// address through the 24 hour dedupe window.
		dedupe := "ban:" + rec.CIDR
		if rec.Permanent {
			dedupe = "permanent-ban:" + rec.CIDR
		}
		notifier.Enqueue(event, text, dedupe, immediate)
		if streams == nil {
			return
		}
		cut := streams.DropBanned(func(addr netip.Addr) bool {
			_, banned := bans.Match(addr)
			return banned
		}, fmt.Sprintf("stream closed by ban %s (%s)", rec.CIDR, rec.Reason))
		if cut > 0 {
			log.Info("closed streaming connections for banned source", "cidr", rec.CIDR, "streams", cut)
		}
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
	csURL, csKey := cfg.CrowdSecURL, cfg.CrowdSecKey
	csEnabled := true
	if raw, ok := kv["crowdsec_enabled"]; ok {
		csEnabled = raw == "1"
	}
	if v := strings.TrimSpace(kv["crowdsec_url"]); v != "" {
		csURL = v
	}
	if enc := kv["crowdsec_key"]; enc != "" {
		if plain, err := box.Open(enc); err == nil {
			csKey = plain
		}
	}
	if !csEnabled {
		csURL, csKey = "", ""
	}
	cs := crowdsec.New(csURL, csKey, bans, log)
	if csURL != "" && csKey != "" {
		log.Info("crowdsec bouncer enabled", "lapi", csURL)
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

	streams = streaming.New(log)
	// The relay bypasses the request pipeline, so banned addresses have to be
	// refused here as well or they could still stream through a forwarded port.
	streams.SetBans(func(addr netip.Addr) bool {
		_, banned := bans.Match(addr)
		return banned
	})
	// Refusals and cut streams are written as ordinary events so they appear in
	// Logs and on the attack globe next to the HTTP traffic. The payload carries
	// the service and port, so the sink needs no manager lookup.
	streams.SetEventSink(func(ev streaming.Event) {
		row := model.Event{
			TS: time.Now(), Host: ev.Service, SrcIP: ev.Addr.String(),
			Method: "TCP", Path: fmt.Sprintf(":%d", ev.Port),
			Status: http.StatusForbidden, Stage: "stream", Action: "block",
			RuleID: "stream-ban", RuleMsg: ev.Detail,
		}
		if err := st.InsertEvents([]model.Event{row}); err != nil {
			log.Warn("streaming event insert failed", "err", err)
		}
	})
	cfgs := make(map[string]streaming.Config, len(streaming.Catalog))
	for _, def := range streaming.Catalog {
		cfgs[def.ID] = streaming.ConfigFromSettings(def, kv)
	}
	if err := streams.ApplyAll(cfgs); err != nil {
		log.Warn("streaming forwarder not started", "err", err)
	}
	defer streams.Close()

	var dnsSrv *tailnet.DNS
	dnsAddr, dnsErr := "", ""
	dnsUp := false
	if tailProxyAddr != "" && tailscaleDNS {
		dnsAddr = net.JoinHostPort(tailscaleIP, "53")
		dnsSrv = tailnet.NewDNS(dnsAddr, func() ([]string, error) {
			list, err := st.ListProxies()
			if err != nil {
				return nil, err
			}
			hosts := make([]string, 0, len(list))
			for _, p := range list {
				hosts = append(hosts, p.Hostname)
			}
			return hosts, nil
		}, log)
		if err := dnsSrv.Start(); err != nil {
			dnsErr = err.Error()
			dnsSrv = nil
			log.Error("tailnet split DNS failed to start", "err", err)
		} else {
			dnsUp = true
		}
	}
	if dnsSrv != nil {
		defer dnsSrv.Close()
	}

	updateManager := updates.New(log)
	updateManager.SetDataDir(cfg.DataDir)
	// Check host packages daily so the Updates page already has an answer when
	// it is opened, instead of only after the operator presses Check.
	go func() {
		timer := time.NewTimer(2 * time.Minute)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				if _, err := updateManager.Check(ctx); err != nil {
					log.Warn("daily update check failed", "err", err)
				}
				timer.Reset(24 * time.Hour)
			}
		}
	}()
	apiServer := api.New(st, box, cfg, px, pol, bans, feeds, certs, cs, met, notifier, geo, log)
	apiServer.StartBackup(ctx)
	apiServer.StartAutoUpdate(ctx)
	agentLinks := agentlink.New(st, box, log)
	agentLinks.SetRouting(notifier.EventEnabled)
	apiServer.SetAgentLinks(agentLinks)
	go agentLinks.Start(ctx)
	anomalyMon := anomaly.New(st, met, notifier, log)
	anomalyMon.SetSink(agentLinks.Publish)
	apiServer.SetAnomaly(anomalyMon)
	go anomalyMon.Start(ctx)
	apiServer.SetStreaming(streams)
	apiServer.SetUpdates(updateManager)
	apiServer.SetUptime(uptimeMon)
	restartCh := make(chan struct{}, 1)
	apiServer.SetRestart(func() {
		select {
		case restartCh <- struct{}{}:
		default:
		}
	})
	gui := http.NewServeMux()
	gui.Handle("/api/", apiServer.Handler())
	// The agent gateway is deliberately outside /api: it has its own bearer
	// authentication and does not use the admin session or CSRF token.
	mcpGateway := mcpgw.New(st, bans, log, mcpgw.Options{EnvToken: cfg.MCPToken, EnvActor: cfg.MCPActor})
	gui.Handle(mcpgw.Endpoint, mcpGateway)
	gui.Handle(mcpgw.Endpoint+"/", mcpGateway)
	if cfg.MCPToken != "" {
		log.Info("MCP gateway enabled with the environment token", "endpoint", mcpgw.Endpoint, "actor", cfg.MCPActor)
	} else {
		log.Info("MCP gateway available for console-issued tokens", "endpoint", mcpgw.Endpoint)
	}
	// The SPA lives outside the API mux, so apply the same hardening headers.
	gui.Handle("/", api.SecurityHeaders(webui.Handler()))

	type guiListener struct {
		addr  string
		srv   *http.Server
		ln    net.Listener
		fatal bool
	}
	var guiListeners []guiListener
	listenGUI := func(addr string, handler http.Handler, fatal bool) string {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err.Error()
		}
		srv := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    32 << 10,
		}
		guiListeners = append(guiListeners, guiListener{addr: addr, srv: srv, ln: ln, fatal: fatal})
		return ""
	}

	var lanHandler http.Handler = gui
	if cfg.GUIPrivateOnly {
		lanHandler = api.PrivateNetworksOnly(gui)
	}
	if msg := listenGUI(cfg.ListenGUI, lanHandler, true); msg != "" {
		log.Error("admin listener failed", "addr", cfg.ListenGUI, "err", msg)
		cancel()
	}
	tailAdminUp := false
	if tailAdminAddr != "" {
		if msg := listenGUI(tailAdminAddr, api.TailscaleOnly(gui), false); msg != "" {
			tailAdminErr = msg
			log.Error("tailnet admin listener failed", "addr", tailAdminAddr, "err", msg)
		} else {
			tailAdminUp = true
		}
	}

	apiServer.SetTailscaleState(api.TailscaleState{
		AdminAddr: tailAdminAddr, ProxyAddr: tailProxyAddr, DNSAddr: dnsAddr,
		AdminOn: tailscaleAdmin, ProxyOn: tailscaleProxy, DNSOn: tailscaleDNSPref,
		AdminUp: tailAdminUp, DNSUp: dnsUp,
		AdminError: tailAdminErr, ProxyError: tailProxyErr, DNSError: dnsErr,
	})

	met.Start(ctx)
	mcpGateway.Start(ctx)
	go apiServer.Start(ctx)
	go gateEngine.Start(ctx)
	go bots.Start(ctx)
	go feeds.Start(ctx)
	go pol.Start(ctx)
	go bans.Start(ctx)
	go certs.RenewLoop(ctx)
	notifier.Start(ctx)
	uptimeMon.Start(ctx)
	cs.Start(ctx)
	go retentionLoop(ctx, st, log)
	go certWatch(ctx, st, certs, notifier, log)

	for _, gl := range guiListeners {
		go func(gl guiListener) {
			log.Info("admin interface listening", "addr", gl.addr)
			if err := gl.srv.Serve(gl.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("admin listener failed", "addr", gl.addr, "err", err)
				if gl.fatal {
					cancel()
				}
			}
		}(gl)
	}

	proxyErr := make(chan error, 1)
	go func() { proxyErr <- px.Run(ctx, cfg.ListenWAN, tailProxyAddr) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Info("shutting down", "signal", s.String())
	case <-restartCh:
		// The service supervisor (Docker's restart policy or systemd Restart=)
		// starts the process again with the listeners rebuilt.
		log.Info("restart requested; exiting for the service supervisor")
	case err := <-proxyErr:
		if err != nil {
			log.Error("proxy listener failed", "err", err)
		}
	}
	cancel()
	shutdownCtx, done := context.WithTimeout(context.Background(), 8*time.Second)
	defer done()
	for _, gl := range guiListeners {
		_ = gl.srv.Shutdown(shutdownCtx)
	}
	return nil
}

func wildcardBind(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	return host == "" || host == "0.0.0.0" || host == "::"
}

func portOf(addr string, fallback int) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fallback
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fallback
	}
	return n
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
