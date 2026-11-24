// Command wafproxy runs the WAF reverse proxy and its admin API.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/agentlink"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/api"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/backup"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/botguard"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/bundle"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/clientip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/cloudflared"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/config"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/crowdsec"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/gate"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ha"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/intel"
	mcpgw "github.com/kenhermesagent-lab/waf-proxy-docker/internal/mcp"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/notify"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/proxy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/siteres"
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
	if len(os.Args) > 1 {
		var err error
		switch os.Args[1] {
		case "unban":
			err = unbanCLI(os.Args[2:])
		case "setup":
			err = setupCLI(os.Args[2:])
		case "recover":
			err = recoverCLI(os.Args[2:])
		case "backup":
			err = backupCLI(os.Args[2:])
		case "sites":
			err = sitesCLI(os.Args[2:])
		case "ha":
			err = haCLI(os.Args[2:])
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, os.Args[1]+":", err)
			os.Exit(1)
		}
		if os.Args[1] == "unban" || os.Args[1] == "setup" || os.Args[1] == "recover" || os.Args[1] == "backup" || os.Args[1] == "sites" || os.Args[1] == "ha" {
			return
		}
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

// backupCLI writes an encrypted backup and prunes older ones, so a nightly
// job is one command.
func backupCLI(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	out := fs.String("out", "", "output file (default: <data>/backups/wafproxy-backup-<time>.json.enc)")
	pass := fs.String("passphrase", os.Getenv("WAFPROXY_BACKUP_PASSPHRASE"), "encryption passphrase, at least 16 characters")
	keep := fs.Int("keep", 0, "keep only the newest N backups in the output directory")
	site := fs.String("site", "", "back up one site by slug (default: every site in one file)")
	all := fs.Bool("all", false, "write one file per site plus a sites manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(*pass) < 16 {
		return errors.New("the passphrase must be at least 16 characters")
	}
	if *site != "" && *all {
		return errors.New("--site and --all are mutually exclusive")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	if *out == "" {
		dir := filepath.Join(cfg.DataDir, "backups")
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
		*out = filepath.Join(dir, "wafproxy-backup-"+time.Now().UTC().Format("20060102T150405Z")+".json.enc")
	}
	if *all {
		return backupAllSites(st, *out, *pass)
	}
	target := st.Unscoped()
	if *site != "" {
		s, err := st.SiteBySlug(*site)
		if err != nil {
			return fmt.Errorf("site %q: %w", *site, err)
		}
		target = st.InSite(s.ID)
	}
	doc, err := api.BuildBackupDocument(target)
	if err != nil {
		return err
	}
	sealed, err := backup.Encrypt(*pass, doc)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, sealed, 0o600); err != nil {
		return err
	}
	if *keep > 0 {
		removed, err := pruneBackups(filepath.Dir(*out), *keep)
		if err != nil {
			return err
		}
		fmt.Printf("wrote %s; removed %d older backup(s)\n", *out, removed)
		return nil
	}
	fmt.Printf("wrote %s\n", *out)
	return nil
}

// backupAllSites writes one encrypted file per site plus a plain manifest, so a
// restore can name a site without decrypting every file.
func backupAllSites(st *store.Store, out, pass string) error {
	sites, err := st.ListSites()
	if err != nil {
		return err
	}
	dir := filepath.Dir(out)
	base := strings.TrimSuffix(filepath.Base(out), ".enc")
	manifest := make([]map[string]string, 0, len(sites))
	for _, site := range sites {
		doc, err := api.BuildBackupDocument(st.InSite(site.ID))
		if err != nil {
			return err
		}
		sealed, err := backup.Encrypt(pass, doc)
		if err != nil {
			return err
		}
		name := filepath.Join(dir, base+"-"+site.Slug+".enc")
		if err := os.WriteFile(name, sealed, 0o600); err != nil {
			return err
		}
		manifest = append(manifest, map[string]string{
			"slug": site.Slug, "name": site.Name,
			"console_host": site.ConsoleHost, "file": filepath.Base(name),
		})
		fmt.Printf("wrote %s\n", name)
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "sites.json"), data, 0o600)
}

// pruneBackups keeps the newest keep files matching the backup name.
func pruneBackups(dir string, keep int) (int, error) {
	files, err := filepath.Glob(filepath.Join(dir, "wafproxy-backup-*.json.enc"))
	if err != nil {
		return 0, err
	}
	type entry struct {
		path string
		mod  time.Time
	}
	entries := make([]entry, 0, len(files))
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		entries = append(entries, entry{path: path, mod: info.ModTime()})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].mod.After(entries[j].mod) })
	removed := 0
	for i := keep; i < len(entries); i++ {
		if err := os.Remove(entries[i].path); err == nil {
			removed++
		}
	}
	return removed, nil
}

// setupCLI creates the first administrator without a browser, for image builds
// and configuration management. It refuses to touch an initialized install.
func setupCLI(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	user := fs.String("user", "admin", "administrator username")
	pass := fs.String("password", "", "administrator password (required)")
	base := fs.String("base-domain", "", "base domain for site hostnames")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(*pass) < 12 {
		return errors.New("the password must be at least 12 characters")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	if n, err := st.CountUsers(); err != nil {
		return err
	} else if n > 0 {
		return errors.New("this install already has an administrator")
	}
	hash, err := auth.HashPassword(*pass)
	if err != nil {
		return err
	}
	if _, err := st.CreateFirstUser(strings.TrimSpace(*user), hash, "", "", false); err != nil {
		return err
	}
	if domain := strings.TrimSpace(*base); domain != "" {
		if err := st.SetSettings(map[string]string{"base_domain": domain}); err != nil {
			return err
		}
	}
	fmt.Printf("administrator %q created; sign in at the console with %s\n", *user, cfg.ListenGUI)
	return nil
}

// recoverCLI is the break-glass path when the console is unreachable: it
// changes a password and/or clears TOTP directly in the database.
func recoverCLI(args []string) error {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	user := fs.String("user", "admin", "administrator username")
	pass := fs.String("password", "", "new password (optional)")
	resetTOTP := fs.Bool("reset-totp", false, "disable TOTP for this account")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pass == "" && !*resetTOTP {
		return errors.New("nothing to do: pass --password and/or --reset-totp")
	}
	if *pass != "" && len(*pass) < 12 {
		return errors.New("the password must be at least 12 characters")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	// The account may belong to any site; recovery is break-glass, so look
	// across all of them rather than only the default site's console.
	all := st.Unscoped()
	account, err := all.UserByUsername(strings.TrimSpace(*user))
	if err != nil {
		return fmt.Errorf("user %q: %w", *user, err)
	}
	changed := []string{}
	if *pass != "" {
		hash, err := auth.HashPassword(*pass)
		if err != nil {
			return err
		}
		if err := all.UpdateUserPassword(account.ID, hash); err != nil {
			return err
		}
		changed = append(changed, "password")
	}
	if *resetTOTP {
		if err := all.UpdateUserTOTP(account.ID, "", "", false); err != nil {
			return err
		}
		changed = append(changed, "TOTP")
	}
	// Either change is a credential reset, so a stolen session, a remembered
	// browser or a pending reset link must not survive it.
	for _, revoke := range []func(int64) error{
		all.DeleteUserSessions, all.DeleteUserTrustedDevices, all.DeleteUserPasswordResets,
	} {
		if err := revoke(account.ID); err != nil {
			return err
		}
	}
	fmt.Printf("reset %s for %q; existing sessions and remembered browsers were invalidated\n", strings.Join(changed, " and "), *user)
	return nil
}

// consoleTLSConfig serves the certificate that matches the requested console
// host. The callback resolves through the certificate manager on each
// handshake rather than capturing the certificate at startup, so a renewal or
// replacement is picked up without restarting the listener, and a second site's
// console host gets its own certificate from the same listener.
// consoleCerts is the certificate lookup the console listener needs: one ACME
// manager on a single-site install, the per-site set once sites exist.
type consoleCerts interface {
	CertificateForHost(host string) (*tls.Certificate, error)
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

func consoleTLSConfig(certs consoleCerts, host string) (*tls.Config, error) {
	if _, err := certs.CertificateForHost(host); err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := strings.TrimSpace(hello.ServerName)
			if name == "" || strings.EqualFold(name, host) {
				name = host
			}
			return certs.CertificateForHost(name)
		},
	}, nil
}

func run() error {
	log := newLogger()
	log.Info("starting", "version", version.Version, "commit", version.Commit)

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	trusted, err := clientip.New(cfg.TrustedProxies)
	if err != nil {
		return err
	}
	// The console is safe without a wrapper: a bare container or binary binds
	// loopback and refuses non-private clients unless the operator says so.
	if host, _, splitErr := net.SplitHostPort(cfg.ListenGUI); splitErr == nil {
		ip := net.ParseIP(host)
		if !cfg.GUIPrivateOnly && (ip == nil || !ip.IsLoopback()) {
			log.Warn("the admin console accepts clients from any network", "addr", cfg.ListenGUI,
				"hint", "bind 127.0.0.1:8080 or set WAFPROXY_GUI_PRIVATE_ONLY=true")
		}
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	// Session cookies are stored as a keyed digest, so a copy of the database
	// does not hand out live admin sessions.
	st.SetSessionKey(cfg.MasterKey)

	box, err := wfcrypto.New(cfg.MasterKey)
	if err != nil {
		return err
	}
	// Certificate private keys are sealed at rest. The pass re-seals rows an
	// older release wrote in plaintext and is a no-op afterwards.
	st.SetSecretBox(box)
	if n, err := st.Unscoped().SealStoredCertKeys(); err != nil {
		return fmt.Errorf("seal certificate keys: %w", err)
	} else if n > 0 {
		log.Info("sealed certificate private keys", "count", n)
	}
	// The stored host-wide switch decides whether this boot runs HA. Missing
	// means off, and a leftover standby without a pair must serve as a single
	// node rather than answer traffic with none of the active loops running. A
	// paired standby is different: it is the backup, so it stays a standby and
	// stays out of service, or the pair would have two writers.
	haOn := haSettingOn(st)
	pair, pairErr := ha.LoadPair(cfg.DataDir)
	paired := pair != nil
	if pairErr != nil {
		// An unreadable record is not proof of a single node: while HA is on,
		// count it as paired so a standby cannot start serving alone.
		log.Error("could not read the HA pair", "err", pairErr)
		paired = haOn
	}
	// The pairing identity exists before HA is turned on, so the Settings switch
	// can pair this node without a restart and a fresh node has the id its role
	// file needs to become standalone. An active node captures every streamed
	// change into the outbox; a standby writes none and pays nothing for the
	// machinery.
	haIdent, err := ha.LoadOrCreateIdentity(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("ha identity: %w", err)
	}
	// The role file decides which background work this node may do. A missing
	// or damaged file loads as standby, so the safe answer is the default. With
	// HA off the node is standalone and runs everything, as it always has.
	node, roleErr := ha.Load(cfg.DataDir)
	if roleErr != nil {
		log.Error("reading the node role; refusing to run active-only work", "err", roleErr)
	}
	if n, err := haBootRole(cfg.DataDir, node, paired, haOn); err != nil {
		log.Warn("could not normalise the role while HA is off", "err", err)
	} else {
		node = n
	}
	startActive := node.Active()
	if haOn {
		log.Info("high availability", "enabled", haOn,
			"paired", paired, "role", node.Role, "active_work", startActive)
	}
	// haQuiesce pauses configuration writes while a planned move drains this
	// node. It is in memory: a crash releases it.
	haQuiesce := ha.NewQuiesce()
	if haOn && node.Active() {
		st.SetNodeID(haIdent.Node)
	}
	// The standby's audit chain arrives from the active; a local row would
	// break it. The console is read-only there, so nothing of value is lost.
	st.SetAuditEnabled(node.Active())
	// The witness is optional: with one, an active that cannot renew its lease
	// stops serving; without one, moves stay manual.
	var witness *ha.WitnessClient
	if cfg.HAWitness != "" {
		if pair != nil {
			witness = &ha.WitnessClient{
				URL: cfg.HAWitness, Token: cfg.HAWitnessToken,
				ClusterID: pair.ClusterID, Holder: haIdent.Node,
			}
		} else {
			log.Warn("ha witness configured but this node is not paired; no lease is renewed")
		}
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
		if haOn {
			// In HA mode the WAN address is the floating service address. It
			// belongs to the other node until a move, so it must not be replaced
			// by a boot fallback: the standby holds it with IP_FREEBIND.
			log.Info("ha: keeping the floating service address, which this node does not own yet",
				"configured", cfg.ListenWAN)
		} else {
			log.Error("stored WAN address is not configured on this host; using the first-boot address",
				"configured", cfg.ListenWAN, "fallback", fallbackWAN)
			cfg.ListenWAN = fallbackWAN
		}
	}
	if !config.IsLocalAddress(cfg.ListenGUI) {
		log.Error("stored GUI address is not configured on this host; using the first-boot address",
			"configured", cfg.ListenGUI, "fallback", fallbackGUI)
		cfg.ListenGUI = fallbackGUI
		// The first-boot fallback is loopback by default; a wildcard fallback
		// would expose the admin login on the WAN until the address is fixed.
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

	// The proxy side serves every hostname, so its engines see every site's
	// rows. The console keeps the default-scoped handle and narrows per request.
	all := st.Unscoped()

	met := metrics.New(wanIface, lanIface)
	kernel := ban.NewKernel(log)
	bans, err := ban.New(all, log, kernel)
	if err != nil {
		return err
	}
	feeds := intel.New(all, log, 32<<20)
	// Signed signature packs. Each provider is one manifest plus the key it must
	// be signed with; a provider missing either half stays off, and the service
	// still loads any pack already on disk.
	providers, err := bundle.ParseProviders(cfg.BundleProvidersJSON, cfg.BundleURL, cfg.BundlePublicKey)
	if err != nil {
		return fmt.Errorf("bundle channel: %w", err)
	}
	// Providers saved from the console take over from the environment once an
	// administrator edits the list there.
	if raw, gerr := st.GetSetting(bundle.SettingsKey); gerr == nil && strings.TrimSpace(raw) != "" {
		providers, err = bundle.ParseProviderList(raw)
		if err != nil {
			return fmt.Errorf("bundle providers saved in the console: %w", err)
		}
	}
	bundles, err := bundle.New(bundle.Config{
		Dir:       filepath.Join(cfg.DataDir, "bundles"),
		Providers: providers,
		Interval:  time.Duration(cfg.BundleIntervalSeconds) * time.Second,
		Log:       log,
	})
	if err != nil {
		return fmt.Errorf("bundle channel: %w", err)
	}
	if err := bundles.Load(); err != nil {
		log.Warn("could not load installed bundles", "err", err)
	}
	profiles, err := all.ListProfiles()
	if err != nil {
		return err
	}
	wafs := waf.NewSet(profiles, log)
	wafs.SetBundles(bundles.Rules())
	// One instance of policy, notifications, anomaly detection, the canary and
	// the ACME client per site. The default site's instances are the ones a
	// single-site install has always used, so an upgrade changes nothing.
	res, err := siteres.New(siteres.Deps{
		Store: st, Box: box, Log: log, Bans: bans, Feeds: feeds, Geo: geo,
		Metrics: met, Bundles: bundles.Rules,
		ACMEDirectory: cfg.ACMEDirectory, ACMECAFile: cfg.ACMECAFile,
	})
	if err != nil {
		return err
	}
	router := siteres.NewRouter(res)
	certs := res.Default().ACME
	notifier := res.Default().Notify
	uptimeMon := uptime.New(all, notifier, log)

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
		target := notifier
		if b, err := res.For(rec.SiteID); err == nil {
			target = b.Notify
		}
		target.Enqueue(event, text, dedupe, immediate)
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

	gateEngine := gate.New(all, box, bans, log)
	gateEngine.OnBan = func(ip, reason string, permanent bool) {
		kind := "Temporary ban"
		if permanent {
			kind = "Permanent ban"
		}
		notifier.Enqueue("gate", fmt.Sprintf("%s: %s — access gate (%s)", kind, ip, reason), "gate:"+ip, permanent)
	}
	bots := botguard.New(cfg.MasterKey, bans, all, log)
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

	// A new pack is compiled into every site's profiles before the next
	// request, the same path a profile edit already takes.
	bundles.OnChange(func() {
		res.Each(func(b *siteres.Bundle) {
			b.Wafs.SetBundles(bundles.Rules())
			if err := b.Policy.ReloadWAF(); err != nil {
				log.Error("reload WAF after bundle install", "site", b.Site.Slug, "err", err)
			}
		})
	})
	if cfg.MemoryLimit > 0 {
		debug.SetMemoryLimit(cfg.MemoryLimit)
	}
	px, err := proxy.New(proxy.Deps{
		Store: all, Policy: router, Gate: gateEngine, Bots: bots, Bans: bans,
		Geo: geo, Metrics: met, Log: log, ClientIP: trusted,
	})
	if err != nil {
		return err
	}
	px.SetMaxInflight(cfg.MaxInflight)
	px.SetBudget(cfg.MaxBufferedBytes, time.Duration(cfg.QueueMS)*time.Millisecond)
	px.SetBodyTimeout(time.Duration(cfg.BodyTimeout) * time.Second)
	px.SetCertProvider(res)
	// TLS-ALPN-01 validations are answered by the WAN listener itself; lego's
	// own server would have to bind port 443 a second time.
	px.SetALPNProvider(res)
	// HTTP-01 tokens are served by our own plain-HTTP listener, not a second
	// bind on port 80 started from inside the ACME client.
	px.SetHTTPChallengeHandler(res.HTTPChallenge())
	cur := router.Settings(res.DefaultID())
	px.SetBodyLimit(cur.MaxBody)
	bans.SetStealth(cur.StealthPing, cur.WANIface)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Loops that only an active node may run. A standby starts none of them;
	// a promotion starts them, and a demotion stops them.
	active := newActiveSupervisor(ctx)

	if err := px.Reload(ctx); err != nil {
		return err
	}

	// HTTP/3 shares the WAN port over UDP. A UDP forwarder on that number would
	// bind first (the data plane starts the forwarders before the listener
	// serves), so the conflict is named here instead of surfacing as a bare
	// "address already in use" from the QUIC socket.
	if cfg.HTTP3 {
		port, err := wanPort(cfg.ListenWAN)
		if err != nil {
			return fmt.Errorf("WAFPROXY_HTTP3: %w", err)
		}
		kv, err := st.Settings()
		if err != nil {
			return err
		}
		if err := http3StreamConflict(kv, port); err != nil {
			return err
		}
		px.EnableHTTP3(port)
		log.Info("http/3 enabled", "udp_port", port)
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
	streamWriter := newStreamEvents(st, log)
	defer streamWriter.stop()
	streams.SetEventSink(func(ev streaming.Event) { streamWriter.record(streamEventRow(ev)) })
	// A forwarder enforces the same named lists as a proxied site; country
	// entries need the GeoIP database the HTTP pipeline already loads.
	if accessLists, err := st.ListAccessLists(); err != nil {
		log.Warn("streaming lists not loaded", "err", err)
	} else {
		lists := make([]streaming.List, 0, len(accessLists))
		for _, l := range accessLists {
			lists = append(lists, streaming.List{ID: l.ID, Name: l.Name, Block: l.Kind == model.ListKindBlock,
				Prefixes: splitCSV(l.IPs), Countries: splitCSV(l.Countries)})
		}
		streams.SetLists(lists)
	}
	streams.SetCountryLookup(func(addr netip.Addr) string {
		return strings.ToUpper(geo.Lookup(addr).Country)
	})
	// Every promotion reads the settings again: a card saved while this node
	// was active, or replicated from the peer while it was a standby, must be
	// what the forwarders bind, not the map read at boot.
	streamCfgs := func() (map[string]streaming.Config, error) {
		kv, err := st.Settings()
		if err != nil {
			return nil, err
		}
		out := make(map[string]streaming.Config, len(streaming.Catalog))
		for _, def := range streaming.Catalog {
			out[def.ID] = streaming.ConfigFromSettings(def, kv)
		}
		return out, nil
	}
	// Forwarders start with the data plane, not at boot: a standby must not
	// hold a media port, and a promoted node rebinds them.
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
	api.SetTrustedProxies(trusted)
	cloudflareConnector := cloudflared.New(log)
	cloudflareConnector.RefreshVersion(true)
	apiServer := api.New(st, box, cfg, px, res.Default().Policy, bans, feeds, certs, cs, met, notifier, geo, res, log)
	apiServer.SetCloudflared(cloudflareConnector)
	// The connector is started here rather than by systemd, because the console
	// owns its lifecycle: the Enable switch and the token decide whether it runs.
	defer cloudflareConnector.Stop()
	if hostKV, err := st.Settings(); err == nil {
		connectorCfg := cloudflared.Load(hostKV, box)
		trusted.SetCDN(connectorCfg.Enabled && connectorCfg.StrictOrigin)
		if connectorCfg.Enabled && connectorCfg.Token != "" {
			if err := cloudflareConnector.Start(connectorCfg.Token); err != nil {
				log.Warn("cloudflared connector not started", "err", err)
			}
		}
	}
	apiServer.SetBundles(bundles)
	// The runtime is created after the data plane, so the status closure needs
	// a holder it can read once boot reaches that point. The GUI listeners may
	// already be accepting, so publish it atomically.
	var haRT atomic.Pointer[haRuntime]
	apiServer.SetHAStatus(func() api.HAStatus {
		n, _ := ha.Load(cfg.DataDir)
		state := n.EffectiveState()
		pair, _ := ha.LoadPair(cfg.DataDir)
		// The effective switch is read on every request, so turning HA off in
		// Settings takes effect without a restart. Missing means off.
		enabled := haSettingOn(st)
		status := api.HAStatus{
			Enabled: enabled, Role: string(n.Role), State: string(state),
			Serving: ha.Serving(state), Epoch: n.Epoch, Peer: n.Peer,
			Reason: n.Reason, UpdatedAt: n.UpdatedAt,
		}
		if pair != nil {
			status.Paired = true
			status.ClusterID = pair.ClusterID
			status.PeerFingerprint = pair.PeerFingerprint
		}
		if rt := haRT.Load(); rt != nil {
			if err := rt.runtimeFailure(); err != nil {
				status.RuntimeError = err.Error()
			}
		}
		return status
	})
	// A standby must not run backups or apply updates: those belong to the
	// active, and they start again after a promotion.
	active.Add(func(ctx context.Context) { apiServer.StartBackup(ctx) })
	active.Add(func(ctx context.Context) { apiServer.StartAutoUpdate(ctx) })
	agentLinks := agentlink.New(st, box, log)
	agentLinks.SetRouting(notifier.EventEnabled)
	apiServer.SetAgentLinks(agentLinks)
	active.Add(func(ctx context.Context) { agentLinks.Start(ctx) })
	res.Each(func(b *siteres.Bundle) { b.Anomaly.SetSink(agentLinks.Publish) })
	apiServer.SetStreaming(streams)
	apiServer.SetStreamEventDrops(streamWriter.Dropped)
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
	gui.Handle("/metrics", apiServer.Handler())
	// The agent gateway is deliberately outside /api: it has its own bearer
	// authentication and does not use the admin session or CSRF token.
	// Tokens are minted on the default site's console, and every console page
	// answers for one site, so the gateway reads that site's rows. An unscoped
	// store would let one token read every tenant's logs and gate sessions.
	mcpStore := st
	if def, err := st.SiteBySlug(store.DefaultSiteSlug); err == nil && def != nil {
		mcpStore = st.InSite(def.ID)
	}
	mcpGateway := mcpgw.New(mcpStore, bans, log, mcpgw.Options{EnvToken: cfg.MCPToken, EnvActor: cfg.MCPActor})
	mcpGateway.SetStreaming(streams)
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
		if cfg.ListenGUITLS {
			// Resolve once here so a missing certificate fails the listener at
			// boot, then again on every handshake so renewals reach the console.
			tlsCfg, err := consoleTLSConfig(res, cfg.GUIHost)
			if err != nil {
				ln.Close()
				return "console TLS: " + err.Error()
			}
			ln = tls.NewListener(ln, tlsCfg)
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
	// In HA mode the service address moves between nodes, so each node also
	// answers its console on a fixed management address of its own.
	if haOn && cfg.HAMgmtListen != "" && cfg.HAMgmtListen != cfg.ListenGUI {
		if msg := listenGUI(cfg.HAMgmtListen, lanHandler, true); msg != "" {
			log.Error("management listener failed", "addr", cfg.HAMgmtListen, "err", msg)
			cancel()
		}
	}
	if haOn {
		ident := haIdent
		log.Info("ha identity ready", "node", ident.Node, "fingerprint", ha.Fingerprint(ident.Leaf), "capturing", st.Capturing())
		if cfg.HALinkListen != "" {
			join := ha.NewJoinServer(ident, cfg.DataDir, cfg.MasterKey, st, log)
			join.SetQuiesce(haQuiesce)
			ln, err := tls.Listen("tcp", cfg.HALinkListen, join.TLSConfig())
			if err != nil {
				log.Error("ha link listener failed", "addr", cfg.HALinkListen, "err", err)
				cancel()
			} else {
				srv := &http.Server{Handler: join.Handler(), ReadHeaderTimeout: 10 * time.Second}
				log.Info("ha link listening", "addr", cfg.HALinkListen)
				go func() {
					if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
						log.Error("ha link stopped", "err", err)
						cancel()
					}
				}()
			}
		}
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
	// A standby must not renew certificates, fetch feeds or reconcile the
	// kernel: the active does that, and two copies of an ACME order or a ban
	// reconcile is how a pair fights itself.
	active.Add(func(ctx context.Context) { gateEngine.Start(ctx) })
	active.Add(func(ctx context.Context) { bots.Start(ctx) })
	active.Add(func(ctx context.Context) { feeds.Start(ctx) })
	active.Add(func(ctx context.Context) { bundles.Start(ctx) })
	active.Add(func(ctx context.Context) {
		// A second promotion must relaunch the per-site loops, so clear the
		// started flags the first one set.
		res.Reset()
		res.Start(ctx)
	})
	active.Add(func(ctx context.Context) { bans.Start(ctx) })
	active.Add(func(ctx context.Context) { geoAutoUpdate(ctx, st, geo, log) })

	uptimeMon.Start(ctx)
	active.Add(func(ctx context.Context) { cs.Start(ctx) })
	active.Add(func(ctx context.Context) { retentionLoop(ctx, st, log) })
	active.Add(func(ctx context.Context) { certWatch(ctx, res, log) })
	if startActive {
		active.Start()
	}

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

	plane := newDataPlane(ctx, px, streams, streamCfgs, cfg.ListenWAN, cfg.ListenHTTP, tailProxyAddr, log)
	defer plane.Close()
	if !node.Active() {
		// Hold the service address without accepting. A paired standby stays
		// here even when HA is off, so turning it off cannot put two nodes on
		// the address. IP_FREEBIND lets this
		// succeed before the address has moved to this node, so a promotion
		// does not wait for a bind.
		if err := plane.Prebind(ctx); err != nil {
			log.Warn("standby could not pre-bind the service address; promotion will bind instead", "err", err)
		} else {
			log.Info("standby holds the service address without serving", "addrs", plane.Addrs())
		}
	} else if err := plane.Serve(ctx); err != nil {
		return fmt.Errorf("proxy listener: %w", err)
	}
	// The HA-only listeners and the floating service address are settled at
	// boot. A first live enable asks the supervisor for the restart that binds
	// them; the loops themselves still start and stop live.
	haOnAtBoot := haOn
	rt := &haRuntime{
		root: ctx, dir: cfg.DataDir, st: st, all: all, res: res, bans: bans, api: apiServer,
		plane: plane, active: active, repl: newReplicator(ctx, cfg.DataDir, st, log),
		ident: haIdent, quiesce: haQuiesce, witness: witness, fence: cfg.HAFenceCommand,
		witnessURL: cfg.HAWitness, witnessToken: cfg.HAWitnessToken,
		flap:         ha.NewFlapGuard(flapBudget(st, cfg.HAMaxFailovers)),
		autoFailover: cfg.HAAutoFailover, log: log,
	}
	haRT.Store(rt)
	if haOn {
		if err := rt.Start(); err != nil {
			log.Error("high availability did not start", "err", err)
		}
	}
	// The write gate stays installed: quiesce is only set during a move.
	apiServer.SetWriteGate(haQuiesce.Active)
	apiServer.SetHAOps(haControl{dir: cfg.DataDir, st: st, fallback: cfg.HAMaxFailovers, rt: rt})
	// The settings route flips the loops live; the data plane is untouched.
	// Turning HA off on a paired standby is refused: it is out of service by
	// design, and starting it here would give the pair two writers.
	apiServer.SetHAChange(func(on bool, confirm string) (bool, error) {
		if err := haApplyChange(rt, cfg.DataDir, on, confirm); err != nil {
			return false, err
		}
		// The listeners HA adds are bound at boot, so the first enable needs a
		// restart; a later enable in the same process reuses them.
		restart := on && !haOnAtBoot
		if restart {
			go func() {
				time.Sleep(500 * time.Millisecond)
				select {
				case restartCh <- struct{}{}:
				default:
				}
			}()
		}
		return restart, nil
	})

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Info("shutting down", "signal", s.String())
	case <-restartCh:
		// The service supervisor (Docker's restart policy or systemd Restart=)
		// starts the process again with the listeners rebuilt.
		log.Info("restart requested; exiting for the service supervisor")
	}
	cancel()
	shutdownCtx, done := context.WithTimeout(context.Background(), 8*time.Second)
	defer done()
	for _, gl := range guiListeners {
		_ = gl.srv.Shutdown(shutdownCtx)
	}
	return nil
}

// splitCSV turns a stored comma-separated field into its non-empty entries.
func splitCSV(csv string) []string {
	out := []string{}
	for _, part := range strings.Split(csv, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
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
		// Retention is per site: one site keeping a year of history must not
		// delete another site's week.
		sites, err := st.ListSites()
		if err != nil {
			return
		}
		for _, site := range sites {
			siteSt := st.InSite(site.ID)
			kv, err := siteSt.Settings()
			if err != nil {
				continue
			}
			days := 7
			if v, err := strconv.Atoi(kv["retention_days"]); err == nil && v >= 1 && v <= 30 {
				days = v
			}
			cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
			if n, err := siteSt.DeleteEventsBefore(cutoff); err == nil && n > 0 {
				log.Info("retention applied", "site", site.Slug, "deleted_events", n, "days", days)
			}
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

// geoAutoUpdate refreshes an installed GeoIP database once a day. The manual
// Update database button stays available; the setting only controls the timer.
func geoAutoUpdate(ctx context.Context, st *store.Store, geo *geoip.Geo, log *slog.Logger) {
	timer := time.NewTimer(30 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			kv, err := st.Settings()
			if err == nil && kv["geoip_auto_update"] != "0" && geo.Available() {
				if geo.StartInstall() {
					log.Info("daily GeoIP update started")
				}
			}
			timer.Reset(24 * time.Hour)
		}
	}
}

func certWatch(ctx context.Context, res *siteres.Set, log *slog.Logger) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Each site warns through its own channels about its own
			// certificates, so one tenant's expiry never lands in another's
			// inbox.
			res.Each(func(b *siteres.Bundle) {
				list, err := b.Store.ListCerts()
				if err != nil {
					return
				}
				for _, c := range list {
					if c.ExpiresAt == nil {
						continue
					}
					days := int(time.Until(*c.ExpiresAt).Hours() / 24)
					if days <= 7 {
						b.Notify.Enqueue("cert", fmt.Sprintf("Certificate for %s expires in %d days", c.Domains, days),
							"cert:"+c.Domains, true)
					}
				}
			})
		}
	}
}
