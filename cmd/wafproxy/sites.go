package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/config"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// sitesCLI manages the tenants a single process serves. A site is created
// with a stable slug and the console hostname its administrators sign in at.
func sitesCLI(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: wafproxy sites list|add|rename|remove")
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

	switch args[0] {
	case "list":
		sites, err := st.ListSites()
		if err != nil {
			return err
		}
		fmt.Printf("%-12s %-24s %-32s %s\n", "SLUG", "NAME", "CONSOLE HOST", "ENABLED")
		for _, site := range sites {
			host := site.ConsoleHost
			if host == "" {
				host = "-"
			}
			fmt.Printf("%-12s %-24s %-32s %t\n", site.Slug, site.Name, host, site.Enabled)
		}
		return nil

	case "add":
		fs := flag.NewFlagSet("sites add", flag.ContinueOnError)
		slug := fs.String("slug", "", "stable identifier, a-z 0-9 and -")
		name := fs.String("name", "", "display name (default: the slug)")
		console := fs.String("console-host", "", "hostname the site's console answers on")
		disabled := fs.Bool("disabled", false, "create the site without serving it")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if strings.TrimSpace(*slug) == "" {
			return errors.New("--slug is required")
		}
		site, err := st.CreateSite(*slug, *name, *console)
		if err != nil {
			return err
		}
		if *disabled {
			if site, err = st.UpdateSite(site.ID, site.Name, site.ConsoleHost, false); err != nil {
				return err
			}
		}
		if site.ConsoleHost == "" {
			fmt.Printf("created site %q; set --console-host before its console can be reached\n", site.Slug)
			return nil
		}
		fmt.Printf("created site %q, console at https://%s\n", site.Slug, site.ConsoleHost)
		return nil

	case "rename":
		fs := flag.NewFlagSet("sites rename", flag.ContinueOnError)
		slug := fs.String("slug", "", "site to change")
		name := fs.String("name", "", "new display name")
		console := fs.String("console-host", "", "new console hostname")
		enable := fs.Bool("enable", false, "serve the site")
		disable := fs.Bool("disable", false, "stop serving the site")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		site, err := st.SiteBySlug(*slug)
		if err != nil {
			return err
		}
		if *enable && *disable {
			return errors.New("--enable and --disable are exclusive")
		}
		host, enabled := site.ConsoleHost, site.Enabled
		if *name != "" {
			site.Name = *name
		}
		if *console != "" {
			host = *console
		}
		if *enable {
			enabled = true
		}
		if *disable {
			enabled = false
		}
		if _, err := st.UpdateSite(site.ID, site.Name, host, enabled); err != nil {
			return err
		}
		fmt.Printf("updated site %q\n", site.Slug)
		return nil

	case "remove":
		fs := flag.NewFlagSet("sites remove", flag.ContinueOnError)
		slug := fs.String("slug", "", "site to remove with every row it owns")
		yes := fs.Bool("yes", false, "skip the confirmation")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		site, err := st.SiteBySlug(*slug)
		if err != nil {
			return err
		}
		if !*yes {
			return fmt.Errorf("refusing to delete %q and all its proxies, admins and history without --yes", site.Slug)
		}
		if err := st.DeleteSite(site.ID); err != nil {
			return err
		}
		fmt.Printf("removed site %q\n", site.Slug)
		return nil

	default:
		return fmt.Errorf("unknown sites command %q (want list, add, rename or remove)", args[0])
	}
}
