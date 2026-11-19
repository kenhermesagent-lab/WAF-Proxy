package acme

import (
	"fmt"
	"strconv"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/providers/dns/duckdns"
	"github.com/go-acme/lego/v4/providers/dns/godaddy"
	"github.com/go-acme/lego/v4/providers/dns/hetzner"
	"github.com/go-acme/lego/v4/providers/dns/ovh"
	"github.com/go-acme/lego/v4/providers/dns/rfc2136"
	"github.com/go-acme/lego/v4/providers/dns/route53"
)

// Providers lists the DNS providers available in the UI.
var Providers = []string{
	"duckdns", "cloudflare", "route53", "digitalocean", "hetzner", "ovh", "godaddy", "rfc2136",
}

// buildProvider converts a credential map into a lego challenge provider.
func buildProvider(name string, c map[string]string) (challenge.Provider, error) {
	switch name {
	case "duckdns":
		cfg := duckdns.NewDefaultConfig()
		cfg.Token = c["token"]
		return duckdns.NewDNSProviderConfig(cfg)
	case "cloudflare":
		cfg := cloudflare.NewDefaultConfig()
		cfg.AuthToken = c["api_token"]
		cfg.AuthEmail = c["email"]
		cfg.AuthKey = c["api_key"]
		cfg.ZoneToken = c["zone_token"]
		return cloudflare.NewDNSProviderConfig(cfg)
	case "route53":
		cfg := route53.NewDefaultConfig()
		cfg.AccessKeyID = c["access_key_id"]
		cfg.SecretAccessKey = c["secret_access_key"]
		cfg.SessionToken = c["session_token"]
		cfg.Region = c["region"]
		cfg.HostedZoneID = c["hosted_zone_id"]
		return route53.NewDNSProviderConfig(cfg)
	case "digitalocean":
		cfg := digitalocean.NewDefaultConfig()
		cfg.AuthToken = c["token"]
		return digitalocean.NewDNSProviderConfig(cfg)
	case "hetzner":
		cfg := hetzner.NewDefaultConfig()
		cfg.APIToken = c["api_token"]
		return hetzner.NewDNSProviderConfig(cfg)
	case "ovh":
		cfg := ovh.NewDefaultConfig()
		cfg.APIEndpoint = c["endpoint"]
		cfg.ApplicationKey = c["application_key"]
		cfg.ApplicationSecret = c["application_secret"]
		cfg.ConsumerKey = c["consumer_key"]
		return ovh.NewDNSProviderConfig(cfg)
	case "godaddy":
		cfg := godaddy.NewDefaultConfig()
		cfg.APIKey = c["api_key"]
		cfg.APISecret = c["api_secret"]
		return godaddy.NewDNSProviderConfig(cfg)
	case "rfc2136":
		cfg := rfc2136.NewDefaultConfig()
		cfg.Nameserver = c["nameserver"]
		cfg.TSIGKey = c["tsig_key"]
		cfg.TSIGSecret = c["tsig_secret"]
		if alg := c["tsig_algorithm"]; alg != "" {
			cfg.TSIGAlgorithm = alg
		}
		if zones := c["zones"]; zones != "" {
			cfg.Zones = splitCSV(zones)
		}
		if v := c["timeout_seconds"]; v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				cfg.DNSTimeout = time.Duration(n) * time.Second
			}
		}
		return rfc2136.NewDNSProviderConfig(cfg)
	default:
		return nil, fmt.Errorf("unsupported DNS provider %q", name)
	}
}

func splitCSV(s string) []string {
	out := []string{}
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
