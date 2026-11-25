package consoleauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

func ldapURL(cfg Config) string {
	port := cfg.Port
	scheme := "ldap"
	if cfg.UseTLS {
		scheme = "ldaps"
		if port == 0 {
			port = 636
		}
	} else if port == 0 {
		port = 389
	}
	return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(cfg.Host, strconv.Itoa(port)))
}

func ldapTLSConfig(cfg Config) *tls.Config {
	return &tls.Config{ServerName: cfg.Host, InsecureSkipVerify: cfg.SkipVerify} // #nosec G402 -- explicit per-provider opt-out for private CAs
}

func ldapDial(ctx context.Context, cfg Config) (*ldap.Conn, error) {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: timeout})}
	if cfg.UseTLS {
		opts = append(opts, ldap.DialWithTLSConfig(ldapTLSConfig(cfg)))
	}
	conn, err := ldap.DialURL(ldapURL(cfg), opts...)
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(timeout)
	if cfg.StartTLS && !cfg.UseTLS {
		if err := conn.StartTLS(ldapTLSConfig(cfg)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("LDAP StartTLS: %w", err)
		}
	}
	return conn, nil
}

func ldapBind(ctx context.Context, cfg Config, dn, password string) (*ldap.Conn, error) {
	conn, err := ldapDial(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := conn.Bind(dn, password); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func authenticateLDAP(ctx context.Context, cfg Config, username, password string) (Result, error) {
	if cfg.BaseDN == "" {
		return Result{}, errors.New("LDAP base DN is not configured")
	}
	if cfg.UserFilter == "" || !strings.Contains(cfg.UserFilter, "{username}") {
		return Result{}, errors.New("LDAP user filter must contain {username}")
	}
	if (cfg.BindDN == "") != (cfg.BindPassword == "") {
		return Result{}, errors.New("LDAP bind DN and password must both be set, or both be empty")
	}
	service, err := ldapBind(ctx, cfg, cfg.BindDN, cfg.BindPassword)
	if err != nil {
		return Result{}, fmt.Errorf("LDAP service bind: %w", err)
	}
	defer service.Close()

	filter := strings.ReplaceAll(cfg.UserFilter, "{username}", ldap.EscapeFilter(username))
	attrs := []string{"dn", "mail", "cn", "displayName", "sAMAccountName", "memberOf"}
	if cfg.EmailAttr != "" {
		attrs = append(attrs, cfg.EmailAttr)
	}
	search := ldap.NewSearchRequest(cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, int(cfg.TimeoutSeconds), false, filter, attrs, nil)
	entries, err := service.Search(search)
	if err != nil {
		return Result{}, fmt.Errorf("LDAP user search: %w", err)
	}
	if len(entries.Entries) == 0 {
		return Result{}, ErrInvalidCredentials
	}
	if len(entries.Entries) > 1 {
		return Result{}, fmt.Errorf("LDAP user search matched more than one account")
	}
	entry := entries.Entries[0]

	// A user bind proves the password. An anonymous or empty bind would make
	// an empty password a successful login, so it is refused above.
	userConn, err := ldapBind(ctx, cfg, entry.DN, password)
	if err != nil {
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) && ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials {
			return Result{}, ErrInvalidCredentials
		}
		return Result{}, err
	}
	userConn.Close()

	res := Result{Email: entry.GetAttributeValue("mail")}
	if cfg.EmailAttr != "" {
		if v := entry.GetAttributeValue(cfg.EmailAttr); v != "" {
			res.Email = v
		}
	}
	groups := map[string]bool{}
	for _, g := range entry.GetAttributeValues("memberOf") {
		addLDAPGroup(groups, g)
	}
	if strings.TrimSpace(cfg.GroupFilter) != "" {
		gf := strings.ReplaceAll(cfg.GroupFilter, "{dn}", ldap.EscapeFilter(entry.DN))
		gf = strings.ReplaceAll(gf, "{username}", ldap.EscapeFilter(username))
		gs := ldap.NewSearchRequest(cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			200, int(cfg.TimeoutSeconds), false, gf, []string{"dn", "cn"}, nil)
		if found, err := service.Search(gs); err == nil {
			for _, g := range found.Entries {
				addLDAPGroup(groups, g.DN)
				addLDAPGroup(groups, g.GetAttributeValue("cn"))
			}
		} else {
			res.Warning = "LDAP group search: " + err.Error()
		}
	}
	for g := range groups {
		res.Groups = append(res.Groups, g)
	}
	sort.Strings(res.Groups)
	return res, nil
}

func addLDAPGroup(set map[string]bool, dn string) {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return
	}
	set[dn] = true
	if parsed, err := ldap.ParseDN(dn); err == nil && len(parsed.RDNs) > 0 {
		for _, av := range parsed.RDNs[0].Attributes {
			if strings.EqualFold(av.Type, "cn") {
				set[av.Value] = true
			}
		}
	}
	// A URL-escaped DN is not valid filter input, but a plain CN may arrive
	// with a trailing space from an AD attribute. Normalise the simple cases.
	if u, err := url.QueryUnescape(dn); err == nil && u != dn {
		set[u] = true
	}
}
