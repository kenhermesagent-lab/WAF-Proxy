// Package notify delivers alerts to Telegram, email and webhooks.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/smtp"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/urlguard"
)

// EventKind describes one routable notification category.
type EventKind struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
}

// EventKinds is the set of routable events the API exposes. No saved routing
// means every kind reaches every channel; the older notify_events sentinel
// "none" still suppresses every event class while keeping channels configured.
// Routing classes raised by ban handling.
const (
	KindBan          = "ban"
	KindPermanentBan = "permanent_ban"
	KindCrowdSecBan  = "crowdsec"
)

// Security scan finding classes. A known-exploited finding gets its own class
// so it can be kept immediate while ordinary findings are muted or digested.
const (
	KindSecurityNew      = "security_new"
	KindSecurityKEV      = "security_kev"
	KindSecurityResolved = "security_resolved"
)

// RouteChannels are the delivery channels an event can be routed to.
var RouteChannels = []string{"telegram", "email", "webhook"}

var EventKinds = []EventKind{
	{Kind: "ban", Label: "Temporary ban"},
	{Kind: "permanent_ban", Label: "Permanent ban"},
	{Kind: "gate", Label: "Access gate lockout"},
	{Kind: "cert", Label: "Certificate expiry"},
	{Kind: "uptime", Label: "Backend up/down"},
	{Kind: "update", Label: "Application update"},
	{Kind: "crowdsec", Label: "CrowdSec ban"},
	{Kind: KindSecurityNew, Label: "Security scan: new finding"},
	{Kind: KindSecurityKEV, Label: "Security scan: exploited vulnerability"},
	{Kind: KindSecurityResolved, Label: "Security scan: finding resolved"},
	{Kind: "egress_spike", Label: "Outbound traffic spike"},
	{Kind: "rate_spike", Label: "Request-rate spike"},
	{Kind: "auth_burst", Label: "Authentication failure burst"},
}

// Manager owns channel configuration and delivery.
type Manager struct {
	st   *store.Store
	box  *crypto.Box
	log  *slog.Logger
	kick chan struct{}

	client *http.Client
	now    func() time.Time
}

// New creates a notifier.
func New(st *store.Store, box *crypto.Box, log *slog.Logger) *Manager {
	return &Manager{
		st:     st,
		box:    box,
		log:    log,
		kick:   make(chan struct{}, 1),
		client: &http.Client{Timeout: 15 * time.Second},
		now:    time.Now,
	}
}

// Channels describes which channels are configured and enabled.
func (m *Manager) Channels() map[string]bool {
	kv, err := m.st.Settings()
	if err != nil {
		return map[string]bool{}
	}
	return channelsFrom(kv)
}

func channelsFrom(kv map[string]string) map[string]bool {
	return map[string]bool{
		"telegram": kv["notify_telegram_enabled"] == "1" && kv["notify_telegram_token"] != "" && kv["notify_telegram_chat"] != "",
		// The SMTP username is also the envelope sender. There is no separate
		// from/to field: alerts and reset links go to administrators' own
		// addresses, resolved when the message is sent.
		"email":   kv["notify_email_enabled"] == "1" && kv["smtp_host"] != "" && kv["smtp_user"] != "",
		"webhook": kv["notify_webhook_enabled"] == "1" && kv["notify_webhook_url"] != "",
	}
}

// Enqueue records an alert for every enabled channel routed this event.
// Immediate alerts are delivered on the next worker kick; everything else
// waits for the 5 minute digest so a ban wave becomes one message instead of
// hundreds.
func (m *Manager) Enqueue(kind, text, dedupe string, immediate bool) {
	kv, err := m.st.Settings()
	if err != nil {
		return
	}
	routes := routesFromSettings(kv)
	if dedupe != "" {
		if seen, err := m.st.AlertRecentlySent(dedupe, m.now().Add(-24*time.Hour)); err == nil && seen {
			return
		}
	}
	state := "pending"
	if immediate {
		state = "immediate"
	}
	for name, enabled := range channelsFrom(kv) {
		if !enabled || !routeAllows(routes, kind, name) {
			continue
		}
		if err := m.st.EnqueueAlertState(name, kind, dedupe, text, state); err != nil {
			m.log.Warn("enqueue alert", "channel", name, "err", err)
		}
	}
	if immediate {
		select {
		case m.kick <- struct{}{}:
		default:
		}
	}
}

// EnqueueSecurityFindings alerts on a run's findings. A known-exploited finding
// is immediate even at a low score, a critical or high finding is immediate, and
// the rest wait for the digest. The finding key is the dedupe key, so a finding
// that stays open is one alert rather than one per run.
func (m *Manager) EnqueueSecurityFindings(findings []model.ScanFinding) {
	for _, f := range findings {
		kind, immediate := KindSecurityNew, false
		switch {
		case f.Exploitation == "kev":
			kind, immediate = KindSecurityKEV, true
		case f.Severity == "critical" || f.Severity == "high":
			immediate = true
		}
		m.Enqueue(kind, securityFindingText(f), "finding:"+f.Key, immediate)
	}
}

// EnqueueSecurityResolved reports findings that are gone, once per key.
func (m *Manager) EnqueueSecurityResolved(findings []model.ScanFinding) {
	for _, f := range findings {
		m.Enqueue(KindSecurityResolved, "Resolved: "+f.Title, "resolved:"+f.Key, false)
	}
}

func securityFindingText(f model.ScanFinding) string {
	severity := strings.ToUpper(f.Severity)
	if f.Exploitation == "kev" {
		severity += " · CISA KEV"
	}
	text := severity + ": " + f.Title
	if f.Recommendation != "" {
		text += " — " + f.Recommendation
	}
	return text
}

// BanClass is the routing class for a ban, from its source. CrowdSec decisions
// get their own class so a noisy blocklist can be muted without hiding the bans
// this console decided on itself.
func BanClass(source string, permanent bool) string {
	if isCrowdSec(source) {
		return KindCrowdSecBan
	}
	if permanent {
		return KindPermanentBan
	}
	return KindBan
}

func isCrowdSec(source string) bool {
	s := strings.ToLower(strings.TrimSpace(source))
	return s == "crowdsec" || strings.HasPrefix(s, "crowdsec:") || strings.HasPrefix(s, "crowdsec/")
}

// RouteClass returns the routing class of a stored alert. Rows queued before
// CrowdSec bans had their own class were stored as a plain ban and carry the
// original source only in the message, so the message is inspected as well.
func RouteClass(a model.Alert) string {
	if source, ok := banSourceInPayload(a.Payload); ok {
		return BanClass(source, a.Kind == KindPermanentBan)
	}
	return a.Kind
}

func banSourceInPayload(payload string) (string, bool) {
	if !strings.HasPrefix(payload, "Temporary ban:") && !strings.HasPrefix(payload, "Permanent ban:") {
		return "", false
	}
	const marker = "(source: "
	i := strings.LastIndex(payload, marker)
	if i < 0 || !strings.HasSuffix(payload, ")") {
		return "", false
	}
	return strings.TrimSpace(payload[i+len(marker) : len(payload)-1]), true
}

// EventEnabled reports whether a class reaches any channel at all, which is
// what the queue re-check and the recent-delivery badge need.
func (m *Manager) EventEnabled(kind string) bool {
	kv, err := m.st.Settings()
	if err != nil {
		return true
	}
	return eventRouted(routesFromSettings(kv), kind)
}

// routesFromSettings returns nil when every event reaches every channel (the
// default), otherwise the channel set per event. An empty notify_routes falls
// back to the older global notify_events list, so a pending upgrade keeps the
// mutes an operator already set.
func routesFromSettings(kv map[string]string) map[string]map[string]bool {
	if raw := strings.TrimSpace(kv["notify_routes"]); raw != "" {
		var stored map[string][]string
		if err := json.Unmarshal([]byte(raw), &stored); err != nil {
			return nil
		}
		out := map[string]map[string]bool{}
		for kind, channels := range stored {
			out[kind] = map[string]bool{}
			for _, channel := range channels {
				out[kind][channel] = true
			}
		}
		return out
	}
	switch events := strings.TrimSpace(kv["notify_events"]); events {
	case "":
		return nil
	case "none":
		return map[string]map[string]bool{}
	default:
		out := map[string]map[string]bool{}
		for _, part := range strings.Split(events, ",") {
			kind := strings.ToLower(strings.TrimSpace(part))
			if kind == "" {
				continue
			}
			out[kind] = map[string]bool{}
			for _, channel := range RouteChannels {
				out[kind][channel] = true
			}
		}
		return out
	}
}

func routeAllows(routes map[string]map[string]bool, kind, channel string) bool {
	if routes == nil {
		return validRouteChannel(channel)
	}
	return routes[kind][channel]
}

func eventRouted(routes map[string]map[string]bool, kind string) bool {
	if routes == nil {
		return true
	}
	for _, channel := range RouteChannels {
		if routes[kind][channel] {
			return true
		}
	}
	return false
}

// Start runs the digest worker.
func (m *Manager) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.process(false)
			case <-m.kick:
				m.process(true)
			}
		}
	}()
}

func (m *Manager) process(immediateOnly bool) {
	alerts, err := m.st.PendingAlerts(200)
	if err != nil {
		m.log.Error("pending alerts", "err", err)
		return
	}
	if len(alerts) == 0 {
		return
	}
	kv, _ := m.st.Settings()
	routes := routesFromSettings(kv)
	byChannel := map[string][]model.Alert{}
	for _, a := range alerts {
		if immediateOnly && a.State != "immediate" {
			continue
		}
		// Routing is checked again here, not only when the alert was queued: a
		// route muted while its alerts are still pending must stop them, and a
		// backlog queued by an older build must not outlive the mute.
		if !routeAllows(routes, RouteClass(a), a.Channel) {
			_ = m.st.MarkAlert(a.ID, "suppressed", a.Attempts)
			continue
		}
		byChannel[a.Channel] = append(byChannel[a.Channel], a)
	}
	for channel, list := range byChannel {
		body := digestText(list)
		if err := m.deliver(channel, body, list[0].Kind); err != nil {
			m.log.Warn("alert delivery failed", "channel", channel, "err", err)
			for _, a := range list {
				// Retry on the next digest tick up to five times, then give up so
				// a broken channel does not retry forever.
				state := "pending"
				if a.Attempts+1 >= 5 {
					state = "failed"
				}
				_ = m.st.MarkAlert(a.ID, state, a.Attempts+1)
			}
			continue
		}
		for _, a := range list {
			_ = m.st.MarkAlert(a.ID, "sent", a.Attempts+1)
		}
	}
}

func digestText(alerts []model.Alert) string {
	if len(alerts) == 1 {
		return alerts[0].Payload
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d security events\n", len(alerts))
	for i, a := range alerts {
		if i >= 20 {
			fmt.Fprintf(&b, "…and %d more\n", len(alerts)-20)
			break
		}
		fmt.Fprintf(&b, "• %s\n", truncate(a.Payload, 160))
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (m *Manager) deliver(channel, text, kind string) error {
	kv, err := m.st.Settings()
	if err != nil {
		return err
	}
	switch channel {
	case "telegram":
		return m.sendTelegram(kv, text)
	case "email":
		return m.sendEmail(kv, kind, text)
	case "webhook":
		return m.sendWebhook(kv, text)
	}
	return fmt.Errorf("unknown channel %q", channel)
}

func (m *Manager) secret(kv map[string]string, key string) string {
	enc := kv[key]
	if enc == "" {
		return ""
	}
	plain, err := m.box.Open(enc)
	if err != nil {
		return ""
	}
	return plain
}

type telegramMessage struct {
	ChatID                string `json:"chat_id"`
	Text                  string `json:"text"`
	ParseMode             string `json:"parse_mode"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview"`
}

func (m *Manager) sendTelegram(kv map[string]string, text string) error {
	token := strings.TrimSpace(m.secret(kv, "notify_telegram_token"))
	chat := normalizeTelegramChat(kv["notify_telegram_chat"])
	if token == "" || chat == "" {
		return fmt.Errorf("telegram is not configured")
	}
	payload := telegramMessage{
		ChatID:                chat,
		Text:                  "<b>WAF-Proxy</b>\n" + escapeTelegramHTML(text),
		ParseMode:             "HTML",
		DisableWebPagePreview: true,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.telegram.org/bot"+token+"/sendMessage", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		var apiErr struct {
			Description string `json:"description"`
		}
		if json.Unmarshal(body, &apiErr) == nil && apiErr.Description != "" {
			return fmt.Errorf("telegram: %s", apiErr.Description)
		}
		if msg := strings.TrimSpace(string(body)); msg != "" {
			return fmt.Errorf("telegram returned %d: %s", resp.StatusCode, msg)
		}
		return fmt.Errorf("telegram returned %d", resp.StatusCode)
	}
	return nil
}

// Telegram's HTML mode only requires &, < and > to be escaped.
func escapeTelegramHTML(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// Public channels accept @username while private channels need the numeric
// -100… ID. Accept the URL forms users copy from Telegram as well.
func normalizeTelegramChat(raw string) string {
	chat := strings.TrimSpace(raw)
	chat = strings.TrimPrefix(chat, "https://")
	chat = strings.TrimPrefix(chat, "http://")
	chat = strings.TrimPrefix(chat, "t.me/")
	chat = strings.TrimPrefix(chat, "telegram.me/")
	chat = strings.Trim(chat, "/")
	if chat == "" || strings.HasPrefix(chat, "@") || strings.HasPrefix(chat, "-") {
		return chat
	}
	if _, err := strconv.ParseInt(chat, 10, 64); err == nil {
		return chat
	}
	return "@" + chat
}

func (m *Manager) sendEmail(kv map[string]string, kind, text string) error {
	to, err := m.st.ListUserEmails()
	if err != nil {
		return err
	}
	return m.sendEmailMessage(kv, to, "WAF-Proxy alert: "+kind, text, nil)
}

// EmailConfigured reports whether the email channel can deliver mail at all.
func (m *Manager) EmailConfigured() bool {
	return m.Channels()["email"]
}

// SendMail delivers a plain-text message to every administrator of this site
// that has an address. It is used for console mail like password resets, which
// is why the subject is not tied to an event kind.
func (m *Manager) SendMail(subject, text string) error {
	to, err := m.st.ListUserEmails()
	if err != nil {
		return err
	}
	return m.SendMailTo(to, subject, text)
}

// SendMailTo delivers a message to the given addresses. A password reset uses
// it to reach only the account that asked for it.
func (m *Manager) SendMailTo(to []string, subject, text string) error {
	return m.SendMailLink(to, subject, text, "", "")
}

// SendMailLink adds a button and the same URL as text, for reset and invite
// mail where the recipient needs one obvious next step.
func (m *Manager) SendMailLink(to []string, subject, text, label, link string) error {
	kv, err := m.st.Settings()
	if err != nil {
		return err
	}
	var action *mailAction
	if label != "" && link != "" {
		action = &mailAction{Label: label, URL: link}
	}
	return m.sendEmailMessage(kv, to, subject, text, action)
}

type mailAction struct {
	Label string
	URL   string
}

func (m *Manager) sendEmailMessage(kv map[string]string, to []string, subject, text string, action *mailAction) error {
	host := kv["smtp_host"]
	port := kv["smtp_port"]
	if port == "" {
		port = "587"
	}
	// Gmail and most SMTP servers accept the login name as the sender, which
	// is why the console no longer asks for a separate From address.
	from := strings.TrimSpace(kv["smtp_user"])
	pass := m.secret(kv, "smtp_password")
	user := kv["smtp_user"]
	if host == "" || from == "" || len(to) == 0 {
		return fmt.Errorf("email is not configured")
	}
	// A newline in an address would add a header of the sender's choosing.
	for _, addr := range append([]string{from}, to...) {
		if strings.ContainsAny(addr, "\r\n") {
			return fmt.Errorf("email address contains a line break")
		}
	}
	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("invalid smtp port")
	}
	msg, err := buildEmail(from, to, subject, text, action)
	if err != nil {
		return err
	}
	var auth smtp.Auth
	if user != "" || pass != "" {
		auth = smtp.PlainAuth("", user, pass, host)
	}
	return smtp.SendMail(host+":"+port, auth, from, to, msg)
}

// buildEmail is a multipart/alternative message: the plain text an operator
// can read anywhere, and the same content in the console's own styling. The
// logo is drawn with a table cell and a monogram, so no client has to load a
// remote image the internal console may not serve.
func buildEmail(from string, to []string, subject, text string, action *mailAction) ([]byte, error) {
	var content bytes.Buffer
	mw := multipart.NewWriter(&content)
	plain, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type": {"text/plain; charset=utf-8"}, "Content-Transfer-Encoding": {"quoted-printable"},
	})
	if err != nil {
		return nil, err
	}
	if err := writeQuotedPrintable(plain, plainEmail(text, action)); err != nil {
		return nil, err
	}
	htmlPart, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type": {"text/html; charset=utf-8"}, "Content-Transfer-Encoding": {"quoted-printable"},
	})
	if err != nil {
		return nil, err
	}
	if err := writeQuotedPrintable(htmlPart, htmlEmail(subject, text, action)); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	headers := []string{
		"From: WAF-Proxy <" + from + ">",
		"To: " + strings.Join(to, ", "),
		"Subject: " + subject,
		"Date: " + time.Now().Format(time.RFC1123Z),
		"MIME-Version: 1.0",
		"Content-Type: multipart/alternative; boundary=" + mw.Boundary(),
	}
	return []byte(strings.Join(headers, "\r\n") + "\r\n\r\n" + content.String()), nil
}

// writeQuotedPrintable keeps every line under the SMTP limit; the HTML is
// otherwise one long line that strict servers reject.
func writeQuotedPrintable(w io.Writer, body string) error {
	qp := quotedprintable.NewWriter(w)
	if _, err := io.WriteString(qp, body); err != nil {
		return err
	}
	return qp.Close()
}

func plainEmail(text string, action *mailAction) string {
	if action == nil || strings.Contains(text, action.URL) {
		return text
	}
	return strings.TrimSpace(text) + "\n\n" + action.Label + ": " + action.URL + "\n"
}

func htmlEmail(subject, text string, action *mailAction) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><body style="margin:0;padding:24px 12px;background:#f1f5f9">`)
	b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td align="center">`)
	b.WriteString(`<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;width:100%">`)
	b.WriteString(`<tr><td style="padding:22px 28px;background:#0b1220;border-radius:12px 12px 0 0">`)
	b.WriteString(`<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>`)
	b.WriteString(`<td width="36" height="36" align="center" style="background:#2563eb;border-radius:8px;color:#ffffff;font:700 19px Arial,sans-serif">W</td>`)
	b.WriteString(`<td style="padding-left:12px;color:#e5edff;font:700 18px Arial,sans-serif">WAF-Proxy</td>`)
	b.WriteString(`</tr></table></td></tr>`)
	b.WriteString(`<tr><td style="padding:28px;background:#ffffff;border:1px solid #e2e8f0;border-top:0;border-radius:0 0 12px 12px;font:15px/1.6 Arial,sans-serif;color:#1e293b">`)
	b.WriteString(`<h1 style="margin:0 0 16px;font:600 20px Arial,sans-serif;color:#0f172a">` + html.EscapeString(subject) + `</h1>`)
	for _, para := range strings.Split(strings.TrimSpace(text), "\n\n") {
		if para = strings.TrimSpace(para); para == "" {
			continue
		}
		b.WriteString(`<p style="margin:0 0 14px">` + strings.ReplaceAll(html.EscapeString(para), "\n", "<br>") + `</p>`)
	}
	if action != nil {
		link := html.EscapeString(action.URL)
		b.WriteString(`<p style="margin:22px 0"><a href="` + link + `" style="display:inline-block;padding:11px 22px;background:#2563eb;border-radius:8px;color:#ffffff;text-decoration:none;font-weight:600">` + html.EscapeString(action.Label) + `</a></p>`)
		b.WriteString(`<p style="margin:0;font-size:12px;color:#64748b;word-break:break-all">If the button does not work, open this link:<br>` + link + `</p>`)
	}
	b.WriteString(`<p style="margin:24px 0 0;padding-top:16px;border-top:1px solid #e2e8f0;font-size:12px;color:#64748b">Sent by your self-hosted WAF-Proxy console. If you were not expecting this message, you can safely ignore it.</p>`)
	b.WriteString(`</td></tr></table></td></tr></table></body></html>`)
	return b.String()
}

func (m *Manager) sendWebhook(kv map[string]string, text string) error {
	u := m.secret(kv, "notify_webhook_url")
	if u == "" {
		return fmt.Errorf("webhook is not configured")
	}
	raw, _ := json.Marshal(map[string]string{"text": text})
	resp, err := m.client.Post(u, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

// Test delivers a one-off message to a channel.
func (m *Manager) Test(channel string) error {
	text := "Test notification from WAF-Proxy. If you can read this, the channel works."
	return m.deliver(channel, text, "test")
}

// Settings returns channel configuration with secrets masked.
func (m *Manager) Settings() (map[string]string, error) {
	kv, err := m.st.Settings()
	if err != nil {
		return nil, err
	}
	out := map[string]string{
		"telegram_enabled": kv["notify_telegram_enabled"],
		"telegram_chat":    kv["notify_telegram_chat"],
		"telegram_token":   mask(kv["notify_telegram_token"]),
		"email_enabled":    kv["notify_email_enabled"],
		"smtp_host":        kv["smtp_host"],
		"smtp_port":        kv["smtp_port"],
		"smtp_user":        kv["smtp_user"],
		"smtp_password":    mask(kv["smtp_password"]),
		"webhook_enabled":  kv["notify_webhook_enabled"],
		"webhook_url":      mask(kv["notify_webhook_url"]),
		"events":           kv["notify_events"],
		"routes":           routesJSON(routesFromSettings(kv)),
	}
	return out, nil
}

// routesJSON returns the full matrix, with the default all-channels state
// spelled out so the console does not have to infer it.
func routesJSON(routes map[string]map[string]bool) string {
	if routes == nil {
		routes = map[string]map[string]bool{}
		for _, event := range EventKinds {
			routes[event.Kind] = map[string]bool{}
			for _, channel := range RouteChannels {
				routes[event.Kind][channel] = true
			}
		}
	}
	out := map[string][]string{}
	for kind, channels := range routes {
		out[kind] = []string{}
		for channel := range channels {
			out[kind] = append(out[kind], channel)
		}
		sort.Strings(out[kind])
	}
	raw, _ := json.Marshal(out)
	return string(raw)
}

func mask(v string) string {
	if v == "" {
		return ""
	}
	return "********"
}

// Update stores channel configuration. Secret fields are only replaced when a
// non-empty, non-masked value is supplied.
func (m *Manager) Update(in map[string]string) error {
	kv := map[string]string{
		"notify_telegram_enabled": boolString(in["telegram_enabled"]),
		"notify_telegram_chat":    normalizeTelegramChat(in["telegram_chat"]),
		"notify_email_enabled":    boolString(in["email_enabled"]),
		"smtp_host":               strings.TrimSpace(in["smtp_host"]),
		"smtp_port":               strings.TrimSpace(in["smtp_port"]),
		"smtp_user":               strings.TrimSpace(in["smtp_user"]),
		"notify_webhook_enabled":  boolString(in["webhook_enabled"]),
	}
	if raw := strings.TrimSpace(in["routes"]); raw != "" {
		routes, err := cleanRoutes(raw)
		if err != nil {
			return err
		}
		kv["notify_routes"] = routes
		// The per-channel matrix supersedes the older global list.
		kv["notify_events"] = ""
	} else {
		kv["notify_events"] = strings.TrimSpace(in["events"])
		// A legacy client saving the global list must not leave an older
		// per-channel matrix in place to override it.
		kv["notify_routes"] = ""
	}
	if raw := strings.TrimSpace(in["webhook_url"]); raw != "" && raw != "********" {
		if err := urlguard.Check(raw, urlguard.Webhook); err != nil {
			return fmt.Errorf("webhook url: %w", err)
		}
	}
	for field, key := range map[string]string{
		"telegram_token": "notify_telegram_token",
		"smtp_password":  "smtp_password",
		"webhook_url":    "notify_webhook_url",
	} {
		v := in[field]
		if field == "telegram_token" || field == "webhook_url" {
			v = strings.TrimSpace(v)
		}
		if v == "" || v == "********" {
			continue
		}
		enc, err := m.box.Seal(v)
		if err != nil {
			return err
		}
		kv[key] = enc
	}
	return m.st.SetSettings(kv)
}

// cleanRoutes validates the console's matrix and stores a canonical JSON
// object. Unknown event kinds are dropped so an old browser tab cannot persist
// a route nothing will ever read.
func cleanRoutes(raw string) (string, error) {
	var in map[string][]string
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return "", fmt.Errorf("notification routes: %w", err)
	}
	known := map[string]bool{}
	for _, event := range EventKinds {
		known[event.Kind] = true
	}
	out := map[string][]string{}
	for kind, channels := range in {
		if !known[kind] {
			continue
		}
		seen := map[string]bool{}
		out[kind] = []string{}
		for _, channel := range channels {
			channel = strings.ToLower(strings.TrimSpace(channel))
			if !seen[channel] && validRouteChannel(channel) {
				seen[channel] = true
				out[kind] = append(out[kind], channel)
			}
		}
		sort.Strings(out[kind])
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func validRouteChannel(channel string) bool {
	for _, c := range RouteChannels {
		if c == channel {
			return true
		}
	}
	return false
}

func boolString(v string) string {
	if v == "1" || v == "true" || v == "on" {
		return "1"
	}
	return "0"
}
