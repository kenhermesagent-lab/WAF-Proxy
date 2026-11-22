// Package notify delivers alerts to Telegram, email and webhooks.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"sync"
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

// EventKinds is the set of per-event toggles the API exposes. An empty
// notify_events setting means every kind is delivered; the sentinel "none"
// suppresses every event class while keeping channels configured.
// Routing classes raised by ban handling.
const (
	KindBan          = "ban"
	KindPermanentBan = "permanent_ban"
	KindCrowdSecBan  = "crowdsec"
)

var EventKinds = []EventKind{
	{Kind: "ban", Label: "Temporary ban"},
	{Kind: "permanent_ban", Label: "Permanent ban"},
	{Kind: "gate", Label: "Access gate lockout"},
	{Kind: "cert", Label: "Certificate expiry"},
	{Kind: "uptime", Label: "Backend up/down"},
	{Kind: "update", Label: "Application update"},
	{Kind: "crowdsec", Label: "CrowdSec ban"},
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

	mu     sync.Mutex
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
	return map[string]bool{
		"telegram": kv["notify_telegram_enabled"] == "1" && kv["notify_telegram_token"] != "" && kv["notify_telegram_chat"] != "",
		"email":    kv["notify_email_enabled"] == "1" && kv["smtp_host"] != "" && kv["smtp_from"] != "",
		"webhook":  kv["notify_webhook_enabled"] == "1" && kv["notify_webhook_url"] != "",
	}
}

// Enqueue records an alert for every enabled channel. Immediate alerts are
// delivered on the next worker kick; everything else waits for the 5 minute
// digest so a ban wave becomes one message instead of hundreds.
func (m *Manager) Enqueue(kind, text, dedupe string, immediate bool) {
	if !m.EventEnabled(kind) {
		return
	}
	channels := m.Channels()
	if dedupe != "" {
		if seen, err := m.st.AlertRecentlySent(dedupe, m.now().Add(-24*time.Hour)); err == nil && seen {
			return
		}
	}
	state := "pending"
	if immediate {
		state = "immediate"
	}
	for name, enabled := range channels {
		if !enabled {
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

// alertClass returns the routing class of a stored alert. Rows queued before
// CrowdSec bans had their own class were stored as a plain ban and carry the
// original source only in the message, so the message is inspected as well.
func alertClass(a model.Alert) string {
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

// EventEnabled reports whether a class may be delivered under the current
// routing settings: an empty value means every class, "none" means none.
func (m *Manager) EventEnabled(kind string) bool {
	kv, err := m.st.Settings()
	if err != nil {
		return true
	}
	raw := strings.TrimSpace(kv["notify_events"])
	if raw == "none" {
		return false
	}
	if raw == "" {
		return true
	}
	for _, part := range strings.Split(raw, ",") {
		if strings.EqualFold(strings.TrimSpace(part), kind) {
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
	byChannel := map[string][]model.Alert{}
	for _, a := range alerts {
		if immediateOnly && a.State != "immediate" {
			continue
		}
		// Routing is checked again here, not only when the alert was queued: a
		// class muted while its alerts are still pending must stop them, and a
		// backlog queued by an older build must not outlive the mute.
		if !m.EventEnabled(alertClass(a)) {
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
	host := kv["smtp_host"]
	port := kv["smtp_port"]
	if port == "" {
		port = "587"
	}
	from := kv["smtp_from"]
	to := kv["smtp_to"]
	if to == "" {
		to = from
	}
	pass := m.secret(kv, "smtp_password")
	user := kv["smtp_user"]
	if host == "" || from == "" {
		return fmt.Errorf("email is not configured")
	}
	auth := smtp.PlainAuth("", user, pass, host)
	msg := strings.Join([]string{
		"From: " + from,
		"To: " + to,
		"Subject: [wafproxy] " + kind + " alert",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		text,
	}, "\r\n")
	addr := host + ":" + port
	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("invalid smtp port")
	}
	return smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
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
		"smtp_from":        kv["smtp_from"],
		"smtp_to":          kv["smtp_to"],
		"webhook_enabled":  kv["notify_webhook_enabled"],
		"webhook_url":      mask(kv["notify_webhook_url"]),
		"events":           kv["notify_events"],
	}
	return out, nil
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
		"smtp_from":               strings.TrimSpace(in["smtp_from"]),
		"smtp_to":                 strings.TrimSpace(in["smtp_to"]),
		"notify_webhook_enabled":  boolString(in["webhook_enabled"]),
		"notify_events":           strings.TrimSpace(in["events"]),
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

func boolString(v string) string {
	if v == "1" || v == "true" || v == "on" {
		return "1"
	}
	return "0"
}
