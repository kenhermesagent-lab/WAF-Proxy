package api

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// permanentFeedName is the single local threat list that permanent bans are
// folded into, so rolling them up twice reuses the same feed.
const permanentFeedName = "Permanent bans (rolled up)"

// rollupBans moves every permanent ban into one local threat-intel file and
// removes the ban rows, so the permanent list does not grow without end. The
// file is loaded as a local feed, which keeps the addresses blocked.
func (s *Server) rollupBans(w http.ResponseWriter, r *http.Request) {
	bans, err := s.db(r).ListBans(false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	permanent := []model.Ban{}
	for _, b := range bans {
		if b.Permanent {
			permanent = append(permanent, b)
		}
	}
	if len(permanent) == 0 {
		writeError(w, http.StatusBadRequest, "there are no permanent bans to roll up")
		return
	}

	dir := filepath.Join(s.cfg.DataDir, "feeds")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot create the feed directory")
		return
	}
	path := filepath.Join(dir, "permanent-bans.txt")
	var body strings.Builder
	body.WriteString("# Permanent bans rolled up from the console on " + time.Now().UTC().Format(time.RFC3339) + "\n")
	for _, b := range permanent {
		body.WriteString(b.CIDR + "\n")
	}
	tmp, err := os.CreateTemp(dir, ".permanent-bans-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot write the threat list")
		return
	}
	tmpPath := tmp.Name()
	if _, err := tmp.WriteString(body.String()); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		writeError(w, http.StatusInternalServerError, "cannot write the threat list")
		return
	}
	tmp.Close()
	if err := os.Chmod(tmpPath, 0o640); err != nil {
		os.Remove(tmpPath)
		writeError(w, http.StatusInternalServerError, "cannot secure the threat list")
		return
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		writeError(w, http.StatusInternalServerError, "cannot save the threat list")
		return
	}

	if s.feeds == nil {
		writeError(w, http.StatusServiceUnavailable, "the threat-intel feed engine is not running, so the bans were kept")
		return
	}

	// Replace the previous rolled-up feed so its local path and entry count
	// always describe the file that was just written.
	feeds, err := s.db(r).ListFeeds()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	for _, f := range feeds {
		if f.Name == permanentFeedName {
			if _, err := s.db(r).DeleteFeed(f.ID); err != nil {
				writeError(w, http.StatusInternalServerError, "cannot replace the rolled-up feed")
				return
			}
		}
	}
	feedID, err := s.db(r).CreateFeed(&model.Feed{
		Name: permanentFeedName, Action: "block", IntervalS: 3600, Enabled: true,
		Local: true, AlwaysBlock: true, Filename: "permanent-bans.txt", LocalPath: path,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot create the rolled-up feed")
		return
	}

	// Load the list before anything is deleted. If the file cannot be parsed or
	// the engine does not report every entry, the bans stay in force and the
	// half-built feed is removed, so an address is never left unblocked.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	s.feeds.Refresh(ctx, feedID)
	loaded, loadErr := s.db(r).FeedByID(feedID)
	if loadErr != nil || loaded.State != "ok" || loaded.LastCount != len(permanent) {
		_, _ = s.db(r).DeleteFeed(feedID)
		reason := "the new threat list did not load, so the bans were kept"
		if loaded != nil && loaded.LastError != "" {
			reason = "the new threat list did not load (" + loaded.LastError + "), so the bans were kept"
		}
		writeError(w, http.StatusBadGateway, reason)
		return
	}

	removed := 0
	for _, b := range permanent {
		if err := s.bans.Remove(b.CIDR); err != nil {
			continue
		}
		removed++
	}

	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "ban.rollup", "permanent bans → "+path, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"rolled_up": removed, "feed_id": feedID, "path": path,
	})
}
