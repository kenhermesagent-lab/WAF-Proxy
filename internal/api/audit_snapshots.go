package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/rbac"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// entityAreas maps an audited entity to the permission area that owns it, so a
// rollback needs the same write permission as the change it undoes.
var entityAreas = map[string]string{
	"proxy":              "proxies",
	"policy":             "policies",
	"profile":            "policies",
	"protection_profile": "policies",
	"access_profile":     "policies",
	"access_list":        "policies",
}

var errEntityGone = errors.New("the entity no longer exists")

// snapshotJSON marshals an entity for storage. A marshal failure yields nil,
// which the audit layer treats as "no snapshot" rather than a failed change.
func snapshotJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// proxySnapshot keeps a proxy together with the children that a delete would
// cascade away, so the stored state is the whole site.
type proxySnapshot struct {
	Proxy     model.Proxy      `json:"proxy"`
	Upstreams []model.Upstream `json:"upstreams"`
	Routes    []model.Route    `json:"routes"`
}

func (s *Server) snapshotProxy(id int64) []byte {
	p, err := s.st.GetProxy(id)
	if err != nil {
		return nil
	}
	snap := proxySnapshot{Proxy: *p, Upstreams: []model.Upstream{}, Routes: []model.Route{}}
	if ups, err := s.st.ListUpstreams(id); err == nil {
		snap.Upstreams = ups
	}
	if routes, err := s.st.ListRoutes(id); err == nil {
		snap.Routes = routes
	}
	return snapshotJSON(snap)
}

func (s *Server) snapshotPolicy(id int64) []byte {
	p, err := s.st.GetPolicy(id)
	if err != nil {
		return nil
	}
	return snapshotJSON(p)
}

func (s *Server) snapshotProfile(id int64) []byte {
	p, err := s.st.GetProfile(id)
	if err != nil {
		return nil
	}
	return snapshotJSON(p)
}

func (s *Server) snapshotProtectionProfile(id int64) []byte {
	p, err := s.st.GetProtectionProfile(id)
	if err != nil {
		return nil
	}
	return snapshotJSON(p)
}

func (s *Server) snapshotAccessProfile(id int64) []byte {
	p, err := s.st.GetAccessProfile(id)
	if err != nil {
		return nil
	}
	return snapshotJSON(p)
}

func (s *Server) snapshotAccessList(id int64) []byte {
	l, err := s.st.GetAccessList(id)
	if err != nil {
		return nil
	}
	return snapshotJSON(l)
}

// auditChange writes the audit entry for a mutation. When a before state was
// captured the entry also stores the state around the change.
func (s *Server) auditChange(user, action, detail, ip, entity string, id int64, before, after []byte) {
	if before == nil {
		s.st.AddAudit(user, action, detail, ip)
		return
	}
	s.st.AddAuditSnapshot(user, action, detail, ip, model.AuditSnapshot{
		Entity: entity, EntityID: id, Before: string(before), After: string(after),
	})
}

// getAuditEntry returns one entry with the state it changed, if any was stored.
func (s *Server) getAuditEntry(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	entry, err := s.st.GetAuditEntry(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	snap, err := s.st.GetAuditSnapshot(id)
	if errors.Is(err, store.ErrNotFound) {
		snap = nil
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entry": entry, "snapshot": snap})
}

// rollbackAudit restores an entity to the state recorded before an audited
// edit. The rollback is itself audited, so history keeps both changes.
func (s *Server) rollbackAudit(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	snap, err := s.st.GetAuditSnapshot(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "this entry has no stored state")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if snap.Before == "" {
		writeError(w, http.StatusConflict, "this entry created the entity; rollback only restores edits")
		return
	}
	if snap.After == "" {
		writeError(w, http.StatusConflict, "this entry removed the entity; recreate it from its page")
		return
	}
	area, ok := entityAreas[snap.Entity]
	if !ok {
		writeError(w, http.StatusConflict, "this entry cannot be rolled back")
		return
	}
	sess := sessionFrom(r)
	// A database from before RBAC has no role; it keeps its full access.
	if !(sess.Role == "" && len(sess.Permissions) == 0) && !sess.Can(rbac.Permission(area, "write")) {
		writeError(w, http.StatusForbidden, "your role does not allow this action")
		return
	}
	if err := s.restoreSnapshot(snap); err != nil {
		if errors.Is(err, errEntityGone) {
			writeError(w, http.StatusConflict, "the entity no longer exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "cannot restore: "+err.Error())
		return
	}
	s.reload(r.Context())
	s.st.AddAudit(sess.Username, snap.Entity+".rollback",
		fmt.Sprintf("restored entry %d", id), clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"restored": snap.Entity, "id": snap.EntityID})
}

// restoreSnapshot writes the recorded before state back over the entity.
func (s *Server) restoreSnapshot(snap *model.AuditSnapshot) error {
	switch snap.Entity {
	case "proxy":
		var snapIn proxySnapshot
		if err := json.Unmarshal([]byte(snap.Before), &snapIn); err != nil {
			return err
		}
		p := snapIn.Proxy
		if _, err := s.st.GetProxy(p.ID); err != nil {
			return errEntityGone
		}
		if err := s.st.UpdateProxy(&p); err != nil {
			return err
		}
		if err := s.st.ReplaceUpstreams(p.ID, snapIn.Upstreams); err != nil {
			return err
		}
		return s.st.ReplaceRoutes(p.ID, snapIn.Routes)
	case "policy":
		var p model.Policy
		if err := json.Unmarshal([]byte(snap.Before), &p); err != nil {
			return err
		}
		if _, err := s.st.GetPolicy(p.ID); err != nil {
			return errEntityGone
		}
		return s.st.UpdatePolicy(&p)
	case "profile":
		var p model.Profile
		if err := json.Unmarshal([]byte(snap.Before), &p); err != nil {
			return err
		}
		if _, err := s.st.GetProfile(p.ID); err != nil {
			return errEntityGone
		}
		return s.st.UpdateProfile(&p)
	case "protection_profile":
		var p model.ProtectionProfile
		if err := json.Unmarshal([]byte(snap.Before), &p); err != nil {
			return err
		}
		if _, err := s.st.GetProtectionProfile(p.ID); err != nil {
			return errEntityGone
		}
		return s.st.UpdateProtectionProfile(&p)
	case "access_profile":
		var p model.AccessProfile
		if err := json.Unmarshal([]byte(snap.Before), &p); err != nil {
			return err
		}
		if _, err := s.st.GetAccessProfile(p.ID); err != nil {
			return errEntityGone
		}
		return s.st.UpdateAccessProfile(&p)
	case "access_list":
		var l model.AccessList
		if err := json.Unmarshal([]byte(snap.Before), &l); err != nil {
			return err
		}
		if _, err := s.st.GetAccessList(l.ID); err != nil {
			return errEntityGone
		}
		return s.st.UpdateAccessList(&l)
	}
	return errors.New("unknown entity")
}
