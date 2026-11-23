package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/agentlink"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/urlguard"
)

// SetAgentLinks attaches the webhook dispatcher.
func (s *Server) SetAgentLinks(d *agentlink.Dispatcher) { s.agentLinks = d }

type agentLinkBody struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	Secret   string `json:"secret"`
	Enabled  *bool  `json:"enabled"`
}

func validateAgentLink(name, endpoint string) string {
	if name == "" || len(name) > 64 {
		return "an agent name of 1–64 characters is required"
	}
	if !isHTTPURL(endpoint) {
		return "the endpoint must be an absolute http(s) URL"
	}
	// Every other operator-supplied outbound URL goes through the same guard.
	// A LAN collector such as Home Assistant stays allowed; a link-local or
	// cloud metadata address does not.
	if err := urlguard.Check(endpoint, urlguard.Webhook); err != nil {
		return "the endpoint cannot be a link-local or cloud metadata address (" + err.Error() + ")"
	}
	return ""
}

func (s *Server) listAgentLinks(w http.ResponseWriter, r *http.Request) {
	list, err := s.db(r).ListAgentLinks()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	last, err := s.db(r).LastDeliveries()
	if err == nil {
		for i := range list {
			if d, ok := last[list[i].ID]; ok {
				list[i].LastDelivery = &model.DeliverySummary{
					ID: d.ID, Kind: d.Kind, State: d.State, Attempts: d.Attempts,
					LastStatus: d.LastStatus, LastError: d.LastError,
					CreatedAt: d.CreatedAt, DeliveredAt: d.DeliveredAt,
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, list)
}

// listAgentDeliveries shows a link's recent payloads, newest first.
func (s *Server) listAgentDeliveries(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := s.db(r).DeliveriesForLink(id, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// retryAgentLink re-queues the newest delivery for a link.
func (s *Server) retryAgentLink(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if s.agentLinks == nil {
		writeError(w, http.StatusServiceUnavailable, "the agent dispatcher is not configured")
		return
	}
	ok, err := s.agentLinks.RetryLast(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "no delivery to retry")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "queued"})
}

func (s *Server) createAgentLink(w http.ResponseWriter, r *http.Request) {
	var in agentLinkBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Endpoint = strings.TrimSpace(in.Endpoint)
	if msg := validateAgentLink(in.Name, in.Endpoint); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	link := &model.AgentLink{Name: in.Name, Endpoint: in.Endpoint, Enabled: in.Enabled == nil || *in.Enabled}
	if in.Secret != "" {
		sealed, err := s.box.Seal(in.Secret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encryption error")
			return
		}
		link.Secret = sealed
	}
	id, err := s.db(r).CreateAgentLink(link)
	if err != nil {
		writeError(w, http.StatusConflict, "an agent with that name already exists")
		return
	}
	if saved, err := s.db(r).GetAgentLink(id); err == nil {
		link = saved
	} else {
		link.ID = id
	}
	link.HasSecret = link.Secret != ""
	link.Secret = ""
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "agent-link.create", link.Name, clientIP(r))
	writeJSON(w, http.StatusCreated, link)
}

func (s *Server) updateAgentLink(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	current, err := s.db(r).GetAgentLink(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	var in agentLinkBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	current.Name = strings.TrimSpace(in.Name)
	current.Endpoint = strings.TrimSpace(in.Endpoint)
	if in.Enabled != nil {
		current.Enabled = *in.Enabled
	}
	if msg := validateAgentLink(current.Name, current.Endpoint); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if in.Secret != "" {
		sealed, err := s.box.Seal(in.Secret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encryption error")
			return
		}
		current.Secret = sealed
	}
	if err := s.db(r).UpdateAgentLink(current); err != nil {
		writeError(w, http.StatusConflict, "an agent with that name already exists")
		return
	}
	current.HasSecret = current.Secret != ""
	current.Secret = ""
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "agent-link.update", current.Name, clientIP(r))
	writeJSON(w, http.StatusOK, current)
}

func (s *Server) deleteAgentLink(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	link, err := s.db(r).GetAgentLink(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err := s.db(r).DeleteAgentLink(id); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete")
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "agent-link.delete", link.Name, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// testAgentLink posts a synthetic event so the admin can prove reachability.
func (s *Server) testAgentLink(w http.ResponseWriter, r *http.Request) {
	if s.agentLinks == nil {
		writeError(w, http.StatusServiceUnavailable, "the agent dispatcher is not configured")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	link, err := s.db(r).GetAgentLink(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err := s.agentLinks.SendTest(r.Context(), *link); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}
