package model

import "time"

// ScanRun is one execution of the security scanner against one hostname.
type ScanRun struct {
	ID        int64      `json:"id"`
	SiteID    int64      `json:"site_id"`
	Target    string     `json:"target"`
	Trigger   string     `json:"trigger"`
	Actor     string     `json:"actor"`
	Path      string     `json:"path"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Verdicts  string     `json:"verdicts,omitempty"`
	Skipped   string     `json:"skipped_reason,omitempty"`
	AgentNode string     `json:"agent_node,omitempty"`
}

// ScanEvidence is one probe's verdict. It keeps hashes and a redacted request
// line, never a credential or a response body.
type ScanEvidence struct {
	RunID      int64   `json:"run_id"`
	Seq        int     `json:"seq"`
	Stage      string  `json:"stage"`
	Class      string  `json:"class"`
	Method     string  `json:"method"`
	Path       string  `json:"path"`
	Verdict    string  `json:"verdict"`
	WANStatus  int     `json:"wan_status"`
	UpStatus   int     `json:"upstream_status"`
	WANHash    string  `json:"wan_hash,omitempty"`
	UpHash     string  `json:"upstream_hash,omitempty"`
	Similarity float64 `json:"similarity,omitempty"`
	Detail     string  `json:"detail,omitempty"`
	Note       string  `json:"note,omitempty"`
}
