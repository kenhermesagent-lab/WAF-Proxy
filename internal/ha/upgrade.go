package ha

import "fmt"

// NodeVersion is what one node reports about its release and data format. The
// heartbeat carries the same facts, so an upgrade can be planned before either
// node restarts.
type NodeVersion struct {
	Node     string `json:"node,omitempty"`
	Role     string `json:"role,omitempty"`
	Version  string `json:"version"`
	Schema   string `json:"schema"`
	Protocol int    `json:"protocol"`
}

// UpgradeCheck is the pair-wide answer to `wafproxy ha upgrade --check`.
type UpgradeCheck struct {
	Local       NodeVersion  `json:"local"`
	Peer        *NodeVersion `json:"peer,omitempty"`
	Compatible  bool         `json:"compatible"`
	SameVersion bool         `json:"same_version"`
	Problems    []string     `json:"problems,omitempty"`
	Advice      string       `json:"advice"`
}

// CheckUpgrade compares this node with its peer; peerErr is why there is no
// peer when the heartbeat failed. Schema and protocol must match
// before a move or a join; a release difference is expected in the middle of an
// upgrade and is reported without blocking.
func CheckUpgrade(local NodeVersion, peer *NodeVersion, peerErr error) UpgradeCheck {
	out := UpgradeCheck{Local: local, Peer: peer}
	if peer == nil {
		problem := "the peer did not answer the heartbeat"
		if peerErr != nil {
			problem += ": " + peerErr.Error()
		}
		out.Problems = append(out.Problems, problem)
		out.Advice = "start the peer and check the HA link before upgrading"
		return out
	}
	switch {
	case peer.Version == "":
		out.Problems = append(out.Problems, "the peer does not report its release; it predates this check")
	case peer.Version != local.Version:
		out.Problems = append(out.Problems, fmt.Sprintf("release %s here and %s on the peer", local.Version, peer.Version))
	default:
		out.SameVersion = true
	}
	if local.Schema != peer.Schema {
		out.Problems = append(out.Problems, fmt.Sprintf("schema %s here and %s on the peer", local.Schema, peer.Schema))
	}
	if local.Protocol != peer.Protocol {
		out.Problems = append(out.Problems, fmt.Sprintf("protocol %d here and %d on the peer", local.Protocol, peer.Protocol))
	}
	out.Compatible = local.Schema == peer.Schema && local.Protocol == peer.Protocol
	switch {
	case len(out.Problems) == 0:
		out.Advice = "the pair is on the same release and schema; upgrade the standby first, then fail over and upgrade the old active"
	case !out.Compatible:
		out.Advice = "the nodes must agree on schema and protocol before a move; start the newer release on the standby first"
	default:
		out.Advice = "the releases differ but the data format matches, so a move is safe; upgrade the standby first and finish with the old active"
	}
	return out
}
