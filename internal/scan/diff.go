package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/gate"
)

// answer is one response, reduced to what the comparison needs. Headers are
// kept only so preflight can see CF-Ray and decide which path the probe took.
type answer struct {
	status int
	header http.Header
	body   []byte
}

func (a answer) hash() string {
	if len(a.body) == 0 {
		return ""
	}
	sum := sha256.Sum256(a.body)
	return hex.EncodeToString(sum[:])[:16]
}

// similarityThreshold is how much of two bodies must line up for the same
// answer. A timestamp in a footer moves one block and stays conclusive; a
// different page does not.
const similarityThreshold = 0.9

// verdictFor compares the published answer with the upstream one.
func verdictFor(wan, up answer) (Verdict, float64) {
	if isGatePage(wan) && !isGatePage(up) {
		return BlockedGate, 0
	}
	if wanRefusal(wan.status) && wan.status != up.status {
		return BlockedWAF, 0
	}
	if wan.status != up.status {
		return Inconclusive, 0
	}
	sim := similarity(wan.body, up.body)
	if sim < similarityThreshold {
		return Inconclusive, sim
	}
	return ReachedBackend, sim
}

// wanRefusal reports the statuses a WAF or rate limit answers with. Blocked
// pages served with 200 are caught by the body comparison instead.
func wanRefusal(status int) bool {
	switch status {
	case 403, 406, 429:
		return true
	}
	return false
}

// isGatePage recognises the access gate's challenge, which is the same page for
// every path so an unauthenticated visitor learns nothing.
func isGatePage(a answer) bool {
	return bytes.Contains(a.body, []byte(`action="`+gate.LoginPath+`"`))
}

// similarity compares two bodies block by block, so a dynamic fragment costs
// one block instead of the whole page.
func similarity(a, b []byte) float64 {
	const block = 64
	blocks := (max(len(a), len(b)) + block - 1) / block
	if blocks == 0 {
		return 1
	}
	same := 0
	for i := 0; i < blocks; i++ {
		if bytes.Equal(chunk(a, i, block), chunk(b, i, block)) {
			same++
		}
	}
	return float64(same) / float64(blocks)
}

func chunk(b []byte, i, size int) []byte {
	start := i * size
	if start >= len(b) {
		return nil
	}
	return b[start:min(start+size, len(b))]
}

// shortError keeps a transport error storable.
func shortError(err error) string {
	msg := strings.TrimSpace(err.Error())
	if len(msg) > 160 {
		msg = msg[:160]
	}
	return msg
}
