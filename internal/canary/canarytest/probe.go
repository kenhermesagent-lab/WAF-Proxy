// Package canarytest holds a scripted probe for tests that need a canary
// result without a network.
package canarytest

import (
	"context"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/canary"
)

// Probe returns a fixed result.
type Probe struct {
	Result canary.Result
	Calls  int
}

func (p *Probe) Run(context.Context, string) canary.Result {
	p.Calls++
	return p.Result
}
