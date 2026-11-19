//go:build !linux

package ban

import "log/slog"

// Kernel is a no-op on platforms without nftables.
type Kernel struct{}

// NewKernel returns an unavailable kernel on non-Linux platforms.
func NewKernel(_ *slog.Logger) *Kernel { return &Kernel{} }

// Status reports kernel enforcement as unavailable.
func (k *Kernel) Status() (bool, string) { return false, "kernel enforcement requires Linux" }

// Sync is a no-op.
func (k *Kernel) Sync(_ []Record) error { return nil }

// SetStealth is a no-op.
func (k *Kernel) SetStealth(_ bool, _ string) error { return nil }

// Add is a no-op.
func (k *Kernel) Add(_ string) error { return nil }

// Remove is a no-op.
func (k *Kernel) Remove(_ string) error { return nil }
