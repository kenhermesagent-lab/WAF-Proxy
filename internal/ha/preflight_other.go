//go:build !linux

package ha

import "errors"

// diskFreePercent is unavailable where the platform has no statfs.
func diskFreePercent(string) (float64, error) {
	return 0, errors.New("ha: disk free percentage is not available on this platform")
}
