//go:build linux

package ha

import "golang.org/x/sys/unix"

// diskFreePercent reports the free space on the filesystem holding dir.
func diskFreePercent(dir string) (float64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	total := float64(st.Blocks) * float64(st.Bsize)
	if total <= 0 {
		return 0, nil
	}
	free := float64(st.Bavail) * float64(st.Bsize)
	return free / total * 100, nil
}
