package snapshot

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/containerd/log"
)

// isFUSEPath checks if the given path is on a FUSE filesystem
func isFUSEPath(path string) bool {
	// Method 1: Check filesystem type using statfs
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err == nil {
		// FUSE filesystem type magic number
		if stat.Type == 0x65735546 { // FUSE_SUPER_MAGIC
			return true
		}
	}

	// Method 2: Check /proc/mounts as fallback
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	file, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	longestMatch := ""
	isFuse := false

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		
		mountPoint := fields[1]
		fsType := fields[2]
		
		// Check if this mount point is a parent of our path
		if strings.HasPrefix(absPath, mountPoint) && len(mountPoint) > len(longestMatch) {
			longestMatch = mountPoint
			// Check if it's a FUSE filesystem
			isFuse = strings.HasPrefix(fsType, "fuse") || fsType == "juicefs"
		}
	}

	return isFuse
}

// shouldUseFuseOverlayfs determines if we should use fuse-overlayfs instead of kernel overlayfs
func shouldUseFuseOverlayfs(upperDir string) bool {
	if upperDir == "" {
		return false
	}

	// Check if the upper directory is on a FUSE filesystem
	if isFUSEPath(upperDir) {
		log.L.Infof("Detected FUSE filesystem for upperdir %s, will use fuse-overlayfs", upperDir)
		return true
	}

	return false
}