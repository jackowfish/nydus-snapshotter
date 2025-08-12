package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
)

const (
	// Extra mount option to pass Nydus specific information from snapshotter to runtime through containerd.
	extraOptionKey = "extraoption="
	// Kata virtual volume infmation passed from snapshotter to runtime through containerd, superset of `extraOptionKey`.
	// Please refer to `KataVirtualVolume` in https://github.com/kata-containers/kata-containers/blob/main/src/libs/kata-types/src/mount.rs
	kataVolumeOptionKey = "io.katacontainers.volume="
)

var (
	Version   = "v0.1"
	BuildTime = "unknown"
)

// ExtraOption represents the nydus-specific mount information
type ExtraOption struct {
	Source      string `json:"source"`
	Config      string `json:"config"`
	Snapshotdir string `json:"snapshotdir"`
	Version     string `json:"fs_version"`
}

// NydusdConfig represents the nydusd configuration to check for overlay settings
type NydusdConfig struct {
	Overlay *OverlayConfig `json:"overlay,omitempty"`
}

// OverlayConfig represents overlay filesystem configuration
type OverlayConfig struct {
	UpperDir string `json:"upper_dir"`
	WorkDir  string `json:"work_dir"`
}

/*
containerd run fuse.mount format: nydus-overlayfs overlay /tmp/ctd-volume107067851
-o lowerdir=/foo/lower2:/foo/lower1,upperdir=/foo/upper,workdir=/foo/work,extraoption={...},dev,suid]
*/
type mountArgs struct {
	fsType      string
	target      string
	options     []string
	extraOption *ExtraOption
}

// parseExtraOption extracts and parses the extraoption from mount options
func parseExtraOption(options []string) *ExtraOption {
	for _, opt := range options {
		if strings.HasPrefix(opt, extraOptionKey) {
			extraOptionB64 := strings.TrimPrefix(opt, extraOptionKey)
			extraOptionJSON, err := base64.StdEncoding.DecodeString(extraOptionB64)
			if err != nil {
				log.Printf("Failed to decode extraoption: %v", err)
				return nil
			}
			
			var extraOption ExtraOption
			if err := json.Unmarshal(extraOptionJSON, &extraOption); err != nil {
				log.Printf("Failed to unmarshal extraoption: %v", err)
				return nil
			}
			
			return &extraOption
		}
	}
	return nil
}

// hasOverlayInConfig checks if overlay configuration is present in nydusd config
func hasOverlayInConfig(config string) bool {
	var nydusdConfig NydusdConfig
	if err := json.Unmarshal([]byte(config), &nydusdConfig); err != nil {
		log.Printf("Failed to parse nydusd config: %v", err)
		return false
	}
	
	return nydusdConfig.Overlay != nil && 
		   nydusdConfig.Overlay.UpperDir != "" && 
		   nydusdConfig.Overlay.WorkDir != ""
}

func parseArgs(args []string) (*mountArgs, error) {
	margs := &mountArgs{
		fsType: args[0],
		target: args[1],
	}
	if margs.fsType != "overlay" {
		return nil, errors.Errorf("invalid filesystem type %s for overlayfs", margs.fsType)
	}
	if len(margs.target) == 0 {
		return nil, errors.New("empty overlayfs mount target")
	}

	if args[2] == "-o" && len(args[3]) != 0 {
		allOptions := strings.Split(args[3], ",")
		
		// Parse extraoption before filtering
		margs.extraOption = parseExtraOption(allOptions)
		
		for _, opt := range allOptions {
			// filter Nydus specific options
			if strings.HasPrefix(opt, extraOptionKey) || strings.HasPrefix(opt, kataVolumeOptionKey) {
				continue
			}
			margs.options = append(margs.options, opt)
		}
	}
	if len(margs.options) == 0 && margs.extraOption == nil {
		return nil, errors.New("empty overlayfs mount options and no extraoption")
	}

	return margs, nil
}

func parseOptions(options []string) (int, string) {
	flagsTable := map[string]int{
		"async":         unix.MS_SYNCHRONOUS,
		"atime":         unix.MS_NOATIME,
		"bind":          unix.MS_BIND,
		"defaults":      0,
		"dev":           unix.MS_NODEV,
		"diratime":      unix.MS_NODIRATIME,
		"dirsync":       unix.MS_DIRSYNC,
		"exec":          unix.MS_NOEXEC,
		"mand":          unix.MS_MANDLOCK,
		"noatime":       unix.MS_NOATIME,
		"nodev":         unix.MS_NODEV,
		"nodiratime":    unix.MS_NODIRATIME,
		"noexec":        unix.MS_NOEXEC,
		"nomand":        unix.MS_MANDLOCK,
		"norelatime":    unix.MS_RELATIME,
		"nostrictatime": unix.MS_STRICTATIME,
		"nosuid":        unix.MS_NOSUID,
		"rbind":         unix.MS_BIND | unix.MS_REC,
		"relatime":      unix.MS_RELATIME,
		"remount":       unix.MS_REMOUNT,
		"ro":            unix.MS_RDONLY,
		"rw":            unix.MS_RDONLY,
		"strictatime":   unix.MS_STRICTATIME,
		"suid":          unix.MS_NOSUID,
		"sync":          unix.MS_SYNCHRONOUS,
	}

	var (
		flags int
		data  []string
	)
	for _, o := range options {
		if f, exist := flagsTable[o]; exist {
			flags |= f
		} else {
			data = append(data, o)
		}
	}
	return flags, strings.Join(data, ",")
}

func run(args cli.Args) error {
	margs, err := parseArgs(args.Slice())
	if err != nil {
		return errors.Wrap(err, "parse mount options")
	}

	// Check if overlay configuration is present in extraoption
	if margs.extraOption != nil && hasOverlayInConfig(margs.extraOption.Config) {
		log.Printf("Detected overlay configuration in nydusd config - skipping syscall overlayfs mount")
		log.Printf("Target: %s will be mounted by nydusd with native overlay support", margs.target)
		
		// Create target directory if it doesn't exist
		if err := os.MkdirAll(margs.target, 0755); err != nil {
			return errors.Wrapf(err, "failed to create target directory %s", margs.target)
		}
		
		// Return success - let nydusd handle the mounting with its native overlay support
		return nil
	}

	// Fall back to regular overlayfs syscall mount for cases without overlay config
	flags, data := parseOptions(margs.options)
	err = syscall.Mount(margs.fsType, margs.target, margs.fsType, uintptr(flags), data)
	if err != nil {
		return errors.Wrapf(err, "mount overlayfs by syscall")
	}
	return nil
}

func main() {
	app := &cli.App{
		Name:      "NydusOverlayfs",
		Usage:     "FUSE mount helper for containerd to filter out Nydus specific options",
		Version:   fmt.Sprintf("%s.%s", Version, BuildTime),
		UsageText: "[Usage]: nydus-overlayfs overlay <target> -o <options>",
		Action: func(c *cli.Context) error {
			return run(c.Args())
		},
		Before: func(c *cli.Context) error {
			if c.NArg() != 4 {
				cli.ShowAppHelpAndExit(c, 1)
			}
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

	os.Exit(0)
}
