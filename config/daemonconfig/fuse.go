/*
 * Copyright (c) 2022. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package daemonconfig

import (
	"encoding/json"
	"os"
	"path"
	"strings"

	"github.com/pkg/errors"

	"github.com/containerd/nydus-snapshotter/pkg/auth"
	"github.com/containerd/log"
)

const CacheDir string = "cachedir"
const BaseConfigPath string = "base_config_path"

// Used when nydusd works as a FUSE daemon or vhost-user-fs backend
type FuseDaemonConfig struct {
	Device          *DeviceConfig `json:"device"`
	Mode            string        `json:"mode"`
	DigestValidate  bool          `json:"digest_validate"`
	IOStatsFiles    bool          `json:"iostats_files,omitempty"`
	EnableXattr     bool          `json:"enable_xattr,omitempty"`
	AccessPattern   bool          `json:"access_pattern,omitempty"`
	LatestReadFiles bool          `json:"latest_read_files,omitempty"`
	AmplifyIo       *int          `json:"amplify_io,omitempty"`
	FSPrefetch      `json:"fs_prefetch,omitempty"`
	// (experimental) The nydus daemon could cache more data to increase hit ratio when enabled the warmup feature.
	Warmup uint64 `json:"warmup,omitempty"`
	// Overlay filesystem configuration for writable containers (used by nydusd)
	Overlay *OverlayConfig `json:"overlay,omitempty"`
	// Snapshotter overlay filesystem configuration (used by snapshotter for mounts)
	SnapshotterOverlay *SnapshotterOverlayConfig `json:"snapshotter_overlay,omitempty"`
}

// OverlayConfig defines the overlay filesystem configuration
type OverlayConfig struct {
	UpperDir string `json:"upper_dir"`
	WorkDir  string `json:"work_dir"`
}

// SnapshotterOverlayConfig defines the overlay filesystem configuration for snapshotter mounts
type SnapshotterOverlayConfig struct {
	UpperDir string `json:"upper_dir"`
	WorkDir  string `json:"work_dir"`
}

// Control how to perform prefetch from file system layer
type FSPrefetch struct {
	Enable        bool `json:"enable"`
	PrefetchAll   bool `json:"prefetch_all"`
	ThreadsCount  int  `json:"threads_count"`
	MergingSize   int  `json:"merging_size"`
	BandwidthRate int  `json:"bandwidth_rate"`
}

// Load fuse daemon configuration from template file
func LoadFuseConfig(p string) (*FuseDaemonConfig, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, errors.Wrapf(err, "read FUSE configuration file %s", p)
	}
	var cfg FuseDaemonConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, errors.Wrapf(err, "unmarshal %s", p)
	}

	if cfg.Device == nil {
		return nil, errors.New("invalid fuse daemon configuration")
	}

	return &cfg, nil
}

func (c *FuseDaemonConfig) Supplement(host, repo, _ string, params map[string]string) {
	c.Device.Backend.Config.Host = host
	c.Device.Backend.Config.Repo = repo
	c.Device.Cache.Config.WorkDir = params[CacheDir]
	
	// Read overlay configuration from base config file every time
	if baseConfigPath, exists := params[BaseConfigPath]; exists {
		log.L.Infof("Supplement: loading overlay config from base config path: %s", baseConfigPath)
		
		// Check if we should skip loading overlay config (to use external fuse-overlayfs)
		if shouldUseExternalOverlay(baseConfigPath) {
			log.L.Infof("Supplement: skipping overlay config loading - will use external fuse-overlayfs")
		} else {
			c.loadOverlayFromBaseConfig(baseConfigPath)
		}
	} else {
		log.L.Infof("Supplement: no BaseConfigPath provided in params, overlay config will not be loaded")
	}
}

// shouldUseExternalOverlay checks if we should use external fuse-overlayfs instead of nydusd's internal overlay
func shouldUseExternalOverlay(baseConfigPath string) bool {
	baseConfig, err := LoadFuseConfig(baseConfigPath)
	if err != nil {
		log.L.Warnf("shouldUseExternalOverlay: failed to load config from %s: %v", baseConfigPath, err)
		return false
	}
	
	// If overlay config exists, check if it's using JuiceFS or similar FUSE filesystem
	if baseConfig.Overlay != nil && baseConfig.Overlay.UpperDir != "" {
		// Check if the upper directory path suggests it's a FUSE filesystem (e.g., JuiceFS)
		// JuiceFS typically mounts under /mnt/juicefs/ or similar paths
		if strings.Contains(baseConfig.Overlay.UpperDir, "/mnt/juicefs/") ||
		   strings.Contains(baseConfig.Overlay.UpperDir, "/juicefs/") ||
		   strings.Contains(baseConfig.Overlay.UpperDir, "fuse") {
			log.L.Infof("shouldUseExternalOverlay: detected FUSE filesystem in upper dir: %s", baseConfig.Overlay.UpperDir)
			return true
		}
	}
	
	return false
}

// loadOverlayFromBaseConfig reads only the snapshotter overlay configuration from the base config file
func (c *FuseDaemonConfig) loadOverlayFromBaseConfig(baseConfigPath string) {
	log.L.Infof("loadOverlayFromBaseConfig: attempting to load from %s", baseConfigPath)
	baseConfig, err := LoadFuseConfig(baseConfigPath)
	if err != nil {
		log.L.Warnf("loadOverlayFromBaseConfig: failed to load config from %s: %v", baseConfigPath, err)
		return
	}
	
	// Copy only the snapshotter_overlay configuration if it exists
	if baseConfig.SnapshotterOverlay != nil {
		c.SnapshotterOverlay = &SnapshotterOverlayConfig{
			UpperDir: baseConfig.SnapshotterOverlay.UpperDir,
			WorkDir:  baseConfig.SnapshotterOverlay.WorkDir,
		}
		log.L.Infof("loadOverlayFromBaseConfig: loaded snapshotter_overlay config - upperDir=%s, workDir=%s", 
			c.SnapshotterOverlay.UpperDir, c.SnapshotterOverlay.WorkDir)
	} else {
		log.L.Infof("loadOverlayFromBaseConfig: no snapshotter_overlay configuration found in base config")
	}
}

func (c *FuseDaemonConfig) FillAuth(kc *auth.PassKeyChain) {
	if kc != nil {
		if kc.TokenBase() {
			c.Device.Backend.Config.RegistryToken = kc.Password
		} else {
			c.Device.Backend.Config.Auth = kc.ToBase64()
		}
	}
}

func (c *FuseDaemonConfig) UpdateMirrors(mirrorsConfigDir, registryHost string) error {
	mirrors, err := LoadMirrorsConfig(mirrorsConfigDir, registryHost)
	if err != nil {
		return err
	}
	if len(mirrors) > 0 {
		c.Device.Backend.Config.Mirrors = mirrors
	}
	return nil
}

func (c *FuseDaemonConfig) StorageBackend() (string, *BackendConfig) {
	return c.Device.Backend.BackendType, &c.Device.Backend.Config
}

func (c *FuseDaemonConfig) DumpString() (string, error) {
	return DumpConfigString(c)
}

func (c *FuseDaemonConfig) DumpFile(f string) error {
	if err := os.MkdirAll(path.Dir(f), 0755); err != nil {
		return err
	}
	return DumpConfigFile(c, f)
}
