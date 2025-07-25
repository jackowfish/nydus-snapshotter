/*
 * Copyright (c) 2023. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshot

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/snapshots/storage"
	"github.com/containerd/log"
	"github.com/containerd/nydus-snapshotter/config/daemonconfig"
	"github.com/containerd/nydus-snapshotter/pkg/label"
	"github.com/containerd/nydus-snapshotter/pkg/layout"
	"github.com/containerd/nydus-snapshotter/pkg/rafs"
	"github.com/containerd/nydus-snapshotter/pkg/snapshot"
	"github.com/pkg/errors"
)

const (
	KataVirtualVolumeDefaultSource = "overlay"
	KataVirtualVolumeDummySource   = "dummy-image-reference"
)

type ExtraOption struct {
	Source      string `json:"source"`
	Config      string `json:"config"`
	Snapshotdir string `json:"snapshotdir"`
	Version     string `json:"fs_version"`
}

func (o *snapshotter) remoteMountWithExtraOptions(ctx context.Context, s storage.Snapshot, id string, overlayOptions []string) ([]mount.Mount, error) {
	source, err := o.fs.BootstrapFile(id)
	if err != nil {
		return nil, err
	}

	instance := rafs.RafsGlobalCache.Get(id)
	daemon, err := o.fs.GetDaemonByID(instance.DaemonID)
	if err != nil {
		return nil, errors.Wrapf(err, "get daemon with ID %s", instance.DaemonID)
	}

	var c daemonconfig.DaemonConfig
	if daemon.IsSharedDaemon() {
		c, err = daemonconfig.NewDaemonConfig(daemon.States.FsDriver, daemon.ConfigFile(instance.SnapshotID))
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to load instance configuration %s",
				daemon.ConfigFile(instance.SnapshotID))
		}
	} else {
		c = daemon.Config
	}
	configContent, err := c.DumpString()
	if err != nil {
		return nil, errors.Wrapf(err, "remoteMounts: failed to marshal config")
	}

	// get version from bootstrap
	f, err := os.Open(source)
	if err != nil {
		return nil, errors.Wrapf(err, "remoteMounts: check bootstrap version: failed to open bootstrap")
	}
	defer f.Close()
	header := make([]byte, 4096)
	sz, err := f.Read(header)
	if err != nil {
		return nil, errors.Wrapf(err, "remoteMounts: check bootstrap version: failed to read bootstrap")
	}
	version, err := layout.DetectFsVersion(header[0:sz])
	if err != nil {
		return nil, errors.Wrapf(err, "remoteMounts: failed to detect filesystem version")
	}

	// when enable nydus-overlayfs, return unified mount slice for runc and kata
	extraOption := &ExtraOption{
		Source:      source,
		Config:      configContent,
		Snapshotdir: o.snapshotDir(s.ID),
		Version:     version,
	}
	no, err := json.Marshal(extraOption)
	if err != nil {
		return nil, errors.Wrapf(err, "remoteMounts: failed to marshal NydusOption")
	}
	// XXX: Log options without extraoptions as it might contain secrets.
	log.G(ctx).Debugf("fuse.nydus-overlayfs mount options %v", overlayOptions)
	// base64 to filter easily in `nydus-overlayfs`
	opt := fmt.Sprintf("extraoption=%s", base64.StdEncoding.EncodeToString(no))
	overlayOptions = append(overlayOptions, opt)

	// Replace upperdir/workdir with PVC paths if configured
	upperPath, workPath := loadOverlayPaths()
	if upperPath != "" && workPath != "" && s.Kind == snapshots.KindActive {
		// Remove existing upperdir/workdir options
		var newOptions []string
		for _, option := range overlayOptions {
			if !strings.HasPrefix(option, "upperdir=") && !strings.HasPrefix(option, "workdir=") {
				newOptions = append(newOptions, option)
			}
		}
		// Add PVC paths
		newOptions = append(newOptions, 
			fmt.Sprintf("upperdir=%s", upperPath),
			fmt.Sprintf("workdir=%s", workPath),
		)
		overlayOptions = newOptions
		log.G(ctx).Infof("Using PVC paths for overlay mount - upperdir=%s, workdir=%s", upperPath, workPath)
	}

	// Check if we should use fuse-overlayfs based on upperdir
	upperDir := ""
	for _, option := range overlayOptions {
		if strings.HasPrefix(option, "upperdir=") {
			upperDir = strings.TrimPrefix(option, "upperdir=")
			break
		}
	}

	mountType := "fuse.nydus-overlayfs"
	mountSource := KataVirtualVolumeDefaultSource
	
	if upperDir != "" && shouldUseFuseOverlayfs(upperDir) {
		// Use fuse-overlayfs for FUSE upper directories
		mountType = "fuse.fuse-overlayfs"
		mountSource = "fuse-overlayfs"
		log.G(ctx).Infof("Using fuse-overlayfs for mount due to FUSE upper directory")
	} else if o.nydusOverlayFSPath != "" {
		log.G(ctx).Infof("Using nydus-overlayfs from path: %s", o.nydusOverlayFSPath)
		mountType = fmt.Sprintf("fuse.%s", o.nydusOverlayFSPath)
	}

	return []mount.Mount{
		{
			Type:    mountType,
			Source:  mountSource,
			Options: overlayOptions,
		},
	}, nil
}

func (o *snapshotter) mountWithKataVolume(ctx context.Context, id string, overlayOptions []string, key string) ([]mount.Mount, error) {
	hasVolume := false
	rafs := rafs.RafsGlobalCache.Get(id)
	if rafs == nil {
		return []mount.Mount{}, errors.Errorf("failed to find RAFS instance for snapshot %s", id)
	}

	// Insert Kata volume for proxy
	if label.IsNydusProxyMode(rafs.Annotations) {
		options, err := o.mountWithProxyVolume(*rafs)
		if err != nil {
			return []mount.Mount{}, errors.Wrapf(err, "create kata volume for proxy")
		}
		if len(options) > 0 {
			overlayOptions = append(overlayOptions, options...)
			hasVolume = true
		}
	}

	// Insert Kata volume for tarfs
	if blobID, ok := rafs.Annotations[label.NydusTarfsLayer]; ok {
		options, err := o.mountWithTarfsVolume(ctx, *rafs, blobID, key)
		if err != nil {
			return []mount.Mount{}, errors.Wrapf(err, "create kata volume for tarfs")
		}
		if len(options) > 0 {
			overlayOptions = append(overlayOptions, options...)
			hasVolume = true
		}
	}

	if hasVolume {
		log.G(ctx).Debugf("fuse.nydus-overlayfs mount options %v", overlayOptions)

		mountType := "fuse.nydus-overlayfs"
		if o.nydusOverlayFSPath != "" {
			log.G(ctx).Infof("Using nydus-overlayfs from path: %s", o.nydusOverlayFSPath)
			mountType = fmt.Sprintf("fuse.%s", o.nydusOverlayFSPath)
		}

		mounts := []mount.Mount{
			{
				Type:    mountType,
				Source:  KataVirtualVolumeDefaultSource,
				Options: overlayOptions,
			},
		}
		return mounts, nil
	}

	return overlayMount(overlayOptions), nil
}

func (o *snapshotter) mountWithProxyVolume(rafs rafs.Rafs) ([]string, error) {
	options := []string{}
	source := rafs.Annotations[label.CRIImageRef]

	// In the normal flow, this should correctly return the imageRef. However, passing the CRIImageRef label
	// from containerd is not supported. Therefore, the source will be set to "".
	// But in this case, kata runtime-rs has a non-empty check for the source field. To ensure this field
	// remains non-empty, a forced assignment is used here. This does not affect the passing of information.
	// it is solely to pass the check.
	if len(source) == 0 {
		source = KataVirtualVolumeDummySource
	}

	for k, v := range rafs.Annotations {
		options = append(options, fmt.Sprintf("%s=%s", k, v))
	}
	opt, err := o.prepareKataVirtualVolume(label.NydusProxyMode, source, KataVirtualVolumeImageGuestPullType, "", options, rafs.Annotations)
	if err != nil {
		return options, errors.Wrapf(err, "failed to prepare KataVirtualVolume")
	}
	return []string{opt}, nil
}

func (o *snapshotter) mountWithTarfsVolume(ctx context.Context, rafs rafs.Rafs, blobID, key string) ([]string, error) {
	options := []string{}
	if info, ok := rafs.Annotations[label.NydusImageBlockInfo]; ok {
		path, err := o.fs.GetTarfsImageDiskFilePath(blobID)
		if err != nil {
			return []string{}, errors.Wrapf(err, "get tarfs image disk file path")
		}
		log.L.Debugf("mountWithTarfsVolume info %v", info)
		opt, err := o.prepareKataVirtualVolume(label.NydusImageBlockInfo, path, KataVirtualVolumeImageRawBlockType, "erofs", []string{"ro"}, rafs.Annotations)
		if err != nil {
			return options, errors.Wrapf(err, "failed to prepare KataVirtualVolume for image_raw_block")
		}

		options = append(options, opt)
		log.L.Debugf("mountWithTarfsVolume type=%v, options %v", KataVirtualVolumeImageRawBlockType, options)
		return options, nil
	}

	if _, ok := rafs.Annotations[label.NydusLayerBlockInfo]; ok {
		for {
			pID, pInfo, _, pErr := snapshot.GetSnapshotInfo(ctx, o.ms, key)
			log.G(ctx).Debugf("mountWithKataVolume pID= %v, pInfo = %v", pID, pInfo)

			if pErr != nil {
				return options, errors.Wrapf(pErr, "failed to get snapshot info")
			}
			if pInfo.Kind == snapshots.KindActive {
				key = pInfo.Parent
				continue
			}

			blobID = pInfo.Labels[label.NydusTarfsLayer]
			path, err := o.fs.GetTarfsLayerDiskFilePath(blobID)
			if err != nil {
				return options, errors.Wrapf(err, "get tarfs image disk file path")
			}

			opt, err := o.prepareKataVirtualVolume(label.NydusLayerBlockInfo, path, KataVirtualVolumeLayerRawBlockType, "erofs", []string{"ro"}, pInfo.Labels)
			if err != nil {
				return options, errors.Wrapf(err, "failed to prepare KataVirtualVolume for layer_raw_block")
			}

			options = append(options, opt)

			if pInfo.Parent == "" {
				break
			}
			key = pInfo.Parent
		}
		log.L.Debugf("mountWithTarfsVolume type=%v, options %v", KataVirtualVolumeLayerRawBlockType, options)
		return options, nil
	}

	// If Neither image_raw_block or layer_raw_block, return empty strings
	return options, nil
}

func (o *snapshotter) prepareKataVirtualVolume(blockType, source, volumeType, fsType string, options []string, labels map[string]string) (string, error) {
	volume := &KataVirtualVolume{
		VolumeType: volumeType,
		Source:     source,
		FSType:     fsType,
		Options:    options,
	}
	if blockType == label.NydusImageBlockInfo || blockType == label.NydusLayerBlockInfo {
		dmverityInfo := labels[blockType]
		if len(dmverityInfo) > 0 {
			dmverity, err := parseTarfsDmVerityInfo(dmverityInfo)
			if err != nil {
				return "", err
			}
			volume.DmVerity = &dmverity
		}
	} else if blockType == label.NydusProxyMode {
		volume.ImagePull = &ImagePullVolume{Metadata: labels}
	}

	if !volume.Validate() {
		return "", errors.Errorf("got invalid kata volume, %v", volume)
	}
	info, err := EncodeKataVirtualVolumeToBase64(*volume)
	if err != nil {
		return "", errors.Errorf("failed to encoding Kata Volume info %v", volume)
	}
	opt := fmt.Sprintf("%s=%s", KataVirtualVolumeOptionName, info)
	return opt, nil
}

func parseTarfsDmVerityInfo(info string) (DmVerityInfo, error) {
	var dataBlocks, hashOffset uint64
	var rootHash string

	pattern := "%d,%d,sha256:%s"
	if count, err := fmt.Sscanf(info, pattern, &dataBlocks, &hashOffset, &rootHash); err == nil && count == 3 {
		di := DmVerityInfo{
			HashType:  "sha256",
			Hash:      rootHash,
			BlockNum:  dataBlocks,
			Blocksize: 512,
			Hashsize:  4096,
			Offset:    hashOffset,
		}
		if err := di.Validate(); err != nil {
			return DmVerityInfo{}, errors.Wrap(err, "validate dm-verity information")
		}
		return di, nil
	}

	return DmVerityInfo{}, errors.Errorf("invalid dm-verity information: %s", info)
}

// Consts and data structures for Kata Virtual Volume
const (
	minBlockSize = 1 << 9
	maxBlockSize = 1 << 19
)

const (
	KataVirtualVolumeOptionName          = "io.katacontainers.volume"
	KataVirtualVolumeDirectBlockType     = "direct_block"
	KataVirtualVolumeImageRawBlockType   = "image_raw_block"
	KataVirtualVolumeLayerRawBlockType   = "layer_raw_block"
	KataVirtualVolumeImageNydusBlockType = "image_nydus_block"
	KataVirtualVolumeLayerNydusBlockType = "layer_nydus_block"
	KataVirtualVolumeImageNydusFsType    = "image_nydus_fs"
	KataVirtualVolumeLayerNydusFsType    = "layer_nydus_fs"
	KataVirtualVolumeImageGuestPullType  = "image_guest_pull"
)

// DmVerityInfo contains configuration information for DmVerity device.
type DmVerityInfo struct {
	HashType  string `json:"hashtype"`
	Hash      string `json:"hash"`
	BlockNum  uint64 `json:"blocknum"`
	Blocksize uint64 `json:"blocksize"`
	Hashsize  uint64 `json:"hashsize"`
	Offset    uint64 `json:"offset"`
}

func (d *DmVerityInfo) Validate() error {
	err := d.validateHashType()
	if err != nil {
		return err
	}

	if d.BlockNum == 0 || d.BlockNum > uint64(^uint32(0)) {
		return fmt.Errorf("Zero block count for DmVerity device %s", d.Hash)
	}

	if !validateBlockSize(d.Blocksize) || !validateBlockSize(d.Hashsize) {
		return fmt.Errorf("Unsupported verity block size: data_block_size = %d, hash_block_size = %d", d.Blocksize, d.Hashsize)
	}

	if d.Offset%d.Hashsize != 0 || d.Offset < d.Blocksize*d.BlockNum {
		return fmt.Errorf("Invalid hashvalue offset %d for DmVerity device %s", d.Offset, d.Hash)
	}

	return nil
}

func (d *DmVerityInfo) validateHashType() error {
	switch strings.ToLower(d.HashType) {
	case "sha256":
		return d.validateHash(64, "sha256")
	case "sha1":
		return d.validateHash(40, "sha1")
	default:
		return fmt.Errorf("Unsupported hash algorithm %s for DmVerity device %s", d.HashType, d.Hash)
	}
}

func (d *DmVerityInfo) validateHash(expectedLen int, hashType string) error {
	_, err := hex.DecodeString(d.Hash)
	if len(d.Hash) != expectedLen || err != nil {
		return fmt.Errorf("Invalid hash value %s:%s for DmVerity device with %s", hashType, d.Hash, hashType)
	}
	return nil
}

func validateBlockSize(blockSize uint64) bool {
	return minBlockSize <= blockSize && blockSize <= maxBlockSize
}

func ParseDmVerityInfo(option string) (*DmVerityInfo, error) {
	no := &DmVerityInfo{}
	if err := json.Unmarshal([]byte(option), no); err != nil {
		return nil, errors.Wrapf(err, "DmVerityInfo json unmarshal err")
	}
	if err := no.Validate(); err != nil {
		return nil, fmt.Errorf("DmVerityInfo is not correct, %+v; error = %+v", no, err)
	}
	return no, nil
}

// DirectAssignedVolume contains meta information for a directly assigned volume.
type DirectAssignedVolume struct {
	Metadata map[string]string `json:"metadata"`
}

func (d *DirectAssignedVolume) Validate() bool {
	return d.Metadata != nil
}

// ImagePullVolume contains meta information for pulling an image inside the guest.
type ImagePullVolume struct {
	Metadata map[string]string `json:"metadata"`
}

func (i *ImagePullVolume) Validate() bool {
	return i.Metadata != nil
}

// NydusImageVolume contains Nydus image volume information.
type NydusImageVolume struct {
	Config      string `json:"config"`
	SnapshotDir string `json:"snapshot_dir"`
}

func (n *NydusImageVolume) Validate() bool {
	return len(n.Config) > 0 || len(n.SnapshotDir) > 0
}

// KataVirtualVolume encapsulates information for extra mount options and direct volumes.
type KataVirtualVolume struct {
	VolumeType   string                `json:"volume_type"`
	Source       string                `json:"source,omitempty"`
	FSType       string                `json:"fs_type,omitempty"`
	Options      []string              `json:"options,omitempty"`
	DirectVolume *DirectAssignedVolume `json:"direct_volume,omitempty"`
	ImagePull    *ImagePullVolume      `json:"image_pull,omitempty"`
	NydusImage   *NydusImageVolume     `json:"nydus_image,omitempty"`
	DmVerity     *DmVerityInfo         `json:"dm_verity,omitempty"`
}

func (k *KataVirtualVolume) Validate() bool {
	switch k.VolumeType {
	case KataVirtualVolumeDirectBlockType:
		if k.Source != "" && k.DirectVolume != nil && k.DirectVolume.Validate() {
			return true
		}
	case KataVirtualVolumeImageRawBlockType, KataVirtualVolumeLayerRawBlockType:
		if k.Source != "" && (k.DmVerity == nil || k.DmVerity.Validate() == nil) {
			return true
		}
	case KataVirtualVolumeImageNydusBlockType, KataVirtualVolumeLayerNydusBlockType, KataVirtualVolumeImageNydusFsType, KataVirtualVolumeLayerNydusFsType:
		if k.Source != "" && k.NydusImage != nil && k.NydusImage.Validate() {
			return true
		}
	case KataVirtualVolumeImageGuestPullType:
		if k.ImagePull != nil && k.ImagePull.Validate() {
			return true
		}
	}

	return false
}

func ParseKataVirtualVolume(option []byte) (*KataVirtualVolume, error) {
	no := &KataVirtualVolume{}
	if err := json.Unmarshal(option, no); err != nil {
		return nil, errors.Wrapf(err, "KataVirtualVolume json unmarshal err")
	}
	if !no.Validate() {
		return nil, fmt.Errorf("KataVirtualVolume is not correct, %+v", no)
	}

	return no, nil
}

func ParseKataVirtualVolumeFromBase64(option string) (*KataVirtualVolume, error) {
	opt, err := base64.StdEncoding.DecodeString(option)
	if err != nil {
		return nil, errors.Wrap(err, "KataVirtualVolume base64 decoding err")
	}
	return ParseKataVirtualVolume(opt)
}

func EncodeKataVirtualVolumeToBase64(volume KataVirtualVolume) (string, error) {
	validKataVirtualVolumeJSON, err := json.Marshal(volume)
	if err != nil {
		return "", errors.Wrapf(err, "marshal KataVirtualVolume object")
	}
	log.L.Infof("encode kata volume %s", validKataVirtualVolumeJSON)
	option := base64.StdEncoding.EncodeToString(validKataVirtualVolumeJSON)
	return option, nil
}
