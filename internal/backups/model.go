// Package backups implements TomPanel's site recovery archives: versioned
// manifests, guarded restores, retention, and optional age-encrypted object
// storage uploads.
package backups

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Kind describes why a backup exists.
type Kind string

const (
	KindManual     Kind = "manual"
	KindScheduled  Kind = "scheduled"
	KindPreRestore Kind = "pre_restore"
	KindFinal      Kind = "final"
)

// Storage describes where a backup body lives.
type Storage string

const (
	StorageLocal    Storage = "local"
	StorageS3       Storage = "s3"
	StorageLocalS3  Storage = "local+s3"
)

// Backup is one persisted archive record.
type Backup struct {
	ID        string    `json:"id"`
	SiteID    string    `json:"site_id"`
	Kind      Kind      `json:"kind"`
	Storage   Storage   `json:"storage"`
	State     string    `json:"state"`
	AgentPath string    `json:"agent_path,omitempty"`
	ObjectKey string    `json:"object_key,omitempty"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	Manifest  []byte    `json:"-"`
	Protected bool      `json:"protected"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// DiskState is one free-space observation of the backup volume.
type DiskState struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
	Free  uint64 `json:"free"`
}

var (
	ErrInsufficientDisk = errors.New("insufficient disk space for a new backup")
	ErrBackupNotFound   = errors.New("backup not found")
	ErrProtectedBackup  = errors.New("manual backups are never deleted automatically")
	ErrChecksumMismatch = errors.New("backup checksum mismatch")
	ErrNoRemoteObject   = errors.New("backup has no remote object")
)

const (
	diskGuardRatio  = 0.85
	diskGuardFree   = 2 << 30
	retainedScheduled = 7
	quarantineDays  = 7
)

// CheckDisk applies the backup disk guard: stop above 85% use or below 2 GiB.
func CheckDisk(state DiskState) error {
	if state.Total == 0 {
		return errors.New("disk state is unavailable")
	}
	if float64(state.Used)/float64(state.Total) >= diskGuardRatio {
		return ErrInsufficientDisk
	}
	if state.Free < diskGuardFree {
		return ErrInsufficientDisk
	}
	return nil
}

func newBackupID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate backup ID: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}
