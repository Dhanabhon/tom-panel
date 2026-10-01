package backups

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// ManifestVersion is the current manifest schema version.
const ManifestVersion = 1

// FileEntry records one archived file body.
type FileEntry struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// DatabaseDump records one consistent database body of the archive.
type DatabaseDump struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Consistency records how the bodies were captured.
type Consistency struct {
	FilesArchiveStreamed bool `json:"files_archive_streamed"`
	DatabaseSnapshotTxn  bool `json:"database_snapshot_txn"`
}

// Manifest is the versioned, canonical description of one backup.
type Manifest struct {
	Version      int               `json:"version"`
	SiteID       string            `json:"site_id"`
	Kind         string            `json:"kind"`
	CreatedAt    int64             `json:"created_at"`
	Files        []FileEntry       `json:"files"`
	Database     []DatabaseDump    `json:"database"`
	ToolVersions map[string]string `json:"tool_versions"`
	Consistency  Consistency       `json:"consistency"`
}

var ErrManifestInvalid = errors.New("backup manifest is invalid")

// CanonicalJSON renders the manifest deterministically.
func (m Manifest) CanonicalJSON() ([]byte, error) {
	encoded, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

// Sum returns the canonical checksum of the manifest.
func (m Manifest) Sum() (string, error) {
	encoded, err := m.CanonicalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// ParseManifest decodes and validates a stored manifest blob.
func ParseManifest(blob []byte) (Manifest, error) {
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(blob))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrManifestInvalid, err)
	}
	if manifest.Version != ManifestVersion || manifest.SiteID == "" || len(manifest.SiteID) != 32 {
		return Manifest{}, fmt.Errorf("%w: version or site", ErrManifestInvalid)
	}
	if len(manifest.Files) == 0 && len(manifest.Database) == 0 {
		return Manifest{}, fmt.Errorf("%w: empty archive", ErrManifestInvalid)
	}
	return manifest, nil
}

// AppendFile records one file body.
func (m *Manifest) AppendFile(name string, size int64, sha string) {
	m.Files = append(m.Files, FileEntry{Name: name, Size: size, SHA256: sha})
}

// AppendDatabase records one database body.
func (m *Manifest) AppendDatabase(name, path string, size int64, sha string) {
	m.Database = append(m.Database, DatabaseDump{Name: name, Path: path, Size: size, SHA256: sha})
}
