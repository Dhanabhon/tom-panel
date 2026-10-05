package files

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"
)

// Limits bound every File Manager operation so a single request cannot
// exhaust disk or memory.
type Limits struct {
	MaxUploadBytes   int64
	MaxTextBytes     int64
	MaxArchiveFiles  int
	MaxExpandedBytes int64
	MaxPathBytes     int
	MaxNameBytes     int
}

func DefaultLimits() Limits {
	return Limits{
		MaxUploadBytes:   256 << 20,
		MaxTextBytes:     4 << 20,
		MaxArchiveFiles:  20_000,
		MaxExpandedBytes: 1024 << 20,
		MaxPathBytes:     1024,
		MaxNameBytes:     255,
	}
}

var (
	ErrUnsafePath         = errors.New("path escapes or violates the site root rules")
	ErrNotFound           = errors.New("path was not found")
	ErrDestinationExists  = errors.New("destination already exists")
	ErrTooLarge           = errors.New("operation exceeds configured size limits")
	ErrNotRegularFile     = errors.New("path is not a regular file")
	ErrUnsafeArchiveEntry = errors.New("archive entry is unsafe")
	ErrArchiveTooLarge    = errors.New("archive exceeds configured limits")
)

const (
	trashDirName    = ".tompanel-trash"
	tempPrefix      = ".tompanel-tmp-"
	metaFileName    = "meta.json"
	temporarySuffix = ".tompanel-partial"
)

// Kind selects what Create materialises.
type Kind int

const (
	KindFile Kind = iota
	KindDirectory
)

// Entry describes one directory listing row.
type Entry struct {
	Name    string    `json:"name"`
	IsDir   bool      `json:"is_dir"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"mod_time"`
}

// TrashEntry describes a recoverable deletion.
type TrashEntry struct {
	ID           string    `json:"id"`
	OriginalPath string    `json:"original_path"`
	DeletedAt    time.Time `json:"deleted_at"`
}

type trashMeta struct {
	OriginalPath string `json:"original_path"`
	DeletedAt    int64  `json:"deleted_at"`
}

// Service performs confined File Manager operations against site roots.
type Service struct {
	limits  Limits
	resolve func(siteID string) (string, error)
}

// NewService builds a Service. resolve maps a site ID to its root directory
// and must reject unsafe identifiers.
func NewService(limits Limits, resolve func(siteID string) (string, error)) *Service {
	if resolve == nil {
		panic("files.Service requires a root resolver")
	}
	return &Service{limits: limits, resolve: resolve}
}

// FixedRootResolver pins every site to the same root for tests and tools.
func FixedRootResolver(root string) func(string) (string, error) {
	return func(string) (string, error) { return root, nil }
}

// SiteRootResolver maps validated site IDs to directories under root.
func SiteRootResolver(root string) func(siteID string) (string, error) {
	return func(siteID string) (string, error) {
		if !ValidSiteID(siteID) {
			return "", ErrUnsafePath
		}
		return path.Join(root, siteID), nil
	}
}

// ValidSiteID reports whether id is a 32 character lowercase hex identifier.
func ValidSiteID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, character := range id {
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
}

func (s *Service) Limits() Limits { return s.limits }

func (s *Service) root(siteID string) (*os.Root, error) {
	base, err := s.resolve(siteID)
	if err != nil {
		return nil, err
	}
	return os.OpenRoot(base)
}

// ValidateRelative enforces the path rules shared by every operation.
func (s *Service) ValidateRelative(input string) (string, error) {
	cleaned, err := validateRelative(input, s.limits)
	if err != nil {
		return "", err
	}
	return cleaned, nil
}

func validateRelative(input string, limits Limits) (string, error) {
	if input == "" || input == "." {
		return ".", nil
	}
	if limits.MaxPathBytes > 0 && len(input) > limits.MaxPathBytes {
		return "", ErrUnsafePath
	}
	if strings.ContainsRune(input, 0) {
		return "", ErrUnsafePath
	}
	for _, r := range input {
		if r < 0x20 || r == 0x7f {
			return "", ErrUnsafePath
		}
	}
	if strings.HasPrefix(input, "/") {
		return "", ErrUnsafePath
	}
	segments := strings.Split(input, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return "", ErrUnsafePath
		}
		if limits.MaxNameBytes > 0 && len(segment) > limits.MaxNameBytes {
			return "", ErrUnsafePath
		}
	}
	return input, nil
}

func isTrashPath(rel string) bool {
	return rel == trashDirName || strings.HasPrefix(rel, trashDirName+"/")
}

func isTempPath(rel string) bool {
	segment := path.Base(rel)
	return strings.HasPrefix(segment, tempPrefix) || strings.HasSuffix(segment, temporarySuffix)
}

func (s *Service) validateOperable(rel string) (string, error) {
	cleaned, err := s.ValidateRelative(rel)
	if err != nil {
		return "", err
	}
	if cleaned != "." && (isTrashPath(cleaned) || isTempPath(cleaned)) {
		return "", ErrUnsafePath
	}
	return cleaned, nil
}

func (s *Service) List(ctx context.Context, siteID, dir string) ([]Entry, error) {
	rel, err := s.validateOperable(dir)
	if err != nil {
		return nil, err
	}
	root, err := s.root(siteID)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	handle, err := root.Open(rel)
	if err != nil {
		return nil, pathError(err)
	}
	defer handle.Close()
	directories, err := handle.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(directories))
	for _, item := range directories {
		name := item.Name()
		if name == trashDirName || isTempPath(name) {
			continue
		}
		info, err := item.Info()
		if err != nil {
			continue
		}
		entries = append(entries, Entry{
			Name: name, IsDir: item.IsDir(), Size: info.Size(),
			Mode: info.Mode().Perm().String(), ModTime: info.ModTime().UTC().Truncate(time.Second),
		})
	}
	return entries, nil
}

func (s *Service) ReadText(ctx context.Context, siteID, rel string) ([]byte, error) {
	clean, err := s.validateOperable(rel)
	if err != nil {
		return nil, err
	}
	if int64(s.limits.MaxTextBytes) == 0 {
		return nil, ErrTooLarge
	}
	root, err := s.root(siteID)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	handle, err := openRegular(root, clean)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	info, err := handle.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > int64(s.limits.MaxTextBytes) {
		return nil, ErrTooLarge
	}
	content, err := io.ReadAll(io.LimitReader(handle, int64(s.limits.MaxTextBytes)+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > int64(s.limits.MaxTextBytes) {
		return nil, ErrTooLarge
	}
	return content, nil
}

func openRegular(root *os.Root, rel string) (*os.File, error) {
	handle, err := root.Open(rel)
	if err != nil {
		return nil, pathError(err)
	}
	info, err := handle.Stat()
	if err != nil {
		handle.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		handle.Close()
		return nil, ErrNotRegularFile
	}
	return handle, nil
}

// writeTemp streams content into a temporary sibling and renames it into
// place so readers never observe partial writes.
func (s *Service) writeTemp(root *os.Root, rel string, mode fs.FileMode, reader io.Reader, budget int64) error {
	temporary, err := tempName()
	if err != nil {
		return err
	}
	handle, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(handle, &budgetedReader{reader: reader, budget: budget})
	closeErr := handle.Close()
	if copyErr == nil && written > budget {
		copyErr = ErrTooLarge
	}
	if copyErr != nil || closeErr != nil {
		_ = root.Remove(temporary)
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}
	if err := root.Rename(temporary, rel); err != nil {
		_ = root.Remove(temporary)
		return err
	}
	return nil
}

type budgetedReader struct {
	reader io.Reader
	budget int64
}

func (b *budgetedReader) Read(p []byte) (int, error) {
	if b.budget < 0 {
		return 0, ErrTooLarge
	}
	n, err := b.reader.Read(p)
	b.budget -= int64(n)
	if b.budget < 0 {
		return n, ErrTooLarge
	}
	return n, err
}

func tempName() (string, error) {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate temporary name: %w", err)
	}
	return tempPrefix + hex.EncodeToString(value[:]), nil
}

func (s *Service) WriteText(ctx context.Context, siteID, rel string, content []byte) error {
	clean, err := s.validateOperable(rel)
	if err != nil {
		return err
	}
	if int64(len(content)) > int64(s.limits.MaxTextBytes) {
		return ErrTooLarge
	}
	root, err := s.root(siteID)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := s.ensureParent(root, path.Dir(clean)); err != nil {
		return err
	}
	if info, err := root.Lstat(clean); err == nil && !info.Mode().IsRegular() {
		return ErrNotRegularFile
	}
	return s.writeTemp(root, clean, 0o644, bytes.NewReader(content), int64(s.limits.MaxTextBytes))
}

func (s *Service) Upload(ctx context.Context, siteID, rel string, reader io.Reader) error {
	clean, err := s.validateOperable(rel)
	if err != nil {
		return err
	}
	root, err := s.root(siteID)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := s.ensureParent(root, path.Dir(clean)); err != nil {
		return err
	}
	if info, err := root.Lstat(clean); err == nil && !info.Mode().IsRegular() {
		return ErrNotRegularFile
	}
	return s.writeTemp(root, clean, 0o644, reader, s.limits.MaxUploadBytes)
}

// Download returns a read handle the caller must close.
func (s *Service) Download(ctx context.Context, siteID, rel string) (*os.File, error) {
	clean, err := s.validateOperable(rel)
	if err != nil {
		return nil, err
	}
	root, err := s.root(siteID)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return openRegular(root, clean)
}

func (s *Service) Create(ctx context.Context, siteID, rel string, kind Kind) error {
	clean, err := s.validateOperable(rel)
	if err != nil {
		return err
	}
	if clean == "." {
		return ErrDestinationExists
	}
	root, err := s.root(siteID)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := s.ensureParent(root, path.Dir(clean)); err != nil {
		return err
	}
	switch kind {
	case KindDirectory:
		if err := root.Mkdir(clean, 0o755); err != nil {
			return pathError(err)
		}
		return nil
	default:
		handle, err := root.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return pathError(err)
		}
		return handle.Close()
	}
}

func (s *Service) Rename(ctx context.Context, siteID, from, to string) error {
	return s.renameWithin(ctx, siteID, from, to)
}

func (s *Service) Move(ctx context.Context, siteID, from, to string) error {
	return s.renameWithin(ctx, siteID, from, to)
}

func (s *Service) renameWithin(ctx context.Context, siteID, from, to string) error {
	source, err := s.validateOperable(from)
	if err != nil {
		return err
	}
	destination, err := s.validateOperable(to)
	if err != nil {
		return err
	}
	if source == "." || destination == "." {
		return ErrUnsafePath
	}
	root, err := s.root(siteID)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Lstat(source); err != nil {
		return pathError(err)
	}
	if _, err := root.Lstat(destination); err == nil {
		return ErrDestinationExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := s.ensureParent(root, path.Dir(destination)); err != nil {
		return err
	}
	if err := root.Rename(source, destination); err != nil {
		return pathError(err)
	}
	return nil
}

func (s *Service) Copy(ctx context.Context, siteID, from, to string) error {
	source, err := s.validateOperable(from)
	if err != nil {
		return err
	}
	destination, err := s.validateOperable(to)
	if err != nil {
		return err
	}
	if source == "." || destination == "." {
		return ErrUnsafePath
	}
	root, err := s.root(siteID)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Lstat(source); err != nil {
		return pathError(err)
	}
	if _, err := root.Lstat(destination); err == nil {
		return ErrDestinationExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := s.ensureParent(root, path.Dir(destination)); err != nil {
		return err
	}
	_, err = s.copyTree(root, source, destination, s.limits.MaxExpandedBytes)
	return err
}

func (s *Service) copyTree(root *os.Root, source, destination string, budget int64) (int64, error) {
	info, err := root.Stat(source)
	if err != nil {
		return 0, pathError(err)
	}
	if info.Mode().IsRegular() {
		if info.Size() > budget {
			return 0, ErrTooLarge
		}
		handle, err := openRegular(root, source)
		if err != nil {
			return 0, err
		}
		defer handle.Close()
		written, err := s.writeTempCounted(root, destination, handle, info.Mode().Perm())
		return written, err
	}
	if !info.IsDir() {
		return 0, ErrNotRegularFile
	}
	if err := root.MkdirAll(destination, info.Mode().Perm()); err != nil {
		return 0, err
	}
	handle, err := root.Open(source)
	if err != nil {
		return 0, err
	}
	defer handle.Close()
	children, err := handle.ReadDir(-1)
	if err != nil {
		return 0, err
	}
	var used int64
	for _, child := range children {
		if child.Name() == trashDirName || isTempPath(child.Name()) {
			continue
		}
		consumed, err := s.copyTree(root, path.Join(source, child.Name()), path.Join(destination, child.Name()), budget-used)
		used += consumed
		if err != nil {
			return used, err
		}
	}
	return used, nil
}

func (s *Service) writeTempCounted(root *os.Root, rel string, reader io.Reader, mode fs.FileMode) (int64, error) {
	temporary, err := tempName()
	if err != nil {
		return 0, err
	}
	handle, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return 0, err
	}
	written, copyErr := io.Copy(handle, reader)
	closeErr := handle.Close()
	if copyErr != nil || closeErr != nil {
		_ = root.Remove(temporary)
		if copyErr != nil {
			return written, copyErr
		}
		return written, closeErr
	}
	if err := root.Rename(temporary, rel); err != nil {
		_ = root.Remove(temporary)
		return written, err
	}
	return written, nil
}

// Trash moves a path into the per-site trash area with recovery metadata.
func (s *Service) Trash(ctx context.Context, siteID, rel string) (TrashEntry, error) {
	clean, err := s.validateOperable(rel)
	if err != nil {
		return TrashEntry{}, err
	}
	if clean == "." {
		return TrashEntry{}, ErrUnsafePath
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return TrashEntry{}, fmt.Errorf("generate trash ID: %w", err)
	}
	entryID := hex.EncodeToString(id[:])
	root, err := s.root(siteID)
	if err != nil {
		return TrashEntry{}, err
	}
	defer root.Close()
	if _, err := root.Lstat(clean); err != nil {
		return TrashEntry{}, pathError(err)
	}
	holder := path.Join(trashDirName, entryID)
	if err := root.MkdirAll(holder, 0o700); err != nil {
		return TrashEntry{}, err
	}
	destination := path.Join(holder, "payload", clean)
	if err := root.MkdirAll(path.Dir(destination), 0o700); err != nil {
		return TrashEntry{}, err
	}
	if err := root.Rename(clean, destination); err != nil {
		return TrashEntry{}, err
	}
	meta := trashMeta{OriginalPath: clean, DeletedAt: time.Now().UTC().Unix()}
	encoded, err := json.Marshal(meta)
	if err != nil {
		return TrashEntry{}, err
	}
	if err := root.WriteFile(path.Join(holder, metaFileName), encoded, 0o600); err != nil {
		return TrashEntry{}, err
	}
	return TrashEntry{ID: entryID, OriginalPath: meta.OriginalPath, DeletedAt: time.Unix(meta.DeletedAt, 0).UTC()}, nil
}

// ListTrash describes one trash entry, or every entry when id is empty.
func (s *Service) ListTrash(ctx context.Context, siteID, id string) ([]TrashEntry, error) {
	root, err := s.root(siteID)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if id != "" {
		if !ValidTrashID(id) {
			return nil, ErrUnsafePath
		}
		entry, err := readTrashMeta(root, id)
		if err != nil {
			return nil, pathError(err)
		}
		return []TrashEntry{entry}, nil
	}
	handle, err := root.Open(trashDirName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer handle.Close()
	children, err := handle.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	var entries []TrashEntry
	for _, child := range children {
		if !ValidTrashID(child.Name()) {
			continue
		}
		entry, err := readTrashMeta(root, child.Name())
		if err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func readTrashMeta(root *os.Root, id string) (TrashEntry, error) {
	encoded, err := root.ReadFile(path.Join(trashDirName, id, metaFileName))
	if err != nil {
		return TrashEntry{}, err
	}
	var meta trashMeta
	if err := json.Unmarshal(encoded, &meta); err != nil {
		return TrashEntry{}, err
	}
	return TrashEntry{ID: id, OriginalPath: meta.OriginalPath, DeletedAt: time.Unix(meta.DeletedAt, 0).UTC()}, nil
}

// RestoreTrash returns a trashed path to its original location, or to dest
// when dest is a non-empty relative path.
func (s *Service) RestoreTrash(ctx context.Context, siteID, id, dest string) error {
	if !ValidTrashID(id) {
		return ErrUnsafePath
	}
	destination := ""
	if dest != "" {
		clean, err := s.ValidateRelative(dest)
		if err != nil {
			return err
		}
		destination = clean
	}
	root, err := s.root(siteID)
	if err != nil {
		return err
	}
	defer root.Close()
	entry, err := readTrashMeta(root, id)
	if err != nil {
		return pathError(err)
	}
	target := entry.OriginalPath
	if destination != "" && destination != "." {
		target = destination
	}
	payload := path.Join(trashDirName, id, "payload", entry.OriginalPath)
	if _, err := root.Lstat(payload); err != nil {
		return pathError(err)
	}
	if _, err := root.Lstat(target); err == nil {
		return ErrDestinationExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := s.ensureParent(root, path.Dir(target)); err != nil {
		return err
	}
	if err := root.Rename(payload, target); err != nil {
		return err
	}
	_ = root.RemoveAll(path.Join(trashDirName, id))
	_ = root.Remove(trashDirName)
	return nil
}

// PurgeExpiredTrash removes entries older than retention.
func (s *Service) PurgeExpiredTrash(ctx context.Context, siteID string, retention time.Duration) error {
	entries, err := s.ListTrash(ctx, siteID, "")
	if err != nil {
		return err
	}
	root, err := s.root(siteID)
	if err != nil {
		return err
	}
	defer root.Close()
	cutoff := time.Now().Add(-retention)
	var failures []error
	for _, entry := range entries {
		if entry.DeletedAt.After(cutoff) {
			continue
		}
		if err := root.RemoveAll(path.Join(trashDirName, entry.ID)); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// ValidTrashID reports whether id looks like a generated trash identifier.
func ValidTrashID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, character := range id {
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
}

func (s *Service) ensureParent(root *os.Root, parent string) error {
	if parent == "." {
		return nil
	}
	if _, err := root.Lstat(parent); errors.Is(err, os.ErrNotExist) {
		return root.MkdirAll(parent, 0o755)
	} else if err != nil {
		return err
	}
	info, err := root.Lstat(parent)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return ErrNotRegularFile
	}
	return nil
}

func pathError(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if errors.Is(err, os.ErrExist) {
		return ErrDestinationExists
	}
	return err
}
