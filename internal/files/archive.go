package files

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// gzipMagic identifies gzip-compressed archives so plain tar and tar.gz can
// share one extraction path.
var gzipMagic = []byte{0x1f, 0x8b}

// Extract validates every archive entry before writing it into root.
// Only regular files and directories are permitted; symlink, hardlink,
// device, and FIFO entries are rejected together with absolute, traversal,
// and trash-destination names.
func Extract(root *os.Root, archive io.Reader, limits Limits) error {
	if limits.MaxArchiveFiles <= 0 || limits.MaxExpandedBytes <= 0 {
		return ErrArchiveTooLarge
	}
	reader := archive
	prefix := make([]byte, 2)
	read, err := io.ReadFull(reader, prefix)
	if err == nil && string(prefix) == string(gzipMagic) {
		decompressor, err := gzip.NewReader(io.MultiReader(strings.NewReader(string(prefix)), reader))
		if err != nil {
			return fmt.Errorf("open gzip archive: %w", err)
		}
		defer decompressor.Close()
		reader = decompressor
	} else if err == nil {
		reader = io.MultiReader(strings.NewReader(string(prefix)), reader)
	} else if read > 0 {
		reader = io.MultiReader(strings.NewReader(string(prefix[:read])), reader)
	}

	tarReader := tar.NewReader(reader)
	files := 0
	var expanded int64
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read archive entry: %w", err)
		}
		if header.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		name, err := archiveEntryName(header.Name, limits)
		if err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o755); err != nil {
				return fmt.Errorf("create archive directory %q: %w", name, err)
			}
		case tar.TypeReg:
			files++
			if files > limits.MaxArchiveFiles {
				return ErrArchiveTooLarge
			}
			expanded += header.Size
			if expanded > limits.MaxExpandedBytes {
				return ErrArchiveTooLarge
			}
			if parent := path.Dir(name); parent != "." {
				if err := root.MkdirAll(parent, 0o755); err != nil {
					return fmt.Errorf("create archive directory %q: %w", parent, err)
				}
			}
			if err := extractFile(root, tarReader, header, name); err != nil {
				return err
			}
		default:
			return ErrUnsafeArchiveEntry
		}
	}
}

func extractFile(root *os.Root, reader io.Reader, header *tar.Header, name string) error {
	if header.Size < 0 {
		return ErrUnsafeArchiveEntry
	}
	handle, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create archive file %q: %w", name, err)
	}
	written, copyErr := io.CopyN(handle, reader, header.Size)
	closeErr := handle.Close()
	if copyErr != nil {
		_ = root.Remove(name)
		if errors.Is(copyErr, io.EOF) {
			return fmt.Errorf("archive entry %q is truncated", name)
		}
		return fmt.Errorf("extract %q: %w", name, copyErr)
	}
	if written != header.Size {
		_ = root.Remove(name)
		return fmt.Errorf("archive entry %q has a mismatched size", name)
	}
	return closeErr
}

func archiveEntryName(name string, limits Limits) (string, error) {
	trimmed := strings.TrimSuffix(name, "/")
	cleaned, err := validateRelative(trimmed, limits)
	if err != nil || cleaned == "." {
		return "", ErrUnsafeArchiveEntry
	}
	if isTrashPath(cleaned) || isTempPath(cleaned) {
		return "", ErrUnsafeArchiveEntry
	}
	return cleaned, nil
}

// CleanArchiveSources validates archive source paths against the limits.
func CleanArchiveSources(sources []string, limits Limits) ([]string, error) {
	if len(sources) == 0 || len(sources) > limits.MaxArchiveFiles {
		return nil, ErrArchiveTooLarge
	}
	cleaned := make([]string, 0, len(sources))
	for _, source := range sources {
		clean, err := validateRelative(source, limits)
		if err != nil {
			return nil, ErrUnsafePath
		}
		if isTrashPath(clean) || isTempPath(clean) {
			return nil, ErrUnsafePath
		}
		cleaned = append(cleaned, clean)
	}
	return cleaned, nil
}

// ArchiveTo streams a tar.gz of the selected paths into an external writer
// so callers can direct the body outside the archive root.
func ArchiveTo(root *os.Root, sources []string, output io.Writer, limits Limits) error {
	cleaned, err := CleanArchiveSources(sources, limits)
	if err != nil {
		return err
	}
	entries, err := collectArchiveEntries(root, cleaned, limits)
	if err != nil {
		return err
	}
	return writeArchive(root, output, entries)
}

// Archive writes a tar.gz of the selected paths into destination inside root.
func Archive(root *os.Root, sources []string, destination string, limits Limits) error {
	if len(sources) == 0 || len(sources) > limits.MaxArchiveFiles {
		return ErrArchiveTooLarge
	}
	cleanedDestination, err := validateRelative(destination, limits)
	if err != nil {
		return ErrUnsafePath
	}
	if isTrashPath(cleanedDestination) || isTempPath(cleanedDestination) {
		return ErrUnsafePath
	}
	cleaned := make([]string, 0, len(sources))
	for _, source := range sources {
		clean, err := validateRelative(source, limits)
		if err != nil {
			return ErrUnsafePath
		}
		if isTrashPath(clean) || isTempPath(clean) {
			return ErrUnsafePath
		}
		cleaned = append(cleaned, clean)
	}

	entries, err := collectArchiveEntries(root, cleaned, limits)
	if err != nil {
		return err
	}
	temporary, err := tempName()
	if err != nil {
		return err
	}
	handle, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	writeErr := writeArchive(root, handle, entries)
	closeErr := handle.Close()
	if writeErr != nil || closeErr != nil {
		_ = root.Remove(temporary)
		if writeErr != nil {
			return writeErr
		}
		return closeErr
	}
	if err := root.Rename(temporary, cleanedDestination); err != nil {
		_ = root.Remove(temporary)
		return pathError(err)
	}
	return nil
}

type archiveEntry struct {
	name  string
	isDir bool
	size  int64
	mode  os.FileMode
}

func collectArchiveEntries(root *os.Root, sources []string, limits Limits) ([]archiveEntry, error) {
	var entries []archiveEntry
	seen := make(map[string]bool)
	var total int64
	for _, source := range sources {
		info, err := root.Stat(source)
		if err != nil {
			return nil, pathError(err)
		}
		if err := appendArchiveEntry(&entries, seen, &total, source, info, limits); err != nil {
			return nil, err
		}
		if info.IsDir() {
			if err := walkArchiveTree(root, source, &entries, seen, &total, limits); err != nil {
				return nil, err
			}
		}
	}
	return entries, nil
}

func walkArchiveTree(root *os.Root, dir string, entries *[]archiveEntry, seen map[string]bool, total *int64, limits Limits) error {
	handle, err := root.Open(dir)
	if err != nil {
		return pathError(err)
	}
	defer handle.Close()
	children, err := handle.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, child := range children {
		name := child.Name()
		if name == trashDirName || isTempPath(name) {
			continue
		}
		relative := path.Join(dir, name)
		info, err := root.Stat(relative)
		if err != nil {
			return pathError(err)
		}
		if err := appendArchiveEntry(entries, seen, total, relative, info, limits); err != nil {
			return err
		}
		if info.IsDir() {
			if err := walkArchiveTree(root, relative, entries, seen, total, limits); err != nil {
				return err
			}
		}
	}
	return nil
}

func appendArchiveEntry(entries *[]archiveEntry, seen map[string]bool, total *int64, name string, info os.FileInfo, limits Limits) error {
	if seen[name] {
		return nil
	}
	if len(*entries) >= limits.MaxArchiveFiles {
		return ErrArchiveTooLarge
	}
	if info.Mode().IsRegular() {
		*total += info.Size()
		if *total > limits.MaxExpandedBytes {
			return ErrArchiveTooLarge
		}
	}
	seen[name] = true
	*entries = append(*entries, archiveEntry{name: name, isDir: info.IsDir(), size: info.Size(), mode: info.Mode().Perm()})
	return nil
}

func writeArchive(root *os.Root, output io.Writer, entries []archiveEntry) error {
	compressor := gzip.NewWriter(output)
	tarWriter := tar.NewWriter(compressor)
	for _, entry := range entries {
		name := entry.name
		header := &tar.Header{Name: name, Mode: int64(entry.mode.Perm())}
		if entry.isDir {
			header.Name = name + "/"
			header.Typeflag = tar.TypeDir
			if err := tarWriter.WriteHeader(header); err != nil {
				return err
			}
			continue
		}
		header.Typeflag = tar.TypeReg
		header.Size = entry.size
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		handle, err := root.Open(entry.name)
		if err != nil {
			return pathError(err)
		}
		_, copyErr := io.Copy(tarWriter, handle)
		handle.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	if err := tarWriter.Close(); err != nil {
		return err
	}
	return compressor.Close()
}

// Extract decompresses archive into destDir inside the site root. The
// destination is rolled back when it did not exist before extraction.
func (s *Service) Extract(ctx context.Context, siteID string, archive io.Reader, destDir string, limits Limits) error {
	dest, err := s.ValidateRelative(destDir)
	if err != nil {
		return err
	}
	if isTrashPath(dest) || isTempPath(dest) {
		return ErrUnsafePath
	}
	root, err := s.root(siteID)
	if err != nil {
		return err
	}
	defer root.Close()
	created := false
	if dest != "." {
		if _, err := root.Lstat(dest); errors.Is(err, os.ErrNotExist) {
			created = true
		} else if err != nil {
			return err
		}
	}
	sub := root
	if dest != "." {
		if err := root.MkdirAll(dest, 0o755); err != nil {
			return err
		}
		if sub, err = root.OpenRoot(dest); err != nil {
			return err
		}
		defer sub.Close()
	}
	if err := Extract(sub, archive, limits); err != nil {
		if created {
			_ = root.RemoveAll(dest)
		}
		return err
	}
	return nil
}

// Archive writes a tar.gz of sources into destination inside the site root.
func (s *Service) Archive(ctx context.Context, siteID string, sources []string, destination string) error {
	root, err := s.root(siteID)
	if err != nil {
		return err
	}
	defer root.Close()
	return Archive(root, sources, destination, s.limits)
}
