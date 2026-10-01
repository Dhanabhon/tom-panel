package files

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func maliciousTarWithSymlink(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.WriteHeader(&tar.Header{Name: "evil", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeader(&tar.Header{Name: "ok.txt", Typeflag: tar.TypeReg, Size: 2, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func tarBytes(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for name, content := range entries {
		if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(content)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestExtractRejectsSymlinkEntry(t *testing.T) {
	svc, base := testRoot(t)
	err := svc.Extract(context.Background(), "test", bytes.NewReader(maliciousTarWithSymlink(t)), "out", Limits{MaxArchiveFiles: 100, MaxExpandedBytes: 1 << 20})
	if !errors.Is(err, ErrUnsafeArchiveEntry) {
		t.Fatalf("got %v, want ErrUnsafeArchiveEntry", err)
	}
	if _, err := os.Stat(filepath.Join(base, "out")); !os.IsNotExist(err) {
		t.Fatal("extraction left partial output after unsafe entry")
	}
}

func TestExtractRejectsTraversalEntry(t *testing.T) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.WriteHeader(&tar.Header{Name: "../../escape.txt", Typeflag: tar.TypeReg, Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	svc, _ := testRoot(t)
	err := svc.Extract(context.Background(), "test", bytes.NewReader(buffer.Bytes()), "out", Limits{MaxArchiveFiles: 10, MaxExpandedBytes: 1 << 20})
	if !errors.Is(err, ErrUnsafeArchiveEntry) {
		t.Fatalf("got %v, want ErrUnsafeArchiveEntry", err)
	}
}

func TestExtractEnforcesCountAndSizeGuards(t *testing.T) {
	svc, _ := testRoot(t)
	many := tarBytes(t, map[string]string{"a": "1", "b": "2", "c": "3"})
	err := svc.Extract(context.Background(), "test", bytes.NewReader(many), "out", Limits{MaxArchiveFiles: 2, MaxExpandedBytes: 1 << 20})
	if !errors.Is(err, ErrArchiveTooLarge) {
		t.Fatalf("file-count guard: got %v, want ErrArchiveTooLarge", err)
	}
	big := tarBytes(t, map[string]string{"a": string(bytes.Repeat([]byte("z"), 32))})
	err = svc.Extract(context.Background(), "test", bytes.NewReader(big), "out", Limits{MaxArchiveFiles: 2, MaxExpandedBytes: 16})
	if !errors.Is(err, ErrArchiveTooLarge) {
		t.Fatalf("expanded-size guard: got %v, want ErrArchiveTooLarge", err)
	}
}

func TestExtractHandlesGzipAndStripsModes(t *testing.T) {
	svc, base := testRoot(t)
	var gzipped bytes.Buffer
	compressor := gzip.NewWriter(&gzipped)
	raw := tarBytes(t, map[string]string{"nested/deep.txt": "payload"})
	if _, err := compressor.Write(raw); err != nil {
		t.Fatal(err)
	}
	compressor.Close()
	err := svc.Extract(context.Background(), "test", bytes.NewReader(gzipped.Bytes()), "out", Limits{MaxArchiveFiles: 10, MaxExpandedBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(base, "out/nested/deep.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("extracted file mode is %v, want 0644", info.Mode().Perm())
	}
}

func TestExtractDetectsSizeLies(t *testing.T) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.WriteHeader(&tar.Header{Name: "lie.txt", Typeflag: tar.TypeReg, Size: 8, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("four")); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	svc, _ := testRoot(t)
	err := svc.Extract(context.Background(), "test", bytes.NewReader(buffer.Bytes()), "out", Limits{MaxArchiveFiles: 10, MaxExpandedBytes: 1 << 20})
	if err == nil {
		t.Fatal("truncated tar member accepted")
	}
}

func TestArchiveRoundTripsSelectedPaths(t *testing.T) {
	svc, base := testRoot(t)
	writeTree(t, base, "site/index.html", "<html>")
	writeTree(t, base, "site/about.html", "<p>")
	writeTree(t, base, "ignore.txt", "no")
	ctx := context.Background()
	if err := svc.Archive(ctx, "test", []string{"site"}, "backup.tar.gz"); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(filepath.Join(base, "backup.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if len(archive) == 0 {
		t.Fatal("archive is empty")
	}
	if err := svc.Extract(ctx, "test", bytes.NewReader(archive), "restored", DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(base, "restored/site/index.html"))
	if err != nil || string(got) != "<html>" {
		t.Fatalf("round-trip mismatch: %q %v", got, err)
	}
}

func TestArchiveRejectsTraversalSources(t *testing.T) {
	svc, _ := testRoot(t)
	if err := svc.Archive(context.Background(), "test", []string{"../etc"}, "out.tar.gz"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("got %v, want ErrUnsafePath", err)
	}
}

func TestLargeRandomInputIsBounded(t *testing.T) {
	svc, _ := testRoot(t)
	big := make([]byte, 1<<20)
	_, _ = rand.Read(big)
	err := svc.Extract(context.Background(), "test", bytes.NewReader(big[:64]), "out", Limits{MaxArchiveFiles: 10, MaxExpandedBytes: 1 << 20})
	if err == nil {
		t.Fatal("garbage input accepted as archive")
	}
}
