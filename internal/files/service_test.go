package files

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validPath = "00000000000000000000000000000000"

func testRoot(t *testing.T) (*Service, string) {
	t.Helper()
	base := t.TempDir()
	svc := NewService(DefaultLimits(), FixedRootResolver(base))
	return svc, base
}

func writeTree(t *testing.T, base, rel, content string) {
	t.Helper()
	path := filepath.Join(base, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsParentTraversal(t *testing.T) {
	svc, _ := testRoot(t)
	ctx := context.Background()
	for _, rel := range []string{"../escape.txt", "dir/../../escape.txt", "ok/../../../etc/passwd"} {
		if _, err := svc.ReadText(ctx, "test", rel); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("read %q: got %v, want ErrUnsafePath", rel, err)
		}
	}
	if err := svc.WriteText(ctx, "test", "../escape.txt", []byte("no")); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("write traversal: got %v, want ErrUnsafePath", err)
	}
}

func TestOpenRejectsAbsoluteAndControlPaths(t *testing.T) {
	svc, _ := testRoot(t)
	ctx := context.Background()
	for _, rel := range []string{"/etc/passwd", "file\x00.txt", "bad\x1bname"} {
		if _, err := svc.ReadText(ctx, "test", rel); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("read %q: got %v, want ErrUnsafePath", rel, err)
		}
	}
}

func TestListReportsEntries(t *testing.T) {
	svc, base := testRoot(t)
	writeTree(t, base, "index.html", "hello")
	writeTree(t, base, "assets/app.css", "body{}")
	entries, err := svc.List(context.Background(), "test", ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	var sawDir, sawFile bool
	for _, entry := range entries {
		if entry.Name == "assets" && entry.IsDir {
			sawDir = true
		}
		if entry.Name == "index.html" && !entry.IsDir && entry.Size == 5 {
			sawFile = true
		}
	}
	if !sawDir || !sawFile {
		t.Fatalf("listing missed entries: %+v", entries)
	}
}

func TestWriteTextIsAtomicAndBounded(t *testing.T) {
	svc, base := testRoot(t)
	ctx := context.Background()
	if err := svc.WriteText(ctx, "test", "notes.txt", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := svc.WriteText(ctx, "test", "notes.txt", []byte("second")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(base, "notes.txt"))
	if err != nil || string(got) != "second" {
		t.Fatalf("atomic rewrite failed: %q %v", got, err)
	}
	matches, _ := filepath.Glob(filepath.Join(base, ".tompanel-tmp-*"))
	if len(matches) != 0 {
		t.Fatalf("temporary files leaked: %v", matches)
	}
	svc.limits.MaxTextBytes = 4
	if err := svc.WriteText(ctx, "test", "notes.txt", bytes.Repeat([]byte("a"), 5)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized text: got %v, want ErrTooLarge", err)
	}
}

func TestUploadEnforcesLimitAndRejectsDeviceTargets(t *testing.T) {
	svc, base := testRoot(t)
	svc.limits.MaxUploadBytes = 8
	ctx := context.Background()
	err := svc.Upload(ctx, "test", "big.bin", bytes.NewReader(bytes.Repeat([]byte("a"), 9)))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized upload: got %v, want ErrTooLarge", err)
	}
	matches, _ := filepath.Glob(filepath.Join(base, ".tompanel-tmp-*"))
	if len(matches) != 0 {
		t.Fatalf("partial upload leaked: %v", matches)
	}
	if err := svc.Upload(ctx, "test", "ok.txt", strings.NewReader("small")); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(base, "ok.txt"))
	if string(got) != "small" {
		t.Fatalf("upload content mismatch: %q", got)
	}
}

func TestReadTextRejectsNonRegularFile(t *testing.T) {
	svc, base := testRoot(t)
	if err := os.Mkdir(filepath.Join(base, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReadText(context.Background(), "test", "sub"); !errors.Is(err, ErrNotRegularFile) {
		t.Fatalf("read directory: got %v, want ErrNotRegularFile", err)
	}
}

func TestTrashThenRestoreRecoversFile(t *testing.T) {
	svc, base := testRoot(t)
	writeTree(t, base, "docs/guide.md", "content")
	ctx := context.Background()
	entry, err := svc.Trash(ctx, "test", "docs/guide.md")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "docs/guide.md")); !os.IsNotExist(err) {
		t.Fatal("file still visible after trash")
	}
	if err := svc.RestoreTrash(ctx, "test", entry.ID, ""); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(base, "docs/guide.md"))
	if err != nil || string(got) != "content" {
		t.Fatalf("restore mismatch: %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(base, trashDirName)); !os.IsNotExist(err) {
		t.Fatal("trash directory not cleaned")
	}
}

func TestTrashOverwritesBlockedAndPurgeExpires(t *testing.T) {
	svc, base := testRoot(t)
	writeTree(t, base, "keep.txt", "v1")
	ctx := context.Background()
	entry, err := svc.Trash(ctx, "test", "keep.txt")
	if err != nil {
		t.Fatal(err)
	}
	writeTree(t, base, "keep.txt", "v2")
	if err := svc.RestoreTrash(ctx, "test", entry.ID, ""); !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("restore over existing: got %v, want ErrDestinationExists", err)
	}
	if err := svc.PurgeExpiredTrash(ctx, "test", time.Minute); err != nil {
		t.Fatal(err)
	}
	remaining, err := svc.ListTrash(ctx, "test", entry.ID)
	if err != nil || len(remaining) != 1 {
		t.Fatalf("fresh trash entry was purged early: %v %+v", err, remaining)
	}
	if err := svc.PurgeExpiredTrash(ctx, "test", -time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ListTrash(ctx, "test", entry.ID); err == nil {
		t.Fatal("expired trash entry survived purge")
	}
}

func TestCopyAndMoveStayConfined(t *testing.T) {
	svc, base := testRoot(t)
	writeTree(t, base, "a/one.txt", "1")
	writeTree(t, base, "a/two.txt", "2")
	ctx := context.Background()
	if err := svc.Copy(ctx, "test", "a", "b"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(base, "b/one.txt"))
	if err != nil || string(got) != "1" {
		t.Fatalf("copy mismatch: %q %v", got, err)
	}
	if err := svc.Move(ctx, "test", "a", "c"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "a")); !os.IsNotExist(err) {
		t.Fatal("move left the source behind")
	}
	if err := svc.Copy(ctx, "test", "a", "../escape"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("copy traversal: got %v, want ErrUnsafePath", err)
	}
}

func TestCreateRenameAndKindGuards(t *testing.T) {
	svc, base := testRoot(t)
	ctx := context.Background()
	if err := svc.Create(ctx, "test", "nested/dir", KindDirectory); err != nil {
		t.Fatal(err)
	}
	if err := svc.Create(ctx, "test", "nested/dir/file.txt", KindFile); err != nil {
		t.Fatal(err)
	}
	if err := svc.Rename(ctx, "test", "nested/dir/file.txt", "nested/dir/renamed.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "nested/dir/renamed.txt")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Create(ctx, "test", "nested/dir", KindDirectory); !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("duplicate create: got %v, want ErrDestinationExists", err)
	}
	if err := svc.Rename(ctx, "test", "nested/dir/renamed.txt", "../out"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("rename traversal: got %v, want ErrUnsafePath", err)
	}
}

func TestSiteIDResolverRejectsUnsafeIDs(t *testing.T) {
	resolve := SiteRootResolver("/srv/tompanel/sites")
	for _, id := range []string{"../evil", "ABC123", "short", "", "000000000000000000000000000000g"} {
		if _, err := resolve(id); err == nil {
			t.Fatalf("resolver accepted unsafe site ID %q", id)
		}
	}
	if _, err := resolve("00000000000000000000000000000000"); err != nil {
		t.Fatalf("resolver rejected valid site ID: %v", err)
	}
}
