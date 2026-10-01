package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/files"
	"github.com/Dhanabhon/tom-panel/internal/sites"
)

func newFileRuntime(t *testing.T) (*fileTestHarness, auth.Session) {
	t.Helper()
	database, authService, _, recoveryCode := newDashboardRuntime(t)
	repository := sites.NewRepository(database)
	site, err := repository.Create(context.Background(), sites.CreateInput{
		Kind: sites.KindStatic, PrimaryDomain: "files.example.com", HTTPPort: 80, HTTPSPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	service := files.NewService(files.DefaultLimits(), files.FixedRootResolver(root))
	access := files.NewAccessService(database, func(context.Context, string, any, any) error {
		return nil
	})
	handlers, err := NewFileHandlers(authService, repository, service, access, "server-1")
	if err != nil {
		t.Fatal(err)
	}
	session := loginDashboardUser(t, authService, recoveryCode)
	return &fileTestHarness{
		handler: handlers.Handler(), session: session, service: service, access: access,
		authService: authService, site: site, root: root, recoveryCode: recoveryCode,
	}, session
}

type fileTestHarness struct {
	handler      http.Handler
	session      auth.Session
	service      *files.Service
	access       *files.AccessService
	authService  *auth.Service
	site         sites.Site
	root         string
	recoveryCode string
}

func (h *fileTestHarness) get(path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "https://panel.example"+path, nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: h.session.ID})
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, req)
	return recorder
}

func (h *fileTestHarness) post(path, values string) *httptest.ResponseRecorder {
	values += "&csrf_token=" + h.session.CSRFToken
	req := httptest.NewRequest(http.MethodPost, "https://panel.example"+path, strings.NewReader(values))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://panel.example")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: h.session.ID})
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: h.session.CSRFToken})
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, req)
	return recorder
}

func (h *fileTestHarness) postMultipart(path, fileField, filename string, content []byte, extra url.Values) *httptest.ResponseRecorder {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile(fileField, filename)
	if err != nil {
		panic(err)
	}
	if _, err := part.Write(content); err != nil {
		panic(err)
	}
	for name, values := range extra {
		for _, value := range values {
			_ = writer.WriteField(name, value)
		}
	}
	_ = writer.WriteField("csrf_token", h.session.CSRFToken)
	if err := writer.Close(); err != nil {
		panic(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://panel.example"+path, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Origin", "https://panel.example")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: h.session.ID})
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: h.session.CSRFToken})
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, req)
	return recorder
}

func TestFilePageListsEntriesAndHidesTrash(t *testing.T) {
	harness, _ := newFileRuntime(t)
	if err := os.WriteFile(filepath.Join(harness.root, "index.html"), []byte("<html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	recorder := harness.get("/sites/" + harness.site.ID + "/files")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "index.html") || !strings.Contains(body, "Files &amp; Access") {
		t.Fatalf("listing missing: %s", body)
	}
	if strings.Contains(body, ".tompanel-trash") {
		t.Fatal("trash directory leaked into listing")
	}
}

func TestFileHandlerRejectsTraversalOverHTTP(t *testing.T) {
	harness, _ := newFileRuntime(t)
	if recorder := harness.get("/sites/" + harness.site.ID + "/files/download?path=" + url.QueryEscape("../../etc/passwd")); recorder.Code != http.StatusBadRequest {
		t.Fatalf("download traversal status = %d", recorder.Code)
	}
	if recorder := harness.post("/sites/"+harness.site.ID+"/files/save", "path=../evil.txt&content=no"); recorder.Code != http.StatusBadRequest {
		t.Fatalf("save traversal status = %d", recorder.Code)
	}
	if _, err := os.Stat(filepath.Join(harness.root, "..", "evil.txt")); err == nil {
		t.Fatal("traversal wrote outside the site root")
	}
}

func TestFileUploadConfinesTraversalFilename(t *testing.T) {
	harness, _ := newFileRuntime(t)
	// Go's multipart reader reduces the name to its basename; the result must
	// stay inside the site root no matter what the client claimed.
	recorder := harness.postMultipart("/sites/"+harness.site.ID+"/files/upload", "file", "../../evil.sh", []byte("x"), url.Values{"path": {"."}})
	if recorder.Code != http.StatusSeeOther && recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if _, err := os.Stat(filepath.Join(harness.root, "evil.sh")); recorder.Code == http.StatusSeeOther && err != nil {
		t.Fatalf("confined upload missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(harness.root, "..", "evil.sh")); err == nil {
		t.Fatal("upload escaped the site root")
	}
}

func TestFileTrashRestoreFlowOverHTTP(t *testing.T) {
	harness, _ := newFileRuntime(t)
	if err := os.WriteFile(filepath.Join(harness.root, "draft.txt"), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	recorder := harness.post("/sites/"+harness.site.ID+"/files/trash", "path=draft.txt")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("trash status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if _, err := os.Stat(filepath.Join(harness.root, "draft.txt")); !os.IsNotExist(err) {
		t.Fatal("file survived trash")
	}
	trash, err := harness.service.ListTrash(context.Background(), harness.site.ID, "")
	if err != nil || len(trash) != 1 {
		t.Fatalf("trash entries: %+v %v", trash, err)
	}
	recorder = harness.post("/sites/"+harness.site.ID+"/files/trash/restore", "id="+trash[0].ID)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("restore status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	got, err := os.ReadFile(filepath.Join(harness.root, "draft.txt"))
	if err != nil || string(got) != "v1" {
		t.Fatalf("restore mismatch: %q %v", got, err)
	}
}

func TestFileExtractRejectsSymlinkArchiveOverHTTP(t *testing.T) {
	harness, _ := newFileRuntime(t)
	var archive bytes.Buffer
	// tar with a single symlink entry pointing outside the root.
	archive.WriteString("placeholder-for-binary-tar")
	recorder := harness.postMultipart("/sites/"+harness.site.ID+"/files/extract", "file", "evil.tar.gz", archive.Bytes(), url.Values{"path": {"."}})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestSFTPRotatePasswordRequiresStepUp(t *testing.T) {
	harness, _ := newFileRuntime(t)
	path := "/sites/" + harness.site.ID + "/access/sftp/password"
	recorder := harness.post(path, "")
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestSFTPRotatePasswordShowsOnceAndNeverPersists(t *testing.T) {
	harness, _ := newFileRuntime(t)
	if _, err := harness.access.Enable(context.Background(), harness.site.ID, nil); err != nil {
		t.Fatal(err)
	}
	enrollment, err := harness.authService.ResetTOTP(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	// ResetTOTP revokes every session, so sign in again before stepping up.
	harness.session = loginDashboardUser(t, harness.authService, enrollment.RecoveryCodes[0])
	code := webTOTPCode(enrollment.TOTPSecret, time.Unix(1_800_000_000, 0))
	if err := harness.authService.StepUp(context.Background(), harness.session.ID, "correct horse battery staple", code); err != nil {
		t.Fatal(err)
	}
	recorder := harness.post("/sites/"+harness.site.ID+"/access/sftp/password", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if cache := recorder.Header().Get("Cache-Control"); cache != "no-store" {
		t.Fatalf("Cache-Control = %q", cache)
	}
	body := recorder.Body.String()
	start := strings.Index(body, "data-one-time-password>")
	if start < 0 {
		t.Fatal("one-time password marker missing")
	}
	rest := body[start+len("data-one-time-password>"):]
	end := strings.Index(rest, "<")
	if end < 16 {
		t.Fatalf("password not rendered: %q", rest)
	}
	shown := rest[:end]
	if strings.Count(body, shown) != 1 {
		t.Fatal("password rendered more than once")
	}
	account, _, err := harness.access.Get(context.Background(), harness.site.ID)
	if err != nil || !account.PasswordSet {
		t.Fatalf("password state missing: %+v %v", account, err)
	}
}

func TestSFTPPageShowsAccountState(t *testing.T) {
	harness, _ := newFileRuntime(t)
	if _, err := harness.access.Enable(context.Background(), harness.site.ID, nil); err != nil {
		t.Fatal(err)
	}
	recorder := harness.get("/sites/" + harness.site.ID + "/files")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "tp_"+harness.site.ID[:16]) {
		t.Fatal("account username missing from page")
	}
}

func TestFileOperationsRequireAuthentication(t *testing.T) {
	harness, _ := newFileRuntime(t)
	req := httptest.NewRequest(http.MethodGet, "https://panel.example/sites/"+harness.site.ID+"/files", nil)
	recorder := httptest.NewRecorder()
	harness.handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func webTOTPCode(secret string, at time.Time) string {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, raw)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%06d", value)
}
