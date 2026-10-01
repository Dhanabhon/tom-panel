package web

import (
	"context"
	"net/url"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/operations"
)

func newUpdateHarness(t *testing.T) (*updateWebHarness, ed25519.PublicKey) {
	t.Helper()
	database, authService, manager, recoveryCode := newDashboardRuntime(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	updater := operations.NewUpdater(database, func(context.Context, string, any, any) error { return nil }, public)
	if err := updater.Register(manager); err != nil {
		t.Fatal(err)
	}
	handlers, err := NewUpdateHandlers(authService, updater, manager)
	if err != nil {
		t.Fatal(err)
	}
	session := loginDashboardUser(t, authService, recoveryCode)
	return &updateWebHarness{
		handler: handlers.Handler(), session: session, authService: authService, manager: manager, private: private,
	}, public
}

type updateWebHarness struct {
	handler     http.Handler
	session     auth.Session
	authService *auth.Service
	manager     *jobs.Manager
	private     ed25519.PrivateKey
}

func (h *updateWebHarness) stepUp(t *testing.T) {
	t.Helper()
	enrollment, err := h.authService.ResetTOTP(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	h.session = loginDashboardUser(t, h.authService, enrollment.RecoveryCodes[0])
	code := webTOTPCode(enrollment.TOTPSecret, time.Unix(1_800_000_000, 0))
	if err := h.authService.StepUp(context.Background(), h.session.ID, "correct horse battery staple", code); err != nil {
		t.Fatal(err)
	}
}

func (h *updateWebHarness) post(path, values string) *httptest.ResponseRecorder {
	values += "&csrf_token=" + h.session.CSRFToken
	request := httptest.NewRequest(http.MethodPost, "https://panel.example"+path, strings.NewReader(values))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://panel.example")
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: h.session.ID})
	request.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: h.session.CSRFToken})
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	return recorder
}

func signedManifest(harness *updateWebHarness, version, sha string) operations.ReleaseManifest {
	manifest := operations.ReleaseManifest{
		Version: version, SHA256: sha, URL: "https://releases.example/tompanel-" + version + ".deb",
	}
	signature := ed25519.Sign(harness.private, []byte(version+"\n"+sha))
	manifest.Signature = base64.StdEncoding.EncodeToString(signature)
	return manifest
}

func TestTomPanelUpdateQueuesOnlySignedReleases(t *testing.T) {
	harness, _ := newUpdateHarness(t)
	if recorder := harness.post("/updates/tompanel", "version=1.2.0&sha256=x&url=https://x&signature=y"); recorder.Code != http.StatusForbidden {
		t.Fatalf("pre-step-up status = %d", recorder.Code)
	}
	harness.stepUp(t)
	manifest := signedManifest(harness, "1.2.0", strings.Repeat("ab", 32))
	form := "version=" + manifest.Version + "&sha256=" + manifest.SHA256 + "&url=" + url.QueryEscape(manifest.URL) + "&signature=" + url.QueryEscape(manifest.Signature)
	recorder := harness.post("/updates/tompanel", form)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	queued, err := harness.manager.List(context.Background(), 10)
	if err != nil || len(queued) != 1 || queued[0].Kind != operations.TomPanelUpdateJobKind {
		t.Fatalf("update job not queued: %+v %v", queued, err)
	}
	recorder = harness.post("/updates/tompanel", "version=9.9.9&sha256="+strings.Repeat("ab", 32)+"&url=https://x&signature="+manifest.Signature)
	if recorder.Code != http.StatusSeeOther && !strings.Contains(recorder.Header().Get("Location"), "rejected") {
		t.Fatalf("unsigned update accepted: %d %s", recorder.Code, recorder.Header().Get("Location"))
	}
}

func TestPackageUpdateRequiresConfirmation(t *testing.T) {
	harness, _ := newUpdateHarness(t)
	harness.stepUp(t)
	recorder := harness.post("/updates/packages", "packages=nginx-core")
	if !strings.Contains(recorder.Header().Get("Location"), "rejected") {
		t.Fatalf("unconfirmed packages accepted: %s", recorder.Header().Get("Location"))
	}
	recorder = harness.post("/updates/packages", "packages=nginx-core&confirmed=on")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", recorder.Code)
	}
	queued, _ := harness.manager.List(context.Background(), 10)
	if len(queued) != 1 || queued[0].Kind != operations.PackageJobKind {
		t.Fatalf("package job not queued: %+v", queued)
	}
}

func TestToolUpdateRequiresConfirmation(t *testing.T) {
	harness, _ := newUpdateHarness(t)
	harness.stepUp(t)
	recorder := harness.post("/updates/tools", "tool=wpcli&version=2.3.0&sha256="+strings.Repeat("cd", 32))
	if !strings.Contains(recorder.Header().Get("Location"), "rejected") {
		t.Fatalf("unconfirmed tool accepted: %s", recorder.Header().Get("Location"))
	}
	recorder = harness.post("/updates/tools", "tool=wpcli&version=2.3.0&sha256="+strings.Repeat("cd", 32)+"&confirmed=on")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", recorder.Code)
	}
}
