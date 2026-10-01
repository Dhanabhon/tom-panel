package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/backups"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/sites"
)

type backupHarness struct {
	handler     http.Handler
	session     auth.Session
	authService *auth.Service
	backups     *backups.Service
	deleter     *sites.DeleteProvisioner
	manager     *jobs.Manager
	site        sites.Site
}

func newBackupHarness(t *testing.T) *backupHarness {
	t.Helper()
	database, authService, manager, recoveryCode := newDashboardRuntime(t)
	repository := sites.NewRepository(database)
	site, err := repository.Create(context.Background(), sites.CreateInput{
		Kind: sites.KindPHP, PrimaryDomain: "backup.example.com", HTTPPort: 80, HTTPSPort: 443, PHPVersion: "8.3",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.SetState(context.Background(), site.ID, sites.StateActive); err != nil {
		t.Fatal(err)
	}
	backupService := backups.NewService(database, func(_ context.Context, operation string, _, output any) error {
		switch operation {
		case "backup.disk_guard":
			if target, ok := output.(*backups.DiskState); ok {
				*target = backups.DiskState{Total: 80 << 30, Used: 20 << 30, Free: 60 << 30}
			}
		case "backup.archive":
			if target, ok := output.(interface{ Set(path string, size int64, sha string) }); ok {
				_ = target
			}
			if target, ok := output.(*struct {
				Path   string `json:"path"`
				Size   int64  `json:"size"`
				SHA256 string `json:"sha256"`
			}); ok {
				target.Path, target.Size, target.SHA256 = "/var/backups/tompanel/x/files-1.tar.gz", 120, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}
		}
		return nil
	})
	deleter := sites.NewDeleteProvisioner(database, repository, func(context.Context, string, any, any) error { return nil }, nil)
	if err := deleter.Register(manager); err != nil {
		t.Fatal(err)
	}
	handlers, err := NewBackupHandlers(authService, repository, backupService, deleter, manager, "server-1")
	if err != nil {
		t.Fatal(err)
	}
	return &backupHarness{
		handler: handlers.Handler(), session: loginDashboardUser(t, authService, recoveryCode),
		authService: authService, backups: backupService, deleter: deleter, manager: manager, site: site,
	}
}

func (h *backupHarness) stepUp(t *testing.T) {
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

func (h *backupHarness) post(path, values string) *httptest.ResponseRecorder {
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

func (h *backupHarness) get(path string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "https://panel.example"+path, nil)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: h.session.ID})
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	return recorder
}

func TestBackupsPageShowsEmptyStateAndDangerZone(t *testing.T) {
	harness := newBackupHarness(t)
	recorder := harness.get("/sites/" + harness.site.ID + "/backups")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "No backups yet") || !strings.Contains(body, "Danger zone") {
		t.Fatal("empty state or danger zone missing")
	}
	if !strings.Contains(body, harness.site.PrimaryDomain) {
		t.Fatal("exact-name confirmation hint missing")
	}
}

func TestDeleteRequiresNameAndTOTP(t *testing.T) {
	harness := newBackupHarness(t)
	path := "/sites/" + harness.site.ID + "/delete"
	// Without step-up the request is refused outright.
	if recorder := harness.post(path, "confirm_name="+harness.site.PrimaryDomain+"&release_dns=on"); recorder.Code != http.StatusForbidden {
		t.Fatalf("pre-step-up status = %d", recorder.Code)
	}
	harness.stepUp(t)
	// Wrong exact name is refused.
	recorder := harness.post(path, "confirm_name=wrong.example.com&release_dns=on")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "exact primary domain") {
		t.Fatalf("wrong name accepted: status=%d", recorder.Code)
	}
	// Missing DNS decision is refused.
	recorder = harness.post(path, "confirm_name="+harness.site.PrimaryDomain)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "DNS records") {
		t.Fatalf("missing dns decision accepted: status=%d", recorder.Code)
	}
	// The correct form queues the deletion job.
	recorder = harness.post(path, "confirm_name="+harness.site.PrimaryDomain+"&release_dns=on")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	queued, err := harness.manager.List(context.Background(), 10)
	if err != nil || len(queued) != 1 || queued[0].Kind != sites.DeleteJobKind {
		t.Fatalf("delete job not queued: %+v %v", queued, err)
	}
}

func TestBackupCreateStoresManualBackup(t *testing.T) {
	harness := newBackupHarness(t)
	recorder := harness.post("/sites/"+harness.site.ID+"/backups/create", "")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	items, err := harness.backups.List(context.Background(), harness.site.ID)
	if err != nil || len(items) != 1 || items[0].Kind != backups.KindManual || !items[0].Protected {
		t.Fatalf("manual backup missing: %+v %v", items, err)
	}
}
