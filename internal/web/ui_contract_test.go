package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	webassets "github.com/Dhanabhon/tom-panel/web"
)

// UI contract tests: the design system ships with the pages that depend on
// it. Each test guards one failure mode observed in review (missing tab
// styles, orphaned confirmation handlers, token drift), so a future
// template or stylesheet edit cannot silently reintroduce them.

func readEmbeddedAsset(t *testing.T, name string) string {
	t.Helper()
	content, err := fs.ReadFile(webassets.FS, name)
	if err != nil {
		t.Fatalf("read %s from embedded assets: %v", name, err)
	}
	return string(content)
}

func templateSources(t *testing.T) map[string]string {
	t.Helper()
	sources := map[string]string{}
	err := fs.WalkDir(webassets.FS, "templates", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".html") {
			return nil
		}
		content, err := fs.ReadFile(webassets.FS, path)
		if err != nil {
			return err
		}
		sources[strings.TrimPrefix(path, "templates/")] = string(content)
		return nil
	})
	if err != nil {
		t.Fatalf("walk templates: %v", err)
	}
	return sources
}

func TestAppCSSDefinesSiteTabs(t *testing.T) {
	css := readEmbeddedAsset(t, "static/app.css")
	for _, required := range []string{".tabs {", ".tab {", ".tab.active {", ".tab.active::after"} {
		if !strings.Contains(css, required) {
			t.Fatalf("site tab styles missing rule %q", required)
		}
	}
}

func TestAppCSSTokenDiscipline(t *testing.T) {
	css := readEmbeddedAsset(t, "static/app.css")
	root := strings.Index(css, ":root")
	if root < 0 {
		t.Fatal("no :root token block")
	}
	open := strings.Index(css[root:], "{")
	body := css[root+open:]
	closeIndex := strings.Index(body, "\n}")
	if closeIndex < 0 {
		t.Fatal("unterminated :root block")
	}
	afterRoot := body[closeIndex:]
	literal := regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b|(?i)\brgb\(|(?i)\bhsl\(`)
	if matches := literal.FindAllString(afterRoot, -1); len(matches) > 0 {
		t.Fatalf("colour literals outside the :root token block: %v", matches)
	}
}

func TestGlobalConfirmHandlerShipsOnEveryPage(t *testing.T) {
	appJS := readEmbeddedAsset(t, "static/app.js")
	if !strings.Contains(appJS, `closest("[data-confirm]")`) {
		t.Fatal("app.js must carry the document-level data-confirm handler")
	}
	if !strings.Contains(appJS, `, true)`) && !strings.Contains(appJS, "capture") {
		t.Fatal("data-confirm handler must bind in the capture phase")
	}
	fileJS := readEmbeddedAsset(t, "static/file-manager.js")
	if strings.Contains(fileJS, "data-confirm") {
		t.Fatal("file-manager.js must not handle data-confirm (double dialogs)")
	}
	// Every template that renders a confirm button also renders the shared
	// head, which loads app.js.
	head := templateSources(t)["layout.html"]
	if !strings.Contains(head, "/static/app.js") {
		t.Fatal("layout head must load app.js")
	}
	confirming := 0
	for name, source := range templateSources(t) {
		if strings.Contains(source, "data-confirm") && name != "layout.html" {
			confirming++
			if !strings.Contains(source, `{{template "head" .}}`) {
				t.Fatalf("%s uses data-confirm without the shared head", name)
			}
		}
	}
	if confirming == 0 {
		t.Fatal("expected at least one template with data-confirm buttons")
	}
}

func TestSubmitGuardAndPressedState(t *testing.T) {
	appJS := readEmbeddedAsset(t, "static/app.js")
	for _, required := range []string{`addEventListener("submit"`, "defaultPrevented", "event.submitter"} {
		if !strings.Contains(appJS, required) {
			t.Fatalf("double-submit guard missing %q", required)
		}
	}
	css := readEmbeddedAsset(t, "static/app.css")
	if !strings.Contains(css, ".btn:active") {
		t.Fatal("buttons have no pressed state")
	}
	btnBlock := css[strings.Index(css, ".btn {"):strings.Index(css, ".btn:hover")]
	if !strings.Contains(btnBlock, "white-space: nowrap") {
		t.Fatal("buttons may wrap onto two lines")
	}
}

func TestTabularNumeralsOnNumericSurfaces(t *testing.T) {
	css := readEmbeddedAsset(t, "static/app.css")
	if got := strings.Count(css, "font-variant-numeric: tabular-nums"); got < 4 {
		t.Fatalf("tabular-nums applied %d times, want at least 4 (tables, metrics, steps, logs)", got)
	}
}

func TestNoSideStripeAccents(t *testing.T) {
	css := readEmbeddedAsset(t, "static/app.css")
	stripe := regexp.MustCompile(`border-left:\s*\.2rem|inset \.2[0-9]*rem 0`)
	if matches := stripe.FindAllString(css, -1); len(matches) > 0 {
		t.Fatalf("side-stripe accent is banned: %v", matches)
	}
}

func TestEveryTemplateClassIsStyled(t *testing.T) {
	css := readEmbeddedAsset(t, "static/app.css")
	defined := map[string]bool{}
	for _, match := range regexp.MustCompile(`\.([a-zA-Z][a-zA-Z0-9_-]*)`).FindAllStringSubmatch(css, -1) {
		defined[match[1]] = true
	}
	expression := regexp.MustCompile(`\{\{.*?\}\}`)
	elseBranch := regexp.MustCompile(`\{\{\s*else[^}]*\}\}`)
	classAttr := regexp.MustCompile(`class="([^"]+)"`)
	for name, source := range templateSources(t) {
		// Conditional class alternatives ("good{{else}}bad") must become
		// separate candidate tokens, not one concatenated string.
		rendered := elseBranch.ReplaceAllString(source, " ")
		rendered = expression.ReplaceAllString(rendered, "")
		for _, match := range classAttr.FindAllStringSubmatch(rendered, -1) {
			for _, class := range strings.Fields(match[1]) {
				if !defined[class] {
					t.Errorf("%s uses class %q with no rule in app.css", name, class)
				}
			}
		}
	}
}
