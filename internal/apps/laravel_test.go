package apps

import (
	"errors"
	"strings"
	"testing"
)

func TestLaravelRejectsRepositoryWithLocalTransport(t *testing.T) {
	err := ValidateLaravelRepo("file:///tmp/repo")
	if !errors.Is(err, ErrUnsafeGitTransport) {
		t.Fatalf("got %v, want ErrUnsafeGitTransport", err)
	}
	for _, repo := range []string{
		"/tmp/local-repo.git",
		"../relative",
		"ext::sh -c id",
		"http://insecure.example/repo.git",
		"git://git.example/repo.git",
		"ssh://user@host/repo with space",
		"",
	} {
		if err := ValidateLaravelRepo(repo); !errors.Is(err, ErrUnsafeGitTransport) {
			t.Fatalf("accepted unsafe repo %q: %v", repo, err)
		}
	}
	for _, repo := range []string{
		"https://github.com/tom/repo.git",
		"https://gitlab.com/group/project.git",
		"git@git.example:group/project.git",
	} {
		if err := ValidateLaravelRepo(repo); err != nil {
			t.Fatalf("rejected safe repo %q: %v", repo, err)
		}
	}
}

func TestLaravelBranchValidation(t *testing.T) {
	for _, branch := range []string{"main", "release-1.2", "feature/edge"} {
		if err := ValidateLaravelBranch(branch); err != nil {
			t.Fatalf("rejected safe branch %q: %v", branch, err)
		}
	}
	for _, branch := range []string{"", "-danger", "has space", "weird~char", strings.Repeat("a", 200)} {
		if err := ValidateLaravelBranch(branch); err == nil {
			t.Fatalf("accepted unsafe branch %q", branch)
		}
	}
}

func TestDeployPipelineOrdersSafety(t *testing.T) {
	input := LaravelDeployInput{
		SiteID: "0123456789abcdef0123456789abcdef", Repository: "https://github.com/tom/app.git",
		Branch: "main", HTTPSPort: 443,
	}
	steps, err := BuildLaravelDeployJob(input)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(steps, ",")
	if strings.Contains(joined, "laravel.migrate") {
		t.Fatalf("migrations ran without confirmation: %s", joined)
	}
	if !strings.Contains(joined, "laravel.optimize,laravel.health_check,laravel.activate_release") {
		t.Fatalf("pipeline order broken: %s", joined)
	}
	input.RunMigrations = true
	input.NodeBuild = true
	steps, err = BuildLaravelDeployJob(input)
	if err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(steps, ",")
	if !strings.Contains(joined, "laravel.node_build,laravel.migrate") {
		t.Fatalf("node build or migrations misplaced: %s", joined)
	}
}

func TestInstallPipelineAlwaysEndsWithWorkers(t *testing.T) {
	input := LaravelInstallInput{
		SiteID: "0123456789abcdef0123456789abcdef", Repository: "https://github.com/tom/app.git",
		Branch: "main", NodeBuild: true,
	}
	steps, err := BuildLaravelInstallJob(input)
	if err != nil {
		t.Fatal(err)
	}
	if steps[len(steps)-1] != "laravel.ensure_workers" {
		t.Fatalf("install pipeline must finish with workers: %v", steps)
	}
	if steps[0] != "laravel.checkout" || steps[2] != "laravel.node_build" {
		t.Fatalf("unexpected pipeline head: %v", steps)
	}
}

func TestGenerateReleaseIDIsSortable(t *testing.T) {
	first, second := GenerateReleaseID(100), GenerateReleaseID(200)
	if first >= second || len(first) != len(second) {
		t.Fatalf("release ids not sortable: %q %q", first, second)
	}
}
