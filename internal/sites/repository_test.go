package sites

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/store"
)

func openTestRepository(t *testing.T) *Repository {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o400); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(context.Background(), filepath.Join(dir, "tompanel.db"), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return NewRepository(database)
}

func TestRepositoryCreatesNormalizedSite(t *testing.T) {
	repository := openTestRepository(t)
	site, err := repository.Create(context.Background(), CreateInput{
		Kind:          KindPHP,
		PrimaryDomain: "BÜCHER.example.",
		HTTPSPort:     443,
		Public:        true,
		PHPVersion:    "8.4",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(site.ID) != 32 || site.PrimaryDomain != "xn--bcher-kva.example" || site.State != StateProvisioning {
		t.Fatalf("Create() site = %#v", site)
	}

	got, err := repository.Get(context.Background(), site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != site {
		t.Fatalf("Get() = %#v, want %#v", got, site)
	}
}

func TestRepositorySerializesEndpointClaims(t *testing.T) {
	repository := openTestRepository(t)
	start := make(chan struct{})
	errorsByCreate := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := repository.Create(context.Background(), CreateInput{
				Kind:          KindStatic,
				PrimaryDomain: "same.example.com",
				HTTPSPort:     443,
			})
			errorsByCreate <- err
		}()
	}
	close(start)
	workers.Wait()
	close(errorsByCreate)

	var succeeded, occupied int
	for err := range errorsByCreate {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrEndpointOccupied):
			occupied++
		default:
			t.Fatalf("Create() unexpected error: %v", err)
		}
	}
	if succeeded != 1 || occupied != 1 {
		t.Fatalf("concurrent creates: succeeded=%d occupied=%d", succeeded, occupied)
	}
}

func TestRepositoryRejectsInvalidStateTransitionWithoutMutation(t *testing.T) {
	repository := openTestRepository(t)
	site, err := repository.Create(context.Background(), CreateInput{
		Kind: KindStatic, PrimaryDomain: "site.example.com", HTTPSPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.SetState(context.Background(), site.ID, StateActive); err != nil {
		t.Fatal(err)
	}
	if err := repository.SetState(context.Background(), site.ID, StateProvisioning); !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("SetState() error = %v, want %v", err, ErrInvalidStateTransition)
	}
	got, err := repository.Get(context.Background(), site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateActive {
		t.Fatalf("state after rejected transition = %q, want %q", got.State, StateActive)
	}
}
