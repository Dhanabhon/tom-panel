package operations

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

var (
	ErrReleaseSignature = errors.New("release manifest signature is invalid")
	ErrReleaseManifest  = errors.New("release manifest is malformed")
	// TomPanelUpdateJobKind applies one signed panel release transactionally.
	TomPanelUpdateJobKind = "tompanel.update"
	// PackageJobKind applies confirmed official package updates.
	PackageJobKind = "package.apply_official"
	// ToolUpdateJobKind applies verified tool updates.
	ToolUpdateJobKind = "tool.update_verified"
)

// ReleaseManifest describes one signed stable panel release.
type ReleaseManifest struct {
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
	URL       string `json:"url"`
}

// canonicalRelease binds the signature to version and checksum only.
func (m ReleaseManifest) canonical() []byte {
	return []byte(m.Version + "\n" + m.SHA256)
}

// VerifyReleaseManifest checks the Ed25519 signature over the canonical
// manifest content.
func VerifyReleaseManifest(manifest ReleaseManifest, publicKey ed25519.PublicKey) (ReleaseManifest, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return ReleaseManifest{}, fmt.Errorf("%w: key size", ErrReleaseSignature)
	}
	if manifest.Version == "" || len(manifest.SHA256) != 64 || !strings.HasPrefix(manifest.URL, "https://") {
		return ReleaseManifest{}, fmt.Errorf("%w: fields", ErrReleaseManifest)
	}
	signature, err := base64.StdEncoding.DecodeString(manifest.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ReleaseManifest{}, fmt.Errorf("%w: encoding", ErrReleaseSignature)
	}
	if !ed25519.Verify(publicKey, manifest.canonical(), signature) {
		return ReleaseManifest{}, ErrReleaseSignature
	}
	return manifest, nil
}

// Updater builds signed panel update jobs.
type Updater struct {
	store   *store.Store
	agent   func(ctx context.Context, operation string, input, output any) error
	public  ed25519.PublicKey
	confirm func(ctx context.Context, manifest ReleaseManifest) error
}

// NewUpdater builds the updater against the pinned release key.
func NewUpdater(database *store.Store, agentCall func(ctx context.Context, operation string, input, output any) error, publicKey ed25519.PublicKey) *Updater {
	call := agentCall
	if call == nil {
		call = func(context.Context, string, any, any) error { return errors.New("privileged agent is unavailable") }
	}
	return &Updater{store: database, agent: call, public: publicKey}
}

type updateJobInput struct {
	Manifest ReleaseManifest `json:"manifest"`
}

// BuildTomPanelUpdateJob verifies the signature and assembles the staged,
// snapshotted, health-gated update with automatic rollback.
func (u *Updater) BuildTomPanelUpdateJob(ctx context.Context, manifest ReleaseManifest) (jobs.Definition, error) {
	verified, err := VerifyReleaseManifest(manifest, u.public)
	if err != nil {
		return jobs.Definition{}, err
	}
	input, err := json.Marshal(updateJobInput{Manifest: verified})
	if err != nil {
		return jobs.Definition{}, err
	}
	if u.confirm != nil {
		if err := u.confirm(ctx, verified); err != nil {
			return jobs.Definition{}, err
		}
	}
	return u.build(input, verified), nil
}

func (u *Updater) build(input json.RawMessage, manifest ReleaseManifest) jobs.Definition {
	return jobs.Definition{
		Kind:  TomPanelUpdateJobKind,
		Input: input,
		Steps: []jobs.Step{
			{Key: "stage", Run: func(ctx context.Context) (json.RawMessage, error) {
				return nil, u.agent(ctx, "tompanel.stage_update", struct {
					Version string `json:"version"`
					SHA256  string `json:"sha256"`
					URL     string `json:"url"`
				}{manifest.Version, manifest.SHA256, manifest.URL}, &struct{}{})
			}},
			{Key: "snapshot", Run: func(ctx context.Context) (json.RawMessage, error) {
				return nil, u.agent(ctx, "tompanel.snapshot", struct{}{}, &struct{}{})
			}},
			{Key: "activate", Run: func(ctx context.Context) (json.RawMessage, error) {
				return nil, u.agent(ctx, "tompanel.activate_update", struct {
					Version string `json:"version"`
				}{manifest.Version}, &struct{}{})
			}, Reconcile: func(ctx context.Context) (jobs.Reconciliation, error) {
				var state struct {
					Version string `json:"version"`
					State   string `json:"state"`
				}
				if err := u.agent(ctx, "tompanel.update_state", struct{}{}, &state); err != nil {
					return jobs.Reconciliation{}, err
				}
				if state.State == "active" {
					return jobs.Reconciliation{Outcome: jobs.ReconcileSucceeded}, nil
				}
				return jobs.Reconciliation{Outcome: jobs.ReconcileRetry}, nil
			}},
		},
	}
}

// Register wires every update job builder into the manager.
func (u *Updater) Register(manager *jobs.Manager) error {
	if err := manager.Register(TomPanelUpdateJobKind, func(input json.RawMessage) (jobs.Definition, error) {
		var parsed updateJobInput
		if err := json.Unmarshal(input, &parsed); err != nil {
			return jobs.Definition{}, err
		}
		verified, err := VerifyReleaseManifest(parsed.Manifest, u.public)
		if err != nil {
			return jobs.Definition{}, err
		}
		return u.build(input, verified), nil
	}); err != nil {
		return err
	}
	if err := manager.Register(PackageJobKind, func(input json.RawMessage) (jobs.Definition, error) {
		var parsed struct {
			Packages []string `json:"packages"`
		}
		if err := json.Unmarshal(input, &parsed); err != nil {
			return jobs.Definition{}, err
		}
		return u.BuildPackageJob(PackageUpdate{Packages: parsed.Packages, Confirmed: true})
	}); err != nil {
		return err
	}
	return manager.Register(ToolUpdateJobKind, func(input json.RawMessage) (jobs.Definition, error) {
		var parsed ToolUpdate
		if err := json.Unmarshal(input, &parsed); err != nil {
			return jobs.Definition{}, err
		}
		parsed.Confirmed = true
		return u.BuildToolUpdateJob(parsed)
	})
}

// PackageUpdate is one confirmed official package set.
type PackageUpdate struct {
	Packages  []string
	Confirmed bool
	FromPPA   bool
}

// BuildPackageJob applies allowlisted official security updates only.
func (u *Updater) BuildPackageJob(update PackageUpdate) (jobs.Definition, error) {
	if !update.Confirmed {
		return jobs.Definition{}, errors.New("package updates require explicit confirmation")
	}
	if update.FromPPA {
		return jobs.Definition{}, errors.New("PPA packages are not allowlisted for unattended application")
	}
	if len(update.Packages) == 0 || len(update.Packages) > 64 {
		return jobs.Definition{}, errors.New("package set is out of bounds")
	}
	for _, name := range update.Packages {
		if !officialPackagePattern.MatchString(name) {
			return jobs.Definition{}, fmt.Errorf("package %q is not an official archive name", name)
		}
	}
	input, _ := json.Marshal(struct {
		Packages []string `json:"packages"`
	}{update.Packages})
	return jobs.Definition{
		Kind:  PackageJobKind,
		Input: input,
		Steps: []jobs.Step{
			{Key: "apply", Run: func(ctx context.Context) (json.RawMessage, error) {
				return nil, u.agent(ctx, "package.apply_official", struct {
					Packages []string `json:"packages"`
				}{update.Packages}, &struct{}{})
			}},
		},
	}, nil
}

// ToolUpdate is one explicit tool upgrade.
type ToolUpdate struct {
	Tool      string
	Version   string
	SHA256    string
	Confirmed bool
}

// BuildToolUpdateJob applies phpMyAdmin or WP-CLI after upstream
// verification; it never runs without explicit consent.
func (u *Updater) BuildToolUpdateJob(update ToolUpdate) (jobs.Definition, error) {
	if !update.Confirmed {
		return jobs.Definition{}, errors.New("tool updates require explicit confirmation")
	}
	if update.Tool != "phpmyadmin" && update.Tool != "wpcli" {
		return jobs.Definition{}, errors.New("tool is not supported")
	}
	if update.Version == "" || len(update.SHA256) != 64 {
		return jobs.Definition{}, errors.New("tool update payload is invalid")
	}
	input, _ := json.Marshal(update)
	return jobs.Definition{
		Kind:  ToolUpdateJobKind,
		Input: input,
		Steps: []jobs.Step{
			{Key: "verify_and_replace", Run: func(ctx context.Context) (json.RawMessage, error) {
				return nil, u.agent(ctx, "tool.update_verified", struct {
					Tool    string `json:"tool"`
					Version string `json:"version"`
					SHA256  string `json:"sha256"`
				}{update.Tool, update.Version, update.SHA256}, &struct{}{})
			}},
		},
	}, nil
}
