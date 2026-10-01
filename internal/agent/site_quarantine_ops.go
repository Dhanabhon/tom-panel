package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const quarantineRootPath = "/srv/tompanel/quarantine"

type siteQuarantineInput struct {
	SiteID string `json:"site_id"`
}

type sitePurgeInput struct {
	SiteID   string `json:"site_id"`
	DataPath string `json:"data_path"`
}

type siteQuarantineResult struct {
	DataPath string `json:"data_path"`
}

// quarantineSite moves one site tree into the quarantine area. The panel
// keeps a seven-day window before the data is purged for good.
func quarantineSite(_ context.Context, input siteQuarantineInput, quarantineRoot string) (siteQuarantineResult, error) {
	if !validSiteID(input.SiteID) {
		return siteQuarantineResult{}, errors.New("site.quarantine payload is invalid")
	}
	if err := os.MkdirAll(quarantineRoot, 0o700); err != nil {
		return siteQuarantineResult{}, err
	}
	source := filepath.Join(siteRootPath, input.SiteID)
	if _, err := os.Lstat(source); err != nil {
		return siteQuarantineResult{}, fmt.Errorf("site tree missing: %w", err)
	}
	destination := filepath.Join(quarantineRoot, input.SiteID+"-"+fmt.Sprint(time.Now().UTC().Unix()))
	if err := os.Rename(source, destination); err != nil {
		return siteQuarantineResult{}, fmt.Errorf("move site into quarantine: %w", err)
	}
	return siteQuarantineResult{DataPath: destination}, nil
}

// purgeQuarantinedSite removes one quarantined tree. The path must point
// inside the quarantine area and carry the site identity.
func purgeQuarantinedSite(_ context.Context, input sitePurgeInput, quarantineRoot string) error {
	if !validSiteID(input.SiteID) {
		return errors.New("site.purge_quarantine payload is invalid")
	}
	if !confinedQuarantinePath(quarantineRoot, input.SiteID, input.DataPath) {
		return errors.New("site.purge_quarantine path is not confined")
	}
	root, err := os.OpenRoot(quarantineRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	relative, err := filepath.Rel(quarantineRoot, input.DataPath)
	if err != nil {
		return err
	}
	if err := root.RemoveAll(relative); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func confinedQuarantinePath(root, siteID, path string) bool {
	clean := filepath.Clean(path)
	if !strings.HasPrefix(clean, root+string(os.PathSeparator)) {
		return false
	}
	base := filepath.Base(clean)
	return len(base) == 33+13 && base[:32] == siteID && base[32] == '-'
}
