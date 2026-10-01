package agent

import (
	"context"
	"errors"
	"path/filepath"
)

const setfaclBinary = "/usr/bin/setfacl"

// grantPanelAccessWith grants the unprivileged panel account recursive read
// and write access to one site tree. Default ACLs keep newly created files
// reachable by the File Manager.
func grantPanelAccessWith(ctx context.Context, siteID, panelUser, sitesRoot string, run func(context.Context, string, ...string) error) error {
	if !validSiteID(siteID) {
		return errors.New("file.grant_panel_access payload is invalid")
	}
	if !validSystemUserName(panelUser) {
		return errors.New("panel access account is invalid")
	}
	target := filepath.Join(sitesRoot, siteID)
	return run(ctx, setfaclBinary, "-R",
		"-m", "u:"+panelUser+":rwX",
		"-m", "d:u:"+panelUser+":rwX",
		target)
}

func grantPanelAccess(ctx context.Context, siteID string) error {
	return grantPanelAccessWith(ctx, siteID, panelUserName, siteRootPath, runCommand)
}

func validSystemUserName(name string) bool {
	if len(name) == 0 || len(name) > 32 {
		return false
	}
	for index, character := range name {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9' && index > 0:
		case character == '_' || character == '-':
		default:
			return false
		}
	}
	return true
}
