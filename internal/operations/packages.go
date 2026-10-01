package operations

import (
	"regexp"
)

// officialPackagePattern accepts plain Ubuntu archive package names.
var officialPackagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,63}$`)

// PackageStatus is the read-only OS update posture.
type PackageStatus struct {
	SecurityUpdates  int  `json:"security_updates"`
	RebootRequired   bool `json:"reboot_required"`
	UnattendedActive bool `json:"unattended_active"`
}
