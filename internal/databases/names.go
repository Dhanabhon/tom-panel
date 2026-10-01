package databases

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrUnsafeIdentifier = errors.New("database identifier is invalid")
	ErrUnsafeSuffix     = errors.New("database suffix is invalid")

	maxDatabaseName = 64
	maxUserName     = 32
	prefix          = "tp_"
)

// ValidSiteID reports whether id is a 32 character lowercase hex identifier.
func ValidSiteID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, character := range id {
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
}

// ValidateSuffix accepts a short slug used to name one database of a site.
func ValidateSuffix(suffix string) error {
	if len(suffix) == 0 || len(suffix) > 16 {
		return ErrUnsafeSuffix
	}
	for _, character := range suffix {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9' && len(suffix) > 0:
		case character == '_':
		default:
			return ErrUnsafeSuffix
		}
	}
	if strings.HasPrefix(suffix, "_") || strings.HasSuffix(suffix, "_") {
		return ErrUnsafeSuffix
	}
	return nil
}

// SitePrefix derives the shared identifier prefix of one site.
func SitePrefix(siteID string) (string, error) {
	if !ValidSiteID(siteID) {
		return "", ErrUnsafeIdentifier
	}
	return prefix + siteID[:16], nil
}

// DatabaseName derives the MariaDB database name for a site suffix.
func DatabaseName(siteID, suffix string) (string, error) {
	base, err := SitePrefix(siteID)
	if err != nil {
		return "", err
	}
	if err := ValidateSuffix(suffix); err != nil {
		return "", err
	}
	name := base + "_" + suffix
	if len(name) > maxDatabaseName {
		return "", ErrUnsafeIdentifier
	}
	return name, nil
}

// UserName derives the MariaDB user of one credential generation.
func UserName(siteID string, generation int) (string, error) {
	base, err := SitePrefix(siteID)
	if err != nil {
		return "", err
	}
	if generation < 1 || generation > 99 {
		return "", ErrUnsafeIdentifier
	}
	name := fmt.Sprintf("%s_u%d", base, generation)
	if len(name) > maxUserName {
		return "", ErrUnsafeIdentifier
	}
	return name, nil
}

// QuoteIdentifier renders a validated identifier for inline SQL use.
func QuoteIdentifier(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

// QuoteString renders a validated literal for inline SQL use.
func QuoteString(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// ValidatePassword enforces the MariaDB literal-safe password policy.
func ValidatePassword(password string) error {
	if len(password) < 20 || len(password) > 96 {
		return errors.New("database password length must be between 20 and 96 characters")
	}
	for _, r := range password {
		if r <= 0x20 || r == 0x7f || r == '\'' || r == '\\' || r > 0x7e {
			return errors.New("database password contains unsupported characters")
		}
	}
	return nil
}
