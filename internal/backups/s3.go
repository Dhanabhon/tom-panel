package backups

import "strings"

// RemoteSettings describes one configured object storage target. Secrets are
// injected into agent operations only; they are never persisted by this
// package.
type RemoteSettings struct {
	Endpoint     string `json:"endpoint"`
	Region       string `json:"region"`
	Bucket       string `json:"bucket"`
	Prefix       string `json:"prefix"`
	AccessKeyID  string `json:"-"`
	SecretKey    string `json:"-"`
	AgeRecipient string `json:"age_recipient"`
}

// Valid accepts S3-compatible endpoints with bucket, credentials, and an age
// recipient for client-side encryption.
func (r RemoteSettings) Valid() bool {
	return r.Bucket != "" && r.AccessKeyID != "" && r.SecretKey != "" &&
		(r.Endpoint == "" || strings.HasPrefix(r.Endpoint, "https://")) &&
		strings.HasPrefix(r.AgeRecipient, "age1") && len(r.AgeRecipient) >= 20
}

// ObjectKey derives the deterministic remote key of one backup.
func (r RemoteSettings) ObjectKey(siteID, backupID string) string {
	prefix := strings.Trim(r.Prefix, "/")
	if prefix == "" {
		return siteID + "/" + backupID + ".tar.age"
	}
	return prefix + "/" + siteID + "/" + backupID + ".tar.age"
}
