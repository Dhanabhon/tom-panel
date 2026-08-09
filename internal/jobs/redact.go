package jobs

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const redacted = "[REDACTED]"

var (
	authorizationPattern = regexp.MustCompile(`(?i)(\bauthorization\b\s*[:=]\s*)(?:basic|bearer)\s+[^\s,;]+`)
	credentialPattern    = regexp.MustCompile(`(?i)(\b(?:[a-z0-9]+[_-])*(?:password|passwd|token|secret|api[_-]?key|private[_-]?key|credential|authorization)\b\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)`)
)

type Redactor struct {
	mu      sync.RWMutex
	secrets []string
}

func NewRedactor(secrets ...string) *Redactor {
	r := &Redactor{}
	for _, secret := range secrets {
		r.Register(secret)
	}
	return r
}

func (r *Redactor) Register(secret string) {
	if secret == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.secrets {
		if existing == secret {
			return
		}
	}
	r.secrets = append(r.secrets, secret)
	sort.Slice(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
}

func (r *Redactor) Redact(value string) string {
	r.mu.RLock()
	secrets := append([]string(nil), r.secrets...)
	r.mu.RUnlock()
	for _, secret := range secrets {
		value = strings.ReplaceAll(value, secret, redacted)
	}
	value = authorizationPattern.ReplaceAllString(value, `${1}`+redacted)
	return credentialPattern.ReplaceAllString(value, `${1}`+redacted)
}

func (r *Redactor) RedactJSON(value json.RawMessage) json.RawMessage {
	return r.redactJSON(value)
}

func (r *Redactor) redactJSON(value json.RawMessage) json.RawMessage {
	if len(value) == 0 {
		return nil
	}
	var decoded any
	if json.Unmarshal(value, &decoded) != nil {
		return json.RawMessage(r.Redact(string(value)))
	}
	redactJSONValue(r, decoded)
	encoded, err := json.Marshal(decoded)
	if err != nil {
		return json.RawMessage(`null`)
	}
	return encoded
}

func redactJSONValue(r *Redactor, value any) {
	switch value := value.(type) {
	case map[string]any:
		for key, item := range value {
			if isCredentialKey(key) {
				value[key] = redacted
				continue
			}
			switch item := item.(type) {
			case string:
				value[key] = r.Redact(item)
			default:
				redactJSONValue(r, item)
			}
		}
	case []any:
		for index, item := range value {
			switch item := item.(type) {
			case string:
				value[index] = r.Redact(item)
			default:
				redactJSONValue(r, item)
			}
		}
	}
}

func isCredentialKey(key string) bool {
	key = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
	for _, marker := range []string{"password", "passwd", "token", "secret", "apikey", "privatekey", "credential", "authorization"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}
