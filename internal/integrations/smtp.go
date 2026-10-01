package integrations

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// smtpHandshake proves the relay answers SMTP without persisting anything.
func smtpHandshake(ctx context.Context, settings SMTPSettings) error {
	if !settings.Valid() {
		return fmt.Errorf("%w: smtp", ErrInvalidSettings)
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(settings.Host, fmt.Sprint(settings.Port)))
	if err != nil {
		return redacted(fmt.Sprintf("connect relay %s: %v", settings.Host, err))
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return redacted(err.Error())
	}
	greeting := make([]byte, 128)
	if _, err := connection.Read(greeting); err != nil {
		return redacted(fmt.Sprintf("read greeting: %v", err))
	}
	if settings.Username != "" && settings.Password == "" {
		return fmt.Errorf("%w: smtp password missing", ErrInvalidSettings)
	}
	return nil
}

// redacted keeps transport errors displayable without leaking credentials.
func redacted(message string) error {
	return &RedactedError{Message: message}
}

// RedactedError marks provider failures safe for display.
type RedactedError struct{ Message string }

func (e *RedactedError) Error() string { return e.Message }

// cloudflareVerifyZone checks the token can read the configured zone.
func cloudflareVerifyZone(ctx context.Context, zoneID, token string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.cloudflare.com/client/v4/zones/"+zoneID, nil)
	if err != nil {
		return &RedactedError{Message: "build cloudflare request failed"}
	}
	request.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 15 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return &RedactedError{Message: "cloudflare request failed"}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return &RedactedError{Message: fmt.Sprintf("cloudflare zone check returned HTTP %d", response.StatusCode)}
	}
	return nil
}
