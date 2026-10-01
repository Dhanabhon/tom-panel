package operations

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// LogQuery bounds one log read.
type LogQuery struct {
	SiteID   string
	Domain   string
	Source   string // nginx | app
	Search   string
	MaxLines int
}

// LogEvent is one rendered log line with secrets redacted.
type LogEvent struct {
	Line string `json:"line"`
}

const logMaxLines = 400
const logMaxBytes = 4 << 20

var (
	ErrUnsupportedLogSource = errors.New("log source is not supported")
	secretPattern           = regexp.MustCompile(`(?i)(password|passwd|token|secret|api[_-]?key|authorization)[=:]\s*[^\s"']+`)
)

// LogReader reads only TomPanel-owned log locations through the agent.
type LogReader struct {
	agent func(ctx context.Context, operation string, input, output any) error
}

// NewLogReader builds the bounded, redacting log reader.
func NewLogReader(agentCall func(ctx context.Context, operation string, input, output any) error) *LogReader {
	call := agentCall
	if call == nil {
		call = func(context.Context, string, any, any) error { return errors.New("privileged agent is unavailable") }
	}
	return &LogReader{agent: call}
}

// Read returns bounded, redacted lines for one site log source.
func (r *LogReader) Read(ctx context.Context, query LogQuery) ([]LogEvent, error) {
	if query.Source != "nginx" && query.Source != "app" {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedLogSource, query.Source)
	}
	if query.MaxLines <= 0 || query.MaxLines > logMaxLines {
		query.MaxLines = logMaxLines
	}
	if len(query.Search) > 256 {
		return nil, errors.New("search term is too long")
	}
	var result struct {
		Lines []string `json:"lines"`
	}
	if err := r.agent(ctx, "log.read", struct {
		SiteID   string `json:"site_id"`
		Source   string `json:"source"`
		Domain   string `json:"domain"`
		Search   string `json:"search"`
		MaxLines int    `json:"max_lines"`
	}{query.SiteID, query.Source, query.Domain, query.Search, query.MaxLines}, &result); err != nil {
		return nil, err
	}
	events := make([]LogEvent, 0, len(result.Lines))
	for _, line := range result.Lines {
		events = append(events, LogEvent{Line: RedactLogLine(line)})
	}
	return events, nil
}

var authorizationPattern = regexp.MustCompile(`(?i)authorization:\s*\S+\s+\S+`)

// RedactLogLine masks inline credential assignments before display.
func RedactLogLine(line string) string {
	redacted := secretPattern.ReplaceAllStringFunc(line, func(match string) string {
		index := strings.IndexAny(match, ":=")
		if index < 0 {
			return match
		}
		return match[:index+1] + " [REDACTED]"
	})
	return authorizationPattern.ReplaceAllString(redacted, "Authorization: [REDACTED]")
}
