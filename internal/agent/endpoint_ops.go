package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/backups"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const panelEndpointConf = "tompanel-panel.conf"
const panelLoopbackPort = 8080

type endpointActivateInput struct {
	Config struct {
		Mode            string `json:"mode"`
		Hostname        string `json:"hostname,omitempty"`
		Port            uint16 `json:"port,omitempty"`
		CloudflareProxy bool   `json:"cloudflare_proxy,omitempty"`
	} `json:"config"`
}

// renderPanelEndpointConfig produces the managed nginx configuration for the
// panel itself. Public mode terminates TLS in front of the loopback panel.
func renderPanelEndpointConfig(input endpointActivateInput) (string, error) {
	var builder strings.Builder
	builder.WriteString("# Managed by TomPanel: panel-endpoint\n")
	builder.WriteString("server {\n")
	switch input.Config.Mode {
	case "loopback":
		builder.WriteString(fmt.Sprintf("    listen 127.0.0.1:%d;\n", panelLoopbackPort))
		builder.WriteString("    location / {\n        proxy_pass http://127.0.0.1:8081;\n    }\n")
	case "public":
		if input.Config.Hostname == "" || input.Config.Port == 0 {
			return "", errors.New("endpoint.activate payload is invalid")
		}
		builder.WriteString(fmt.Sprintf("    listen %d ssl;\n", input.Config.Port))
		builder.WriteString("    server_name " + input.Config.Hostname + ";\n")
		builder.WriteString("    ssl_certificate /etc/tompanel/endpoint/fullchain.pem;\n")
		builder.WriteString("    ssl_certificate_key /etc/tompanel/endpoint/privkey.pem;\n")
		builder.WriteString("    location / {\n        proxy_pass http://127.0.0.1:8081;\n        proxy_set_header X-Forwarded-Proto https;\n    }\n")
	default:
		return "", errors.New("endpoint.activate mode is unsupported")
	}
	builder.WriteString("}\n")
	return builder.String(), nil
}

func activatePanelEndpoint(ctx context.Context, input endpointActivateInput, env nginxEnvironment) error {
	config, err := renderPanelEndpointConfig(input)
	if err != nil {
		return err
	}
	return activatePHPMyAdminConfig(ctx, panelEndpointConf, config, env)
}

type integrationTestS3Input struct {
	Settings backups.RemoteSettings `json:"settings"`
	Probe    string                 `json:"probe"`
}

type integrationTestResult struct {
	OK bool `json:"ok"`
}

// testS3Integration proves bucket credentials with a write/read/delete of
// one random probe object. Nothing about the probe is persisted.
func testS3Integration(ctx context.Context, input integrationTestS3Input) (integrationTestResult, error) {
	if !input.Settings.Valid() || len(input.Probe) < 8 || strings.ContainsAny(input.Probe, " \t\n\r/") {
		return integrationTestResult{}, errors.New("integration.test_s3 payload is invalid")
	}
	client := s3.NewFromConfig(aws.Config{
		Region:      orDefault(input.Settings.Region, "auto"),
		Credentials: credentials.NewStaticCredentialsProvider(input.Settings.AccessKeyID, input.Settings.SecretKey, ""),
	}, func(options *s3.Options) {
		if input.Settings.Endpoint != "" {
			options.BaseEndpoint = aws.String(input.Settings.Endpoint)
			options.UsePathStyle = true
		}
	})
	body := strings.NewReader("tompanel integration probe")
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(input.Settings.Bucket), Key: aws.String(input.Probe), Body: body,
	}); err != nil {
		return integrationTestResult{}, fmt.Errorf("probe write failed: %w", err)
	}
	if _, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(input.Settings.Bucket), Key: aws.String(input.Probe),
	}); err != nil {
		_, _ = client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(input.Settings.Bucket), Key: aws.String(input.Probe)})
		return integrationTestResult{}, fmt.Errorf("probe read failed: %w", err)
	}
	if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(input.Settings.Bucket), Key: aws.String(input.Probe),
	}); err != nil {
		return integrationTestResult{}, fmt.Errorf("probe cleanup failed: %w", err)
	}
	return integrationTestResult{OK: true}, nil
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
