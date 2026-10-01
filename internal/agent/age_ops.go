package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/backups"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"filippo.io/age"
)

// parseAgeRecipient accepts one X25519 recipient string.
func parseAgeRecipient(value string) (age.Recipient, error) {
	recipient, err := age.ParseX25519Recipient(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("age recipient is invalid: %w", err)
	}
	return recipient, nil
}

// ageEncryptReader wraps body in a streaming age encryption pipe.
func ageEncryptReader(body io.Reader, recipient age.Recipient) (io.Reader, error) {
	reader, writer := io.Pipe()
	go func() {
		encrypter, err := age.Encrypt(writer, recipient)
		if err != nil {
			_ = writer.CloseWithError(err)
			return
		}
		if _, err := io.Copy(encrypter, body); err != nil {
			_ = encrypter.Close()
			_ = writer.CloseWithError(err)
			return
		}
		if err := encrypter.Close(); err != nil {
			_ = writer.CloseWithError(err)
			return
		}
		_ = writer.Close()
	}()
	return reader, nil
}

// uploadEncryptedObject streams an age-encrypted body to S3-compatible
// storage. The plaintext never crosses the network boundary.
func uploadEncryptedObject(ctx context.Context, settings backups.RemoteSettings, key string, body io.Reader, _ int64) (int64, error) {
	if !settings.Valid() {
		return 0, errors.New("object storage settings are invalid")
	}
	client := s3.NewFromConfig(aws.Config{
		Region:      settings.Region,
		Credentials: credentials.NewStaticCredentialsProvider(settings.AccessKeyID, settings.SecretKey, ""),
	}, func(options *s3.Options) {
		if settings.Endpoint != "" {
			options.BaseEndpoint = aws.String(settings.Endpoint)
			options.UsePathStyle = true
		}
	})
	var total int64
	counting := &tallyReader{reader: body}
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(settings.Bucket),
		Key:    aws.String(key),
		Body:   counting,
	})
	total = counting.count
	if err != nil {
		return total, fmt.Errorf("upload encrypted object: %w", err)
	}
	return total, nil
}

type tallyReader struct {
	reader io.Reader
	count  int64
}

func (t *tallyReader) Read(p []byte) (int, error) {
	n, err := t.reader.Read(p)
	t.count += int64(n)
	return n, err
}
