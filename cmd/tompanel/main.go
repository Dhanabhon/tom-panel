package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/cli"
	"github.com/Dhanabhon/tom-panel/internal/config"
	"github.com/Dhanabhon/tom-panel/internal/store"
	"golang.org/x/term"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	return runWith(ctx, args, os.Stdin, os.Stdout, term.IsTerminal(int(os.Stdout.Fd())), openAuthService)
}

func runWith(ctx context.Context, args []string, input *os.File, output io.Writer, outputTTY bool, openService func(context.Context, config.Config) (*auth.Service, error)) error {
	flags := flag.NewFlagSet("tompanel", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "/etc/tompanel/config.toml", "path to configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	remaining := flags.Args()
	setupURL := len(remaining) == 1 && remaining[0] == "setup-url"
	migrate := len(remaining) == 1 && remaining[0] == "migrate"
	admin := len(remaining) == 2 && remaining[0] == "admin"
	if !setupURL && !migrate && !admin {
		return errors.New("usage: tompanel [-config path] setup-url|migrate|admin reset-password|set-username|reset-totp")
	}
	if setupURL && !outputTTY {
		return errors.New("setup URL output requires an interactive terminal")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if migrate {
		// store.Open applies every pending migration before returning.
		service, err := openService(ctx, cfg)
		if err != nil {
			return err
		}
		_ = service
		_, err = fmt.Fprintln(output, "migrations applied")
		return err
	}
	service, err := openService(ctx, cfg)
	if err != nil {
		return err
	}
	if admin {
		return cli.NewAdminCommands(service, input, output).Run(ctx, remaining[1:])
	}
	token, err := service.CreateSetupToken(ctx)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Open this single-use setup URL within 15 minutes:\nhttp://%s/setup#token=%s\n", cfg.Listen, url.QueryEscape(token))
	return err
}

func openAuthService(ctx context.Context, cfg config.Config) (*auth.Service, error) {
	keyPath := filepath.Join(cfg.StateDir, "master.key")
	if filepath.Clean(cfg.StateDir) == "/var/lib/tompanel" {
		keyPath = "/etc/tompanel/master.key"
	}
	database, err := store.Open(ctx, filepath.Join(cfg.StateDir, "tompanel.db"), keyPath)
	if err != nil {
		return nil, err
	}
	return auth.New(database, time.Now), nil
}
