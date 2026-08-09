package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/cli"
	"github.com/Dhanabhon/tom-panel/internal/config"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("tompanel", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "/etc/tompanel/config.toml", "path to configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	remaining := flags.Args()
	if len(remaining) < 2 || remaining[0] != "admin" {
		return errors.New("usage: tompanel [-config path] admin reset-password|set-username|reset-totp")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	database, err := store.Open(ctx, filepath.Join(cfg.StateDir, "tompanel.db"), "/etc/tompanel/master.key")
	if err != nil {
		return err
	}
	service := auth.New(database, time.Now)
	return cli.NewAdminCommands(service, os.Stdin, os.Stdout).Run(ctx, remaining[1:])
}
