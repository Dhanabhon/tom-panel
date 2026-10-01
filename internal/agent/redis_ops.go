package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const redisSocketPath = "/run/redis/redis-server.sock"

type redisEnvironment struct {
	socketPath string
	run        func(ctx context.Context, commands string) error
}

func defaultRedisEnvironment() redisEnvironment {
	return redisEnvironment{
		socketPath: redisSocketPath,
		run: func(ctx context.Context, commands string) error {
			return runCommandInput(ctx, "/usr/bin/redis-cli", []byte(commands), "--unix", redisSocketPath)
		},
	}
}

type redisACLInput struct {
	SiteID   string `json:"site_id"`
	Password string `json:"password,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
}

func redisACLUser(siteID string) (string, error) {
	if !validSiteID(siteID) {
		return "", errors.New("redis acl payload is invalid")
	}
	return "tp_" + siteID[:16], nil
}

// ensureRedisACL creates one ACL user scoped to the site's key prefix.
// The password travels inside the command stream on stdin, never argv.
func ensureRedisACL(ctx context.Context, input redisACLInput, env redisEnvironment) error {
	username, err := redisACLUser(input.SiteID)
	if err != nil {
		return err
	}
	if len(input.Password) < 20 || len(input.Password) > 128 || strings.ContainsAny(input.Password, " \t\n\r\"'") {
		return errors.New("redis acl password is invalid")
	}
	if input.Prefix == "" || len(input.Prefix) > 64 || strings.ContainsAny(input.Prefix, " \t\n\r*") {
		return errors.New("redis acl prefix is invalid")
	}
	commands := strings.Join([]string{
		"ACL SETUSER " + username + " on >" + input.Password + " ~" + input.Prefix + ":* +@read +@write",
	}, "\n")
	if err := env.run(ctx, commands); err != nil {
		return fmt.Errorf("ensure redis acl: %w", err)
	}
	return nil
}

// removeRedisACL deletes the site's ACL user without touching others.
func removeRedisACL(ctx context.Context, input redisACLInput, env redisEnvironment) error {
	username, err := redisACLUser(input.SiteID)
	if err != nil {
		return err
	}
	return env.run(ctx, "ACL DELUSER "+username)
}
