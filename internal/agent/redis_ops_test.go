package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// syntheticRedisPassword is constructed at runtime for ACL fixtures; it is
// not a real credential.
var syntheticRedisPassword = strings.Repeat("k", 24)

type redisCallLog struct {
	commands []string
	fail     bool
}

func (l *redisCallLog) run(_ context.Context, commands string) error {
	l.commands = append(l.commands, commands)
	if l.fail {
		return errors.New("redis forced failure")
	}
	return nil
}

func TestRedisACLCarriesSecretOnlyInStdin(t *testing.T) {
	log := &redisCallLog{}
	env := redisEnvironment{run: log.run}
	if err := ensureRedisACL(context.Background(), redisACLInput{
		SiteID: dbTestSiteID, Password: syntheticRedisPassword, Prefix: "tp_" + dbTestSiteID[:16],
	}, env); err != nil {
		t.Fatal(err)
	}
	if len(log.commands) != 1 {
		t.Fatalf("commands: %v", log.commands)
	}
	command := log.commands[0]
	if !strings.Contains(command, "ACL SETUSER tp_"+dbTestSiteID[:16]) {
		t.Fatalf("acl user missing: %s", command)
	}
	if !strings.Contains(command, "~tp_"+dbTestSiteID[:16]+":*") {
		t.Fatalf("key pattern not scoped to the site prefix: %s", command)
	}
	if !strings.Contains(command, syntheticRedisPassword) {
		t.Fatalf("password missing from the protected command stream: %s", command)
	}
	if strings.Contains(command, "FLUSHALL") || strings.Contains(command, "FLUSHDB") {
		t.Fatalf("dangerous flush command issued: %s", command)
	}
}

func TestRedisACLRemovalOnlyDeletesOwnedUser(t *testing.T) {
	log := &redisCallLog{}
	env := redisEnvironment{run: log.run}
	if err := removeRedisACL(context.Background(), redisACLInput{SiteID: dbTestSiteID}, env); err != nil {
		t.Fatal(err)
	}
	if strings.Join(log.commands, ";") != "ACL DELUSER tp_"+dbTestSiteID[:16] {
		t.Fatalf("unexpected removal commands: %v", log.commands)
	}
}

func TestRedisACLRejectsUnsafePayloads(t *testing.T) {
	log := &redisCallLog{}
	env := redisEnvironment{run: log.run}
	for _, input := range []redisACLInput{
		{SiteID: "../evil", Password: syntheticRedisPassword, Prefix: "ok"},
		{SiteID: dbTestSiteID, Password: "short", Prefix: "ok"},
		{SiteID: dbTestSiteID, Password: "has " + syntheticRedisPassword, Prefix: "ok"},
		{SiteID: dbTestSiteID, Password: syntheticRedisPassword, Prefix: "with space"},
		{SiteID: dbTestSiteID, Password: syntheticRedisPassword, Prefix: "with*star"},
		{SiteID: dbTestSiteID, Password: syntheticRedisPassword},
	} {
		if err := ensureRedisACL(context.Background(), input, env); err == nil {
			t.Fatalf("accepted unsafe payload: %+v", input)
		}
	}
	if len(log.commands) != 0 {
		t.Fatalf("unsafe payloads reached redis: %v", log.commands)
	}
}
