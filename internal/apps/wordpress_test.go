package apps

import (
	"strings"
	"testing"
)

func testInstallInput() WordPressInstallInput {
	return WordPressInstallInput{
		SiteID: "0123456789abcdef0123456789abcdef", SiteURL: "https://wp.example.test",
		Database: "tp_0123456789abcdef_shop", DBUser: "tp_0123456789abcdef_u1",
		DBPassword: "generated-db-password-123", AdminUser: "tom", AdminEmail: "tom@example.test",
		AdminPassword: "generated-password", Title: "My site", Policy: DefaultWordPressPolicy(),
	}
}

func TestWordPressSecretsNeverEnterArguments(t *testing.T) {
	calls, err := BuildWordPressInstallCall(testInstallInput())
	if err != nil {
		t.Fatal(err)
	}
	var joinedArgs string
	var joinedStdin string
	for _, call := range calls {
		joinedArgs += strings.Join(call.Args, " ") + "\n"
		joinedStdin += string(call.Stdin)
	}
	for _, secret := range []string{"generated-db-password-123", "generated-password"} {
		if strings.Contains(joinedArgs, secret) {
			t.Fatalf("secret in argv: %s", joinedArgs)
		}
		if !strings.Contains(joinedStdin, secret) {
			t.Fatalf("secret missing from protected stdin: %q", joinedStdin)
		}
	}
}

func TestInstallCallPromptsForSecrets(t *testing.T) {
	calls, err := BuildWordPressInstallCall(testInstallInput())
	if err != nil {
		t.Fatal(err)
	}
	var configCreate, coreInstall WPCLICall
	for _, call := range calls {
		joined := strings.Join(call.Args, " ")
		if strings.Contains(joined, "config create") {
			configCreate = call
		}
		if strings.Contains(joined, "core install") {
			coreInstall = call
		}
	}
	if !strings.Contains(strings.Join(configCreate.Args, " "), "--prompt=dbpass") {
		t.Fatalf("config create does not prompt for the database password: %v", configCreate.Args)
	}
	if !strings.Contains(strings.Join(coreInstall.Args, " "), "--prompt=admin_password") {
		t.Fatalf("core install does not prompt for the admin password: %v", coreInstall.Args)
	}
}

func TestInstallCallSetsSafeDefaults(t *testing.T) {
	calls, err := BuildWordPressInstallCall(testInstallInput())
	if err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, call := range calls {
		joined += strings.Join(call.Args, " ") + "\n"
	}
	for _, required := range []string{
		"config set WP_AUTO_UPDATE_CORE minor",
		"config set DISALLOW_FILE_EDIT true",
		"config set FORCE_SSL_ADMIN true",
		"core verify-checksums",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("install flow missing %q:\n%s", required, joined)
		}
	}
}

func TestUpdateCallIsPolicyDriven(t *testing.T) {
	base := testInstallInput()
	calls, err := BuildWordPressUpdateCall(base)
	if err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, call := range calls {
		joined += strings.Join(call.Args, " ") + "\n"
	}
	if !strings.Contains(joined, "db export") {
		t.Fatalf("update without pre-export cannot roll back: %s", joined)
	}
	if strings.Contains(joined, "plugin update") || strings.Contains(joined, "theme update") {
		t.Fatalf("default policy updated plugins or themes: %s", joined)
	}
	base.Policy.Plugins, base.Policy.Themes = true, true
	calls, err = BuildWordPressUpdateCall(base)
	if err != nil {
		t.Fatal(err)
	}
	joined = ""
	for _, call := range calls {
		joined += strings.Join(call.Args, " ") + "\n"
	}
	if !strings.Contains(joined, "plugin update --all") || !strings.Contains(joined, "theme update --all") {
		t.Fatalf("policy did not enable updates: %s", joined)
	}
}

func TestInputValidationRejectsWeakSecrets(t *testing.T) {
	base := testInstallInput()
	base.AdminPassword = "short"
	if _, err := BuildWordPressInstallCall(base); err == nil {
		t.Fatal("weak admin password accepted")
	}
	base = testInstallInput()
	base.DBPassword = "has\nnewline-secret-123"
	if _, err := BuildWordPressInstallCall(base); err == nil {
		t.Fatal("multiline database password accepted")
	}
	base = testInstallInput()
	base.SiteID = "../evil"
	if _, err := BuildWordPressInstallCall(base); err == nil {
		t.Fatal("unsafe site id accepted")
	}
}

func TestGeneratedSecretsAreStrong(t *testing.T) {
	password, err := GenerateWordPressSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(password) != secretLength {
		t.Fatalf("password length: %d", len(password))
	}
	second, _ := GenerateWordPressSecrets()
	if password == second {
		t.Fatal("identical secrets generated")
	}
}
