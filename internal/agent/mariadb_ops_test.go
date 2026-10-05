package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dbTestSiteID = "0123456789abcdef0123456789abcdef"

func testDatabase() string {
	return "tp_" + dbTestSiteID[:16] + "_shop"
}

func testDatabaseUser(generation int) string {
	return "tp_" + dbTestSiteID[:16] + "_u" + string(rune('0'+generation))
}

// dbTestPassword is constructed at runtime; not a real credential.
var dbTestPassword = strings.Repeat("c", 26)

type recordedSQL struct {
	query string
	asUser string
}

type fakeMariaDB struct {
	queries   []recordedSQL
	failOn    func(query string) bool
	dumped    []string
	restored  []string
}

func (f *fakeMariaDB) exec(_ context.Context, query string) error {
	f.queries = append(f.queries, recordedSQL{query: query})
	if f.failOn != nil && f.failOn(query) {
		return errors.New("sql forced failure")
	}
	return nil
}

func (f *fakeMariaDB) execAs(_ context.Context, username, password, database, query string) error {
	f.queries = append(f.queries, recordedSQL{query: query, asUser: username + "/" + password + "/" + database})
	if f.failOn != nil && f.failOn(query) {
		return errors.New("credential rejected")
	}
	return nil
}

func (f *fakeMariaDB) env(backupRoot string) mariadbEnvironment {
	return mariadbEnvironment{
		backupRoot: backupRoot,
		exec:       f.exec,
		execAs:     f.execAs,
		dump: func(_ context.Context, database, outPath string) error {
			f.dumped = append(f.dumped, database+"→"+outPath)
			return os.WriteFile(outPath, []byte("-- dump of "+database+"\n"), 0o640)
		},
		restore: func(_ context.Context, database, inPath string) error {
			f.restored = append(f.restored, database+"←"+inPath)
			return nil
		},
	}
}

func TestGrantCannotEscapeSite(t *testing.T) {
	fake := &fakeMariaDB{}
	env := fake.env(t.TempDir())
	if err := ensureMariaDBDatabase(context.Background(), mariadbDatabaseInput{
		SiteID: dbTestSiteID, Database: testDatabase(), Username: testDatabaseUser(1), Password: dbTestPassword,
	}, env); err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, entry := range fake.queries {
		joined += entry.query + "\n"
	}
	if !strings.Contains(joined, "GRANT "+siteScopedGrants+" ON `"+testDatabase()+"`.* TO '"+testDatabaseUser(1)+"'@'localhost'") {
		t.Fatalf("site-scoped grant missing:\n%s", joined)
	}
	if strings.Contains(joined, "*.* TO") {
		t.Fatalf("global grant escaped the site database:\n%s", joined)
	}
	if err := ensureMariaDBDatabase(context.Background(), mariadbDatabaseInput{
		SiteID: dbTestSiteID, Database: "otherdb", Username: testDatabaseUser(1), Password: dbTestPassword,
	}, env); err == nil {
		t.Fatal("accepted a database outside the site scope")
	}
	if err := ensureMariaDBDatabase(context.Background(), mariadbDatabaseInput{
		SiteID: "11111111111111111111111111111111", Database: testDatabase(), Username: testDatabaseUser(1), Password: dbTestPassword,
	}, env); err == nil {
		t.Fatal("accepted a database from another site")
	}
	if err := ensureMariaDBDatabase(context.Background(), mariadbDatabaseInput{
		SiteID: dbTestSiteID, Database: testDatabase() + "`; DROP DATABASE wordpress", Username: testDatabaseUser(1), Password: dbTestPassword,
	}, env); err == nil {
		t.Fatal("accepted injection in the database name")
	}
}

func TestRotationRetiresOnlyAfterExplicitRequest(t *testing.T) {
	fake := &fakeMariaDB{}
	env := fake.env(t.TempDir())
	err := rotateMariaDBUser(context.Background(), mariadbRotateInput{
		SiteID: dbTestSiteID, Database: testDatabase(), Username: testDatabaseUser(2), Password: dbTestPassword,
	}, env)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(sqlOf(fake), "\n"), "DROP USER") {
		t.Fatal("rotation dropped the old user before the health check")
	}
	err = rotateMariaDBUser(context.Background(), mariadbRotateInput{
		SiteID: dbTestSiteID, Database: testDatabase(), Username: testDatabaseUser(2), Password: dbTestPassword,
		RetireUsername: testDatabaseUser(1),
	}, env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(sqlOf(fake), "\n"), "DROP USER IF EXISTS '"+testDatabaseUser(1)+"'@'localhost'") {
		t.Fatal("retire request did not drop the previous user")
	}
	err = rotateMariaDBUser(context.Background(), mariadbRotateInput{
		SiteID: dbTestSiteID, Database: testDatabase(), Username: testDatabaseUser(2), Password: dbTestPassword,
		RetireUsername: testDatabaseUser(2),
	}, env)
	if err == nil {
		t.Fatal("accepted retiring the replacement user itself")
	}
}

func sqlOf(fake *fakeMariaDB) []string {
	var result []string
	for _, entry := range fake.queries {
		result = append(result, entry.query)
	}
	return result
}

func TestVerifyCredentialConnectsAsTheSiteUser(t *testing.T) {
	fake := &fakeMariaDB{}
	env := fake.env(t.TempDir())
	if err := verifyMariaDBCredential(context.Background(), mariadbCredentialInput{
		SiteID: dbTestSiteID, Database: testDatabase(), Username: testDatabaseUser(1), Password: dbTestPassword,
	}, env); err != nil {
		t.Fatal(err)
	}
	if len(fake.queries) != 1 || !strings.Contains(fake.queries[0].asUser, testDatabaseUser(1)+"/") {
		t.Fatalf("verification did not connect as the site user: %+v", fake.queries)
	}
}

func TestDumpAndRestoreStayConfined(t *testing.T) {
	backupRoot := t.TempDir()
	fake := &fakeMariaDB{}
	env := fake.env(backupRoot)
	result, err := dumpMariaDBDatabase(context.Background(), mariadbDatabaseInput{
		SiteID: dbTestSiteID, Database: testDatabase(),
	}, env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.Path, filepath.Join(backupRoot, dbTestSiteID)+string(os.PathSeparator)) {
		t.Fatalf("dump escaped the backup root: %s", result.Path)
	}
	if !strings.HasSuffix(result.Path, ".sql") || result.Size == 0 || len(result.SHA256) != 64 {
		t.Fatalf("dump metadata incomplete: %+v", result)
	}
	if strings.Contains(result.Path, "..") {
		t.Fatalf("dump path traversal: %s", result.Path)
	}
	if err := restoreMariaDBDatabase(context.Background(), mariadbRestoreInput{
		SiteID: dbTestSiteID, Database: testDatabase(), Path: result.Path,
	}, env); err != nil {
		t.Fatal(err)
	}
	if err := restoreMariaDBDatabase(context.Background(), mariadbRestoreInput{
		SiteID: dbTestSiteID, Database: testDatabase(), Path: filepath.Join(backupRoot, "..", "etc", "passwd.sql"),
	}, env); err == nil {
		t.Fatal("restore accepted a path outside the backup root")
	}
}

func TestDropDatabaseCleansUsers(t *testing.T) {
	fake := &fakeMariaDB{}
	env := fake.env(t.TempDir())
	if err := dropMariaDBDatabase(context.Background(), mariadbDropInput{
		SiteID: dbTestSiteID, Database: testDatabase(), Usernames: []string{testDatabaseUser(1), testDatabaseUser(2)},
	}, env); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(sqlOf(fake), "\n")
	if !strings.Contains(joined, "DROP DATABASE IF EXISTS `"+testDatabase()+"`") {
		t.Fatalf("database not dropped: %s", joined)
	}
	if strings.Count(joined, "DROP USER IF EXISTS") != 2 {
		t.Fatalf("users not dropped: %s", joined)
	}
	if err := dropMariaDBDatabase(context.Background(), mariadbDropInput{
		SiteID: dbTestSiteID, Database: testDatabase(), Usernames: []string{"root"},
	}, env); err == nil {
		t.Fatal("accepted dropping a user outside the site scope")
	}
}

func TestGrantRejectsUnsafePasswords(t *testing.T) {
	fake := &fakeMariaDB{}
	env := fake.env(t.TempDir())
	for _, password := range []string{"short", "has space1234567890123", "quote'in-password-12345", strings.Repeat("a", 200)} {
		err := ensureMariaDBDatabase(context.Background(), mariadbDatabaseInput{
			SiteID: dbTestSiteID, Database: testDatabase(), Username: testDatabaseUser(1), Password: password,
		}, env)
		if err == nil {
			t.Fatalf("accepted unsafe password %q", password)
		}
	}
}
