package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/sites"
	"golang.org/x/crypto/bcrypt"
)

const (
	phpMyAdminVersion     = "5.2.2"
	phpMyAdminSHA256      = "d1b6f23f334b1b7b175d78cd9d1cdd7c8a55dcd8a2a2b0c5f2f2f1a4c8e91b70"
	phpMyAdminDownload    = "https://www.phpmyadmin.net/downloads/phpMyAdmin-" + phpMyAdminVersion + "-all-languages.tar.gz"
	phpMyAdminInstallRoot = "/usr/share/tompanel/phpmyadmin"
	phpMyAdminAuthRoot    = "/etc/nginx/tompanel-auth"
)

type phpmyadminEnvironment struct {
	installRoot string
	authRoot    string
	version     string
	expectedSHA string
	download    func(ctx context.Context) ([]byte, error)
	nginx       nginxEnvironment
	ufwEnsure   func(ctx context.Context, input ufwInput) error
	ufwRemove   func(ctx context.Context, input ufwInput) error
}

func defaultPHPMyAdminEnvironment() phpmyadminEnvironment {
	return phpmyadminEnvironment{
		installRoot: phpMyAdminInstallRoot,
		authRoot:    phpMyAdminAuthRoot,
		version:     phpMyAdminVersion,
		expectedSHA: phpMyAdminSHA256,
		download: func(ctx context.Context) ([]byte, error) {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, phpMyAdminDownload, nil)
			if err != nil {
				return nil, err
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				return nil, err
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("download phpmyadmin: HTTP %d", response.StatusCode)
			}
			return io.ReadAll(io.LimitReader(response.Body, 256<<20))
		},
		nginx: defaultNginxEnvironment(),
	}
}

type phpmyadminInstallInput struct {
	Version string `json:"version"`
}

type phpmyadminActivateInput struct {
	SiteID      string `json:"site_id"`
	Mode        string `json:"mode"`
	Hostname    string `json:"hostname,omitempty"`
	Port        int    `json:"port,omitempty"`
	BasicUser   string `json:"basic_user,omitempty"`
	BasicSecret string `json:"basic_secret,omitempty"`
}

type phpmyadminDisableInput struct {
	SiteID string `json:"site_id"`
	Port   int    `json:"port,omitempty"`
}

type phpmyadminResult struct {
	InstallPath string `json:"install_path,omitempty"`
	ConfigPath  string `json:"config_path,omitempty"`
}

func installPHPMyAdmin(ctx context.Context, input phpmyadminInstallInput, env phpmyadminEnvironment) (phpmyadminResult, error) {
	if input.Version != env.version {
		return phpmyadminResult{}, errors.New("phpmyadmin.install version is not pinned")
	}
	if _, err := os.Stat(filepath.Join(env.installRoot, "index.php")); err == nil {
		return phpmyadminResult{InstallPath: env.installRoot}, nil
	}
	archive, err := env.download(ctx)
	if err != nil {
		return phpmyadminResult{}, err
	}
	sum := sha256.Sum256(archive)
	if hex.EncodeToString(sum[:]) != env.expectedSHA {
		return phpmyadminResult{}, errors.New("phpmyadmin archive checksum mismatch")
	}
	if err := os.MkdirAll(filepath.Dir(env.installRoot), 0o755); err != nil {
		return phpmyadminResult{}, err
	}
	parent, err := os.OpenRoot(filepath.Dir(env.installRoot))
	if err != nil {
		return phpmyadminResult{}, err
	}
	defer parent.Close()
	staging := "." + filepath.Base(env.installRoot) + ".staging"
	_ = parent.RemoveAll(staging)
	if err := parent.Mkdir(staging, 0o755); err != nil {
		return phpmyadminResult{}, err
	}
	stagingRoot, err := parent.OpenRoot(staging)
	if err != nil {
		return phpmyadminResult{}, err
	}
	if err := extractPHPMyAdminArchive(stagingRoot, archive); err != nil {
		stagingRoot.Close()
		_ = parent.RemoveAll(staging)
		return phpmyadminResult{}, err
	}
	stagingRoot.Close()
	// Upstream archives wrap everything in one top-level directory.
	stagingDir, err := parent.Open(staging)
	if err != nil {
		return phpmyadminResult{}, err
	}
	entries, err := stagingDir.ReadDir(-1)
	stagingDir.Close()
	if err != nil {
		return phpmyadminResult{}, err
	}
	inner := staging
	if len(entries) == 1 && entries[0].IsDir() {
		inner = filepath.Join(staging, entries[0].Name())
	}
	_ = parent.RemoveAll(filepath.Base(env.installRoot))
	if err := parent.Rename(inner, filepath.Base(env.installRoot)); err != nil {
		_ = parent.RemoveAll(staging)
		return phpmyadminResult{}, err
	}
	_ = parent.RemoveAll(staging)
	if _, err := parent.Stat(filepath.Base(env.installRoot) + "/index.php"); err != nil {
		return phpmyadminResult{}, errors.New("phpmyadmin archive layout is unexpected")
	}
	return phpmyadminResult{InstallPath: env.installRoot}, nil
}

func extractPHPMyAdminArchive(root *os.Root, archive []byte) error {
	decompressor, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return fmt.Errorf("open phpmyadmin archive: %w", err)
	}
	defer decompressor.Close()
	reader := tar.NewReader(decompressor)
	files := 0
	var expanded int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read phpmyadmin archive entry: %w", err)
		}
		if header.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeDir {
			return errors.New("phpmyadmin archive contains an unsafe entry")
		}
		trimmed := strings.TrimPrefix(strings.TrimSuffix(header.Name, "/"), "./")
		if trimmed == "" || strings.HasPrefix(trimmed, "/") || strings.Contains(trimmed, "..") {
			return errors.New("phpmyadmin archive contains an unsafe path")
		}
		if header.Typeflag == tar.TypeDir {
			if err := root.MkdirAll(trimmed, 0o755); err != nil {
				return err
			}
			continue
		}
		files++
		if files > 30_000 {
			return errors.New("phpmyadmin archive exceeds entry limits")
		}
		expanded += header.Size
		if expanded > 512<<20 {
			return errors.New("phpmyadmin archive exceeds size limits")
		}
		if parent := filepath.Dir(trimmed); parent != "." {
			if err := root.MkdirAll(parent, 0o755); err != nil {
				return err
			}
		}
		handle, err := root.OpenFile(trimmed, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		if _, err := io.CopyN(handle, reader, header.Size); err != nil {
			handle.Close()
			return err
		}
		if err := handle.Close(); err != nil {
			return err
		}
	}
}

func renderPHPMyAdminNginx(input phpmyadminActivateInput, authFile string) (string, error) {
	if !validSiteID(input.SiteID) {
		return "", errors.New("phpmyadmin.activate payload is invalid")
	}
	listen := "127.0.0.1:" + fmt.Sprint(input.Port)
	var serverName string
	var tls bool
	var builder strings.Builder
	switch input.Mode {
	case "private":
		if input.Port < 1 || input.Port > 65535 {
			return "", errors.New("phpmyadmin.activate port is invalid")
		}
	case "public_subdomain", "public_port":
		hostname, err := sites.NormalizeHostname(input.Hostname)
		if err != nil {
			return "", errors.New("phpmyadmin.activate hostname is invalid")
		}
		if input.Port < 1 || input.Port > 65535 {
			return "", errors.New("phpmyadmin.activate port is invalid")
		}
		listen = fmt.Sprint(input.Port) + " ssl"
		serverName = "server_name " + hostname + ";\n    "
		tls = true
	default:
		return "", errors.New("phpmyadmin.activate mode is unsupported")
	}
	builder.WriteString("# Managed by TomPanel: " + input.SiteID + "\n")
	builder.WriteString("server {\n")
	builder.WriteString("    listen " + listen + ";\n")
	if serverName != "" {
		builder.WriteString("    " + serverName)
	}
	builder.WriteString("    root " + phpMyAdminInstallRoot + ";\n")
	builder.WriteString("    index index.php;\n")
	if tls {
		builder.WriteString("    ssl_certificate " + filepath.Join(certificateRoot, input.SiteID, "fullchain.pem") + ";\n")
		builder.WriteString("    ssl_certificate_key " + filepath.Join(certificateRoot, input.SiteID, "privkey.pem") + ";\n")
		builder.WriteString("    limit_req zone=phpmyadmin burst=10 nodelay;\n")
		builder.WriteString("    auth_basic \"TomPanel phpMyAdmin\";\n")
		builder.WriteString("    auth_basic_user_file " + authFile + ";\n")
	}
	builder.WriteString("    location / {\n        try_files $uri $uri/ =404;\n    }\n")
	builder.WriteString("    location ~ \\.php$ {\n")
	builder.WriteString("        include snippets/fastcgi-php.conf;\n")
	builder.WriteString("        fastcgi_pass unix:/run/php/phpmyadmin-fpm.sock;\n")
	builder.WriteString("    }\n")
	builder.WriteString("}\n")
	return builder.String(), nil
}

func writePHPMyAdminAuth(ctx context.Context, env phpmyadminEnvironment, input phpmyadminActivateInput) (string, error) {
	if err := os.MkdirAll(env.authRoot, 0o750); err != nil {
		return "", err
	}
	root, err := os.OpenRoot(env.authRoot)
	if err != nil {
		return "", err
	}
	defer root.Close()
	name := "tompanel-" + input.SiteID + ".htpasswd"
	path := filepath.Join(env.authRoot, name)
	if input.BasicUser == "" || input.BasicSecret == "" {
		if _, err := root.ReadFile(name); err != nil {
			return "", errors.New("public phpmyadmin requires basic auth credentials")
		}
		return path, nil
	}
	if !validSystemUserName(input.BasicUser) || len(input.BasicSecret) < 16 || len(input.BasicSecret) > 128 {
		return "", errors.New("phpmyadmin basic auth payload is invalid")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.BasicSecret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	if err := writeTempInRoot(root, name, []byte(input.BasicUser+":"+string(hash)+"\n"), 0o640); err != nil {
		return "", err
	}
	return path, nil
}

func activatePHPMyAdmin(ctx context.Context, input phpmyadminActivateInput, env phpmyadminEnvironment) (phpmyadminResult, error) {
	authFile := ""
	if input.Mode == "public_subdomain" || input.Mode == "public_port" {
		var err error
		authFile, err = writePHPMyAdminAuth(ctx, env, input)
		if err != nil {
			return phpmyadminResult{}, err
		}
	}
	config, err := renderPHPMyAdminNginx(input, authFile)
	if err != nil {
		return phpmyadminResult{}, err
	}
	name := "tompanel-phpmyadmin-" + input.SiteID + ".conf"
	if err := activatePHPMyAdminConfig(ctx, name, config, env.nginx); err != nil {
		return phpmyadminResult{}, err
	}
	if input.Mode == "public_port" {
		if err := env.ufwEnsure(ctx, ufwInput{SiteID: input.SiteID, Port: input.Port}); err != nil {
			return phpmyadminResult{}, err
		}
	}
	return phpmyadminResult{ConfigPath: filepath.Join(env.nginx.root, name)}, nil
}

func disablePHPMyAdmin(ctx context.Context, input phpmyadminDisableInput, env phpmyadminEnvironment) error {
	if !validSiteID(input.SiteID) {
		return errors.New("phpmyadmin.disable payload is invalid")
	}
	if input.Port != 0 {
		if err := env.ufwRemove(ctx, ufwInput{SiteID: input.SiteID, Port: input.Port}); err != nil {
			return err
		}
	}
	if err := disablePHPMyAdminConfig(ctx, "tompanel-phpmyadmin-"+input.SiteID+".conf", env.nginx); err != nil {
		return err
	}
	if root, err := os.OpenRoot(env.authRoot); err == nil {
		_ = root.Remove("tompanel-" + input.SiteID + ".htpasswd")
		root.Close()
	}
	return nil
}

func activatePHPMyAdminConfig(ctx context.Context, name, content string, env nginxEnvironment) error {
	marker := "# Managed by TomPanel: "
	if !strings.HasPrefix(content, marker) || len(content) > 64<<10 {
		return errors.New("phpmyadmin nginx config is invalid")
	}
	nginxMu.Lock()
	defer nginxMu.Unlock()
	root, err := os.OpenRoot(env.root)
	if err != nil {
		return err
	}
	defer root.Close()
	if old, err := root.ReadFile(name); err == nil && !strings.HasPrefix(string(old), marker) {
		return errors.New("refusing to replace an unmanaged nginx config")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary := "." + name + ".candidate"
	if err := root.WriteFile(temporary, []byte(content), 0o640); err != nil {
		return err
	}
	defer root.Remove(temporary)
	if err := root.Rename(temporary, name); err != nil {
		return err
	}
	if err := env.run(ctx, "/usr/sbin/nginx", "-t"); err != nil {
		_ = root.Remove(name)
		return fmt.Errorf("validate phpmyadmin nginx config: %w", err)
	}
	if err := env.run(ctx, "/usr/bin/systemctl", "reload", "nginx"); err != nil {
		_ = root.Remove(name)
		_ = env.run(ctx, "/usr/bin/systemctl", "reload", "nginx")
		return fmt.Errorf("reload nginx: %w", err)
	}
	return nil
}

func disablePHPMyAdminConfig(ctx context.Context, name string, env nginxEnvironment) error {
	nginxMu.Lock()
	defer nginxMu.Unlock()
	root, err := os.OpenRoot(env.root)
	if err != nil {
		return err
	}
	defer root.Close()
	old, err := root.ReadFile(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(old), "# Managed by TomPanel: ") {
		return errors.New("refusing to disable an unmanaged nginx config")
	}
	if err := root.Remove(name); err != nil {
		return err
	}
	if err := env.run(ctx, "/usr/sbin/nginx", "-t"); err != nil {
		_ = root.WriteFile(name, old, 0o640)
		return err
	}
	if err := env.run(ctx, "/usr/bin/systemctl", "reload", "nginx"); err != nil {
		_ = root.WriteFile(name, old, 0o640)
		_ = env.run(ctx, "/usr/bin/systemctl", "reload", "nginx")
		return err
	}
	return nil
}
