package domains

import (
	"strings"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/sites"
)

func TestRenderPHPVirtualHost(t *testing.T) {
	config, err := RenderNginx(sites.Site{
		ID:            "0123456789abcdef0123456789abcdef",
		Kind:          sites.KindPHP,
		PrimaryDomain: "shop.example.com",
		HTTPPort:      80,
		HTTPSPort:     443,
		PHPVersion:    "8.4",
	}, []Hostname{"shop.example.com", "www.shop.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"# Managed by TomPanel: 0123456789abcdef0123456789abcdef",
		"listen 80;",
		"server_name shop.example.com www.shop.example.com;",
		"root /srv/tompanel/sites/0123456789abcdef0123456789abcdef/public;",
		"fastcgi_pass unix:/run/php/tp_0123456789abcdef.sock;",
		"try_files $uri $uri/ /index.php?$query_string;",
	}
	for _, fragment := range want {
		if !strings.Contains(string(config), fragment) {
			t.Errorf("config omitted %q:\n%s", fragment, config)
		}
	}
}

func TestRenderNginxRejectsInjectedHostname(t *testing.T) {
	_, err := RenderNginx(sites.Site{
		ID: "0123456789abcdef0123456789abcdef", Kind: sites.KindStatic, HTTPPort: 80,
	}, []Hostname{"good.example.com; include /etc/passwd"})
	if err == nil {
		t.Fatal("directive injection hostname accepted")
	}
}
