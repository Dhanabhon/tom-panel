package domains

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/sites"
)

type Hostname string

func RenderNginx(site sites.Site, hostnames []Hostname) ([]byte, error) {
	if len(site.ID) != 32 || site.HTTPPort < 1 || site.HTTPPort > 65535 {
		return nil, errors.New("site identity or HTTP port is invalid")
	}
	input := sites.CreateInput{
		Kind: site.Kind, PrimaryDomain: site.PrimaryDomain, HTTPPort: site.HTTPPort,
		HTTPSPort: site.HTTPSPort, Public: site.Public, PHPVersion: site.PHPVersion, ProxyTarget: site.ProxyTarget,
	}
	if err := sites.ValidateCreate(input, nil); err != nil {
		return nil, err
	}

	names := make([]string, 0, len(hostnames))
	seen := make(map[string]bool, len(hostnames))
	for _, value := range hostnames {
		name, err := sites.NormalizeHostname(string(value))
		if err != nil {
			return nil, err
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, errors.New("at least one hostname is required")
	}
	sort.Strings(names)

	root := "/srv/tompanel/sites/" + site.ID + "/public"
	var body string
	switch site.Kind {
	case sites.KindStatic:
		body = "    location / { try_files $uri $uri/ =404; }\n"
	case sites.KindPHP:
		body = fmt.Sprintf("    location / { try_files $uri $uri/ /index.php?$query_string; }\n"+
			"    location ~ \\.php$ {\n        include snippets/fastcgi-php.conf;\n        fastcgi_pass unix:/run/php/tp_%s.sock;\n    }\n", site.ID[:16])
	case sites.KindReverseProxy:
		body = fmt.Sprintf("    location / {\n        proxy_pass %s;\n        proxy_set_header Host $host;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }\n", site.ProxyTarget)
	default:
		return nil, errors.New("unsupported site kind")
	}

	access := ""
	if !site.Public {
		access = "    allow 127.0.0.1;\n    allow ::1;\n    deny all;\n"
	}
	config := fmt.Sprintf("# Managed by TomPanel: %s\nserver {\n    listen %d;\n    server_name %s;\n    root %s;\n    index index.html index.php;\n%s%s}\n",
		site.ID, site.HTTPPort, strings.Join(names, " "), root, access, body)
	return []byte(config), nil
}
