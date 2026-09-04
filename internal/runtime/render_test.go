package runtime

import (
	"strings"
	"testing"
)

func TestRenderPoolDerivesIdentityAndBoundsPaths(t *testing.T) {
	config, err := RenderPool("0123456789abcdef0123456789abcdef", PHPConfig{
		Version: "8.4", MemoryMB: 256, UploadMB: 64, PostMB: 64,
		ExecutionSeconds: 60, InputVars: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[tp_0123456789abcdef]",
		"user = tp_0123456789abcdef",
		"listen = /run/php/tp_0123456789abcdef.sock",
		"php_admin_value[open_basedir] = /srv/tompanel/sites/0123456789abcdef0123456789abcdef:/tmp",
		"php_admin_value[post_max_size] = 64M",
	} {
		if !strings.Contains(string(config), want) {
			t.Errorf("pool config omitted %q:\n%s", want, config)
		}
	}
}
