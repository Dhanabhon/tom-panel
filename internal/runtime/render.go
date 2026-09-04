package runtime

import (
	"errors"
	"fmt"
)

func RenderPool(siteID string, config PHPConfig) ([]byte, error) {
	if !validSiteID(siteID) {
		return nil, errors.New("site ID is invalid")
	}
	if err := ValidatePHPConfig(config); err != nil {
		return nil, err
	}
	name := "tp_" + siteID[:16]
	displayErrors := "Off"
	if config.DisplayErrors {
		displayErrors = "On"
	}
	return []byte(fmt.Sprintf(`; Managed by TomPanel: %s
[%s]
user = %s
group = %s
listen = /run/php/%s.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 8
pm.process_idle_timeout = 10s
pm.max_requests = 500
php_admin_value[memory_limit] = %dM
php_admin_value[upload_max_filesize] = %dM
php_admin_value[post_max_size] = %dM
php_admin_value[max_execution_time] = %d
php_admin_value[max_input_vars] = %d
php_admin_value[display_errors] = %s
php_admin_value[open_basedir] = /srv/tompanel/sites/%s:/tmp
`, siteID, name, name, name, name, config.MemoryMB, config.UploadMB, config.PostMB,
		config.ExecutionSeconds, config.InputVars, displayErrors, siteID)), nil
}

func validSiteID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, character := range id {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}
