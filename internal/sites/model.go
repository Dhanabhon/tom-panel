package sites

import "time"

type Kind string

const (
	KindStatic       Kind = "static"
	KindPHP          Kind = "php"
	KindReverseProxy Kind = "reverse_proxy"
)

type State string

const (
	StateProvisioning State = "provisioning"
	StateActive       State = "active"
	StateFailed       State = "failed"
	StateDisabled     State = "disabled"
)

type CreateInput struct {
	Kind          Kind   `json:"kind"`
	PrimaryDomain string `json:"primary_domain"`
	HTTPPort      int    `json:"http_port,omitempty"`
	HTTPSPort     int    `json:"https_port"`
	Public        bool   `json:"public"`
	PHPVersion    string `json:"php_version,omitempty"`
	ProxyTarget   string `json:"proxy_target,omitempty"`
}

type Site struct {
	ID            string
	Kind          Kind
	State         State
	PrimaryDomain string
	HTTPPort      int
	HTTPSPort     int
	Public        bool
	PHPVersion    string
	ProxyTarget   string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Endpoint struct {
	Hostname string
	Port     int
	Owner    string
}
