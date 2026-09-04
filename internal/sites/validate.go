package sites

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

var (
	ErrInvalidSite            = errors.New("invalid site")
	ErrEndpointOccupied       = errors.New("site endpoint is already occupied")
	ErrInvalidProxyTarget     = errors.New("reverse proxy target must be a loopback HTTP endpoint")
	ErrInvalidStateTransition = errors.New("invalid site state transition")
)

func ValidateCreate(input CreateInput, occupied []Endpoint) error {
	hostname, err := NormalizeHostname(input.PrimaryDomain)
	if err != nil {
		return err
	}
	if input.HTTPSPort < 1 || input.HTTPSPort > 65535 || input.HTTPPort < 0 || input.HTTPPort > 65535 {
		return fmt.Errorf("%w: port is outside 1-65535", ErrInvalidSite)
	}

	switch input.Kind {
	case KindStatic:
		if input.PHPVersion != "" || input.ProxyTarget != "" {
			return fmt.Errorf("%w: static sites cannot configure PHP or an upstream", ErrInvalidSite)
		}
	case KindPHP:
		if !supportedPHPVersion(input.PHPVersion) || input.ProxyTarget != "" {
			return fmt.Errorf("%w: PHP sites require a supported PHP version", ErrInvalidSite)
		}
	case KindReverseProxy:
		if input.PHPVersion != "" || validateProxyTarget(input.ProxyTarget) != nil {
			return ErrInvalidProxyTarget
		}
	default:
		return fmt.Errorf("%w: unknown kind", ErrInvalidSite)
	}

	for _, endpoint := range occupied {
		other, err := NormalizeHostname(endpoint.Hostname)
		if err == nil && other == hostname && (endpoint.Port == input.HTTPSPort || input.HTTPPort != 0 && endpoint.Port == input.HTTPPort) {
			return fmt.Errorf("%w: owned by %s", ErrEndpointOccupied, endpoint.Owner)
		}
	}
	return nil
}

func ValidateStateTransition(from, to State) error {
	if from == to {
		return nil
	}
	allowed := map[State]map[State]bool{
		StateProvisioning: {StateActive: true, StateFailed: true, StateDisabled: true},
		StateActive:       {StateFailed: true, StateDisabled: true},
		StateFailed:       {StateProvisioning: true, StateDisabled: true},
		StateDisabled:     {StateActive: true, StateProvisioning: true, StateFailed: true},
	}
	if !allowed[from][to] {
		return fmt.Errorf("%w: %s to %s", ErrInvalidStateTransition, from, to)
	}
	return nil
}

func NormalizeHostname(value string) (string, error) {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	ASCII, err := idna.Lookup.ToASCII(value)
	if err != nil || len(ASCII) > 253 || net.ParseIP(ASCII) != nil {
		return "", fmt.Errorf("%w: invalid hostname", ErrInvalidSite)
	}
	labels := strings.Split(ASCII, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%w: hostname must contain at least two labels", ErrInvalidSite)
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || !isAlphaNumeric(label[0]) || !isAlphaNumeric(label[len(label)-1]) {
			return "", fmt.Errorf("%w: invalid hostname", ErrInvalidSite)
		}
		for i := 1; i < len(label)-1; i++ {
			if !isAlphaNumeric(label[i]) && label[i] != '-' {
				return "", fmt.Errorf("%w: invalid hostname", ErrInvalidSite)
			}
		}
	}
	return ASCII, nil
}

func validateProxyTarget(value string) error {
	target, err := url.Parse(value)
	if err != nil || target.Scheme != "http" && target.Scheme != "https" || target.User != nil || target.Hostname() == "" || target.Port() == "" || target.RawQuery != "" || target.Fragment != "" {
		return ErrInvalidProxyTarget
	}
	port, err := strconv.Atoi(target.Port())
	if err != nil || port < 1 || port > 65535 {
		return ErrInvalidProxyTarget
	}
	host := strings.ToLower(target.Hostname())
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return ErrInvalidProxyTarget
	}
	return nil
}

func supportedPHPVersion(version string) bool {
	return version == "8.3" || version == "8.4" || version == "8.5"
}

func isAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}
