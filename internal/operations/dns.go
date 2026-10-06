package operations

import (
	"context"
	"net"
	"regexp"
	"time"
)

// DNSTimeout bounds DNS resolution checks.
const DNSTimeout = 5 * time.Second

var hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// ValidEndpointHostname reports whether the hostname is syntactically valid
// for the panel endpoint (lowercase, no protocol, no port, no wildcard).
func ValidEndpointHostname(hostname string) bool {
	return hostnamePattern.MatchString(hostname) && len(hostname) <= 253
}

// ServerPublicIP attempts to discover this server's public IPv4 address.
// Falls back to the first non-loopback interface address if the discovery
// service is unreachable.
func ServerPublicIP(ctx context.Context) string {
	discoverCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if conn, err := net.DialTimeout("udp", "8.8.8.8:53", 2*time.Second); err == nil {
		_ = conn.Close()
		local := conn.LocalAddr().(*net.UDPAddr)
		if local.IP != nil && !local.IP.IsLoopback() {
			_ = discoverCtx
			return local.IP.String()
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "unknown"
}
