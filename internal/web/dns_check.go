package web

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/operations"
)

// dnsCheckHandler verifies that a hostname's A record points to this
// server. It powers the setup wizard's domain-binding step.
func (h *SettingsHandlers) dnsCheck(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth.CurrentSession(r.Context()); !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	hostname := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("hostname")))
	if hostname == "" || len(hostname) > 253 {
		encodeJSON(w, http.StatusBadRequest, map[string]string{"error": "hostname is required"})
		return
	}
	if !operations.ValidEndpointHostname(hostname) {
		encodeJSON(w, http.StatusBadRequest, map[string]string{"error": "hostname is malformed"})
		return
	}

	resolver := &net.Resolver{}
	ctx, cancel := context.WithTimeout(r.Context(), operations.DNSTimeout)
	defer cancel()
	addrs, err := resolver.LookupHost(ctx, hostname)
	if err != nil || len(addrs) == 0 {
		encodeJSON(w, http.StatusOK, map[string]any{
			"hostname":  hostname,
			"status":    "no_dns",
			"message":   "No DNS record found for this hostname. Create an A record pointing it to your server IP.",
			"server_ip": operations.ServerPublicIP(r.Context()),
		})
		return
	}

	serverIP := operations.ServerPublicIP(r.Context())
	type addrStatus struct {
		Address string `json:"address"`
		IsThis  bool   `json:"is_this_server"`
	}
	addresses := make([]addrStatus, 0, len(addrs))
	matched := false
	for _, addr := range addrs {
		is := addr == serverIP
		if is {
			matched = true
		}
		addresses = append(addresses, addrStatus{Address: addr, IsThis: is})
	}

	if matched {
		encodeJSON(w, http.StatusOK, map[string]any{
			"hostname":  hostname,
			"status":    "ok",
			"message":   "DNS verified — this hostname points to your server.",
			"server_ip": serverIP,
			"addresses": addresses,
		})
		return
	}

	encodeJSON(w, http.StatusOK, map[string]any{
		"hostname":  hostname,
		"status":    "mismatch",
		"message":   "DNS points to a different address. Update the A record to " + serverIP + ".",
		"server_ip": serverIP,
		"addresses": addresses,
	})
}

func encodeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
