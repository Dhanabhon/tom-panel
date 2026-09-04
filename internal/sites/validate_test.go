package sites

import (
	"errors"
	"testing"
)

func TestValidateCreateRejectsEndpointCollision(t *testing.T) {
	in := CreateInput{Kind: KindPHP, PrimaryDomain: "shop.example.com", HTTPSPort: 443, PHPVersion: "8.4"}
	err := ValidateCreate(in, []Endpoint{{Hostname: "shop.example.com", Port: 443, Owner: "panel"}})
	if !errors.Is(err, ErrEndpointOccupied) {
		t.Fatalf("ValidateCreate() error = %v, want %v", err, ErrEndpointOccupied)
	}
}

func TestValidateCreateNormalizesIDNAForCollisionChecks(t *testing.T) {
	in := CreateInput{Kind: KindStatic, PrimaryDomain: "BÜCHER.example", HTTPSPort: 443}
	err := ValidateCreate(in, []Endpoint{{Hostname: "xn--bcher-kva.example", Port: 443, Owner: "site-1"}})
	if !errors.Is(err, ErrEndpointOccupied) {
		t.Fatalf("ValidateCreate() error = %v, want %v", err, ErrEndpointOccupied)
	}
}

func TestValidateCreateRejectsNonLoopbackProxyTarget(t *testing.T) {
	in := CreateInput{
		Kind:          KindReverseProxy,
		PrimaryDomain: "app.example.com",
		HTTPSPort:     443,
		ProxyTarget:   "http://10.0.0.5:3000",
	}
	if err := ValidateCreate(in, nil); !errors.Is(err, ErrInvalidProxyTarget) {
		t.Fatalf("ValidateCreate() error = %v, want %v", err, ErrInvalidProxyTarget)
	}
}

func TestStateTransitionRejectsActiveToProvisioning(t *testing.T) {
	if err := ValidateStateTransition(StateActive, StateProvisioning); !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("ValidateStateTransition() error = %v, want %v", err, ErrInvalidStateTransition)
	}
}
