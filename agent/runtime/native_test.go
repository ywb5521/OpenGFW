package runtime

import (
	"context"
	"testing"

	"github.com/apernet/OpenGFW/pkg/models"
	"github.com/apernet/OpenGFW/pkg/telemetry"
)

func TestDefaultTelemetryBundleUsesDefaultProfileAndAnalyzers(t *testing.T) {
	bundle := defaultTelemetryBundle()
	profile := telemetry.DefaultProfile()

	if bundle.Version != "" {
		t.Fatalf("expected built-in bundle version to stay empty, got %q", bundle.Version)
	}
	if !bundle.Runtime.IO.Local {
		t.Fatalf("expected built-in telemetry bundle to capture local traffic by default, got %+v", bundle.Runtime.IO)
	}
	if bundle.Telemetry.Events != profile.Events {
		t.Fatalf("unexpected default telemetry events: %+v", bundle.Telemetry.Events)
	}
	if len(bundle.Telemetry.Analyzers) == 0 {
		t.Fatal("expected built-in telemetry bundle to force analyzers")
	}
}

func TestApplyBundleForcesDefaultTelemetryProfile(t *testing.T) {
	rt := NewNativeRuntime(nil, nil)
	err := rt.ApplyBundle(context.Background(), models.Bundle{
		Version: "custom-rules",
		Runtime: models.RuntimeConfig{
			IO: models.RuntimeIOConfig{
				Local: false,
			},
		},
		Telemetry: models.TelemetryProfile{
			Events: models.TelemetryEvents{
				SuspiciousOnly: true,
			},
		},
		Rules: []models.RuleSpec{
			{
				Name:   "allow-all",
				Action: "allow",
				Expr:   "true",
			},
		},
	})
	if err != nil {
		t.Fatalf("apply bundle failed: %v", err)
	}

	profile := rt.currentProfile()
	if !profile.Events.RuleHit || !profile.Events.FlowSummary || profile.Events.SuspiciousOnly {
		t.Fatalf("expected default telemetry events to be enforced, got %+v", profile.Events)
	}
	if rt.active.Runtime.IO.Local {
		t.Fatalf("expected bundle capture mode to be preserved, got %+v", rt.active.Runtime.IO)
	}
}
