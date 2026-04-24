package policy

import (
	"encoding/json"
	"testing"

	"github.com/apernet/OpenGFW/pkg/models"
	opengfwcore "github.com/apernet/OpenGFW/pkg/opengfw"
)

func TestServiceIncludesReadonlyDefaultReportingBundle(t *testing.T) {
	svc := NewService()

	bundle, ok := svc.GetBundle(DefaultReportingBundleVersion)
	if !ok {
		t.Fatalf("expected built-in bundle %q to exist", DefaultReportingBundleVersion)
	}
	if !bundle.Readonly {
		t.Fatalf("expected built-in bundle %q to be readonly", DefaultReportingBundleVersion)
	}
	if !bundle.Runtime.IO.Local {
		t.Fatalf("expected built-in bundle to keep local capture enabled, got %+v", bundle.Runtime.IO)
	}
	if !bundle.Telemetry.Events.RuleHit || !bundle.Telemetry.Events.FlowSummary || bundle.Telemetry.Events.SuspiciousOnly {
		t.Fatalf("unexpected built-in telemetry events: %+v", bundle.Telemetry.Events)
	}
	if len(bundle.Telemetry.Analyzers) != len(opengfwcore.DefaultAnalyzers()) {
		t.Fatalf("unexpected built-in analyzers: %+v", bundle.Telemetry.Analyzers)
	}
}

func TestAssignBundleMergesDefaultReportingTelemetry(t *testing.T) {
	svc := NewService()
	custom := models.Bundle{
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
	}
	if err := svc.AddBundle(custom); err != nil {
		t.Fatalf("failed to add custom bundle: %v", err)
	}

	tasks, err := svc.AssignBundle(custom.Version, []string{"agent-1"})
	if err != nil {
		t.Fatalf("failed to assign custom bundle: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}

	var payload models.BundleTaskPayload
	if err := json.Unmarshal(tasks[0].Payload, &payload); err != nil {
		t.Fatalf("failed to decode task payload: %v", err)
	}
	if payload.Bundle.Version != custom.Version {
		t.Fatalf("expected merged bundle to keep custom version %q, got %q", custom.Version, payload.Bundle.Version)
	}
	if payload.Bundle.Runtime.IO.Local {
		t.Fatalf("expected merged bundle to preserve custom capture mode, got %+v", payload.Bundle.Runtime.IO)
	}
	if !payload.Bundle.Telemetry.Events.RuleHit || !payload.Bundle.Telemetry.Events.FlowSummary || payload.Bundle.Telemetry.Events.SuspiciousOnly {
		t.Fatalf("unexpected merged telemetry events: %+v", payload.Bundle.Telemetry.Events)
	}
	if len(payload.Bundle.Telemetry.Analyzers) != len(opengfwcore.DefaultAnalyzers()) {
		t.Fatalf("expected merged bundle to force all default analyzers, got %+v", payload.Bundle.Telemetry.Analyzers)
	}
	if len(payload.Bundle.Rules) != 1 || payload.Bundle.Rules[0].Name != "allow-all" {
		t.Fatalf("expected merged bundle to keep custom rules, got %+v", payload.Bundle.Rules)
	}
}
