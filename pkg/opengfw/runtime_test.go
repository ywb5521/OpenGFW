package opengfw

import (
	"testing"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/pkg/models"
	"github.com/apernet/OpenGFW/ruleset"
)

type fakeRuleset struct {
	analyzers []analyzer.Analyzer
}

func (r *fakeRuleset) Analyzers(info ruleset.StreamInfo) []analyzer.Analyzer {
	return r.analyzers
}

func (r *fakeRuleset) Match(info ruleset.StreamInfo) ruleset.MatchResult {
	return ruleset.MatchResult{Action: ruleset.ActionMaybe}
}

type fakeAnalyzer struct {
	name string
}

func (a fakeAnalyzer) Name() string { return a.name }

func (a fakeAnalyzer) Limit() int { return 0 }

func TestWrapRulesetWithTelemetryAddsForcedAnalyzers(t *testing.T) {
	base := &fakeRuleset{
		analyzers: []analyzer.Analyzer{fakeAnalyzer{name: "http"}},
	}
	wrapped, err := WrapRulesetWithTelemetry(base, models.TelemetryProfile{
		Analyzers: []string{"dns", "http"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	analyzers := wrapped.Analyzers(ruleset.StreamInfo{})
	names := make(map[string]struct{}, len(analyzers))
	for _, analyzer := range analyzers {
		names[analyzer.Name()] = struct{}{}
	}
	if _, ok := names["http"]; !ok {
		t.Fatal("expected http analyzer to remain enabled")
	}
	if _, ok := names["dns"]; !ok {
		t.Fatal("expected dns analyzer to be forced by telemetry")
	}
}

func TestWrapRulesetWithTelemetryRejectsUnknownAnalyzer(t *testing.T) {
	_, err := WrapRulesetWithTelemetry(&fakeRuleset{}, models.TelemetryProfile{
		Analyzers: []string{"not-exists"},
	})
	if err == nil {
		t.Fatal("expected unknown analyzer error")
	}
}
