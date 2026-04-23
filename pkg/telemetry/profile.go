package telemetry

import (
	"sort"

	"github.com/apernet/OpenGFW/pkg/models"
)

func DefaultProfile() models.TelemetryProfile {
	return models.TelemetryProfile{
		Events: models.TelemetryEvents{
			RuleHit:     true,
			FlowSummary: true,
		},
	}
}

func NormalizeProfile(profile models.TelemetryProfile) models.TelemetryProfile {
	if !profile.Events.RuleHit && !profile.Events.SuspiciousOnly && !profile.Events.FlowSummary {
		profile.Events = DefaultProfile().Events
	}
	if profile.Sampling.BenignFlow < 0 {
		profile.Sampling.BenignFlow = 0
	}
	if profile.Sampling.BenignFlow > 1 {
		profile.Sampling.BenignFlow = 1
	}
	seen := make(map[string]struct{}, len(profile.Analyzers))
	var analyzers []string
	for _, analyzer := range profile.Analyzers {
		if analyzer == "" {
			continue
		}
		if _, ok := seen[analyzer]; ok {
			continue
		}
		seen[analyzer] = struct{}{}
		analyzers = append(analyzers, analyzer)
	}
	sort.Strings(analyzers)
	profile.Analyzers = analyzers
	return profile
}
