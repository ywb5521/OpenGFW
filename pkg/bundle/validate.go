package bundle

import (
	"fmt"

	"github.com/apernet/OpenGFW/pkg/models"
	"github.com/apernet/OpenGFW/pkg/telemetry"
)

func Normalize(b models.Bundle) models.Bundle {
	b.Telemetry = telemetry.NormalizeProfile(b.Telemetry)
	return b
}

func Validate(b models.Bundle) error {
	if b.Version == "" {
		return fmt.Errorf("bundle version is required")
	}
	seenRules := make(map[string]struct{}, len(b.Rules))
	for i, rule := range b.Rules {
		if rule.Name == "" {
			return fmt.Errorf("rule %d must have a name", i)
		}
		if _, ok := seenRules[rule.Name]; ok {
			return fmt.Errorf("duplicate rule name %q", rule.Name)
		}
		seenRules[rule.Name] = struct{}{}
		if rule.Expr == "" {
			return fmt.Errorf("rule %q must have an expr", rule.Name)
		}
		if rule.Action == "" && !rule.Log {
			return fmt.Errorf("rule %q must have action or log enabled", rule.Name)
		}
		if rule.Action == "modify" {
			if rule.Modifier == nil || rule.Modifier.Name == "" {
				return fmt.Errorf("rule %q must define modifier for modify action", rule.Name)
			}
		}
	}
	if b.Telemetry.Sampling.BenignFlow < 0 || b.Telemetry.Sampling.BenignFlow > 1 {
		return fmt.Errorf("telemetry sampling.benignFlow must be between 0 and 1")
	}
	return nil
}
