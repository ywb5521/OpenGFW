package bundle

import (
	"testing"

	"github.com/apernet/OpenGFW/pkg/models"
)

func TestValidateBundle(t *testing.T) {
	valid := models.Bundle{
		Version: "v1",
		Rules: []models.RuleSpec{
			{Name: "allow-dns", Action: "allow", Expr: `proto == "udp"`},
		},
	}
	if err := Validate(valid); err != nil {
		t.Fatalf("expected valid bundle, got %v", err)
	}
}

func TestValidateBundleRejectsDuplicateRules(t *testing.T) {
	invalid := models.Bundle{
		Version: "v1",
		Rules: []models.RuleSpec{
			{Name: "dup", Action: "allow", Expr: "true"},
			{Name: "dup", Action: "block", Expr: "false"},
		},
	}
	if err := Validate(invalid); err == nil {
		t.Fatal("expected duplicate rule validation error")
	}
}
