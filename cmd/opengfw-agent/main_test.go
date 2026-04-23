package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveAgentVersionPrefersExplicitValue(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent-version"), []byte("v2.0.0\n"), 0o644); err != nil {
		t.Fatalf("write version file: %v", err)
	}
	if got := resolveAgentVersion("v9.9.9", dir); got != "v9.9.9" {
		t.Fatalf("expected explicit version, got %q", got)
	}
}

func TestResolveAgentVersionUsesVersionFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent-version"), []byte("v2.0.0\n"), 0o644); err != nil {
		t.Fatalf("write version file: %v", err)
	}
	if got := resolveAgentVersion("", dir); got != "v2.0.0" {
		t.Fatalf("expected version from file, got %q", got)
	}
}
