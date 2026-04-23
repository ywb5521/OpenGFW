package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apernet/OpenGFW/pkg/models"
)

func TestStageArtifact(t *testing.T) {
	payload := []byte("agent-binary")
	hash := sha256.Sum256(payload)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	dir := t.TempDir()
	stager, err := NewStager(dir, server.Client())
	if err != nil {
		t.Fatalf("failed to create stager: %v", err)
	}

	path, err := stager.Stage(context.Background(), models.ReleaseArtifact{
		Version:     "v1.0.0",
		DownloadURL: server.URL + "/opengfw-agent",
		Checksum:    hex.EncodeToString(hash[:]),
	})
	if err != nil {
		t.Fatalf("failed to stage artifact: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read staged artifact: %v", err)
	}
	if string(data) != string(payload) {
		t.Fatalf("unexpected artifact payload: %q", string(data))
	}
	if filepath.Base(path) != "opengfw-agent" {
		t.Fatalf("unexpected artifact filename: %s", filepath.Base(path))
	}
}

func TestStageArtifactRejectsBadChecksum(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("agent-binary"))
	}))
	defer server.Close()

	stager, err := NewStager(t.TempDir(), server.Client())
	if err != nil {
		t.Fatalf("failed to create stager: %v", err)
	}

	_, err = stager.Stage(context.Background(), models.ReleaseArtifact{
		Version:     "v1.0.0",
		DownloadURL: server.URL + "/opengfw-agent",
		Checksum:    "deadbeef",
	})
	if err == nil {
		t.Fatal("expected checksum error")
	}
}

func TestBuildApplyCommand(t *testing.T) {
	command := buildApplyCommand("/tmp/opengfw-agent", "/usr/local/bin/opengfw-agent", "opengfw-agent", "", "")
	if !strings.HasPrefix(command, "nohup sh -lc ") {
		t.Fatalf("unexpected prefix: %q", command)
	}
	if !containsAll(command, "install -m 0755", "systemctl restart") {
		t.Fatalf("expected install and restart in command: %s", command)
	}
}

func TestBuildApplyCommandWithVersionFile(t *testing.T) {
	command := buildApplyCommand("/tmp/opengfw-agent", "/usr/local/bin/opengfw-agent", "opengfw-agent", "/var/lib/opengfw-agent/agent-version", "v1.2.3")
	if !containsAll(command, "agent-version", "v1.2.3", "systemctl restart") {
		t.Fatalf("expected version write and restart in command: %s", command)
	}
}

func TestResolveReleaseAssetSelectsMatchingPlatform(t *testing.T) {
	asset, err := resolveReleaseAsset(models.ReleaseArtifact{
		Version: "v1.2.3",
		Assets: []models.ReleaseAsset{
			{GOOS: "linux", GOARCH: "amd64", DownloadURL: "https://example.com/linux-amd64", Checksum: "sha256:a"},
			{GOOS: "linux", GOARCH: "arm64", DownloadURL: "https://example.com/linux-arm64", Checksum: "sha256:b"},
		},
	}, "linux", "arm64")
	if err != nil {
		t.Fatalf("resolve release asset failed: %v", err)
	}
	if asset.GOARCH != "arm64" || asset.DownloadURL != "https://example.com/linux-arm64" {
		t.Fatalf("unexpected asset: %+v", asset)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}
