package agentbuild

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apernet/OpenGFW/pkg/models"
)

type fakeRunner struct {
	calls int
}

func (r *fakeRunner) Run(_ context.Context, _ string, _ []string, args []string) error {
	r.calls++
	output := ""
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-o" {
			output = args[i+1]
			break
		}
	}
	if output == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return err
	}
	return os.WriteFile(output, []byte("agent-binary"), 0o755)
}

func TestEnsureBinaryBuildsWhenMissing(t *testing.T) {
	root := prepareAgentProject(t)
	runner := &fakeRunner{}
	service, err := NewService(Config{
		ProjectRoot: root,
		OutputRoot:  filepath.Join(root, "build-out"),
		SourcePaths: []string{"go.mod", "cmd/opengfw-agent"},
		Runner:      runner,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	info, err := service.EnsureBinary(context.Background(), models.AgentBuildRequest{
		GOOS:   "linux",
		GOARCH: "amd64",
	})
	if err != nil {
		t.Fatalf("ensure binary: %v", err)
	}
	if !info.Rebuilt {
		t.Fatal("expected build to run for missing binary")
	}
	if runner.calls != 1 {
		t.Fatalf("expected one build invocation, got %d", runner.calls)
	}
	if info.GOOS != "linux" || info.GOARCH != "amd64" {
		t.Fatalf("unexpected target: %+v", info)
	}
	if info.Checksum == "" {
		t.Fatal("expected checksum to be populated")
	}
	if _, err := os.Stat(info.BinaryPath); err != nil {
		t.Fatalf("expected built binary at %s: %v", info.BinaryPath, err)
	}
}

func TestEnsureBinarySkipsUpToDateBuild(t *testing.T) {
	root := prepareAgentProject(t)
	outputRoot := filepath.Join(root, "build-out")
	outputPath := filepath.Join(outputRoot, "linux", "amd64", defaultBinaryName)
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		t.Fatalf("mkdir output: %v", err)
	}
	if err := os.WriteFile(outputPath, []byte("existing-binary"), 0o755); err != nil {
		t.Fatalf("write output: %v", err)
	}

	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(outputPath, future, future); err != nil {
		t.Fatalf("chtimes output: %v", err)
	}

	runner := &fakeRunner{}
	service, err := NewService(Config{
		ProjectRoot: root,
		OutputRoot:  outputRoot,
		SourcePaths: []string{"go.mod", "cmd/opengfw-agent"},
		Runner:      runner,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	info, err := service.EnsureBinary(context.Background(), models.AgentBuildRequest{
		GOOS:   "linux",
		GOARCH: "amd64",
	})
	if err != nil {
		t.Fatalf("ensure binary: %v", err)
	}
	if info.Rebuilt {
		t.Fatal("expected up-to-date binary to be reused")
	}
	if runner.calls != 0 {
		t.Fatalf("expected no build invocation, got %d", runner.calls)
	}
}

func TestEnsureBinaryForceRebuilds(t *testing.T) {
	root := prepareAgentProject(t)
	outputRoot := filepath.Join(root, "build-out")
	outputPath := filepath.Join(outputRoot, "linux", "amd64", defaultBinaryName)
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		t.Fatalf("mkdir output: %v", err)
	}
	if err := os.WriteFile(outputPath, []byte("existing-binary"), 0o755); err != nil {
		t.Fatalf("write output: %v", err)
	}

	runner := &fakeRunner{}
	service, err := NewService(Config{
		ProjectRoot: root,
		OutputRoot:  outputRoot,
		SourcePaths: []string{"go.mod", "cmd/opengfw-agent"},
		Runner:      runner,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	info, err := service.EnsureBinary(context.Background(), models.AgentBuildRequest{
		GOOS:   "linux",
		GOARCH: "amd64",
		Force:  true,
	})
	if err != nil {
		t.Fatalf("ensure binary: %v", err)
	}
	if !info.Rebuilt {
		t.Fatal("expected force rebuild to rebuild binary")
	}
	if runner.calls != 1 {
		t.Fatalf("expected one build invocation, got %d", runner.calls)
	}
}

func prepareAgentProject(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "cmd", "opengfw-agent"), 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/opengfw\n\ngo 1.26.2\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	mainPath := filepath.Join(root, "cmd", "opengfw-agent", "main.go")
	if err := os.WriteFile(mainPath, []byte("package main\nfunc main(){}\n"), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	now := time.Now().Add(-time.Minute)
	if err := os.Chtimes(mainPath, now, now); err != nil {
		t.Fatalf("chtimes main.go: %v", err)
	}
	return root
}
