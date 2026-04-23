package agentbuild

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/apernet/OpenGFW/pkg/models"
)

const (
	defaultBinaryName = "opengfw-agent"
)

type CommandRunner interface {
	Run(ctx context.Context, dir string, env []string, args []string) error
}

type Config struct {
	ProjectRoot string
	OutputRoot  string
	SourcePaths []string
	Runner      CommandRunner
}

type Service struct {
	projectRoot string
	outputRoot  string
	sourcePaths []string
	runner      CommandRunner
}

type execRunner struct{}

func NewService(cfg Config) (*Service, error) {
	projectRoot := strings.TrimSpace(cfg.ProjectRoot)
	if projectRoot == "" {
		detected, err := findProjectRoot()
		if err != nil {
			return nil, err
		}
		projectRoot = detected
	}
	outputRoot := strings.TrimSpace(cfg.OutputRoot)
	if outputRoot == "" {
		outputRoot = filepath.Join(projectRoot, ".dev-runtime", "build", "agent")
	}
	sourcePaths := cfg.SourcePaths
	if len(sourcePaths) == 0 {
		sourcePaths = []string{
			"go.mod",
			"go.sum",
			"cmd/opengfw-agent",
			"agent",
			"analyzer",
			"engine",
			"io",
			"modifier",
			"pkg",
			"ruleset",
		}
	}
	runner := cfg.Runner
	if runner == nil {
		runner = execRunner{}
	}
	return &Service{
		projectRoot: projectRoot,
		outputRoot:  outputRoot,
		sourcePaths: sourcePaths,
		runner:      runner,
	}, nil
}

func (execRunner) Run(ctx context.Context, dir string, env []string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("build command is required")
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message != "" {
			return fmt.Errorf("%w: %s", err, message)
		}
		return err
	}
	return nil
}

func (s *Service) EnsureBinary(ctx context.Context, req models.AgentBuildRequest) (*models.AgentBuildInfo, error) {
	goos := strings.TrimSpace(req.GOOS)
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := strings.TrimSpace(req.GOARCH)
	if goarch == "" {
		goarch = runtime.GOARCH
	}

	sourceModifiedAt, err := s.sourceModifiedAt()
	if err != nil {
		return nil, err
	}

	outputDir := filepath.Join(s.outputRoot, goos, goarch)
	outputPath := filepath.Join(outputDir, defaultBinaryName)

	outputInfo, statErr := os.Stat(outputPath)
	needsBuild := req.Force || statErr != nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return nil, statErr
	}
	if !needsBuild && outputInfo.ModTime().Before(sourceModifiedAt) {
		needsBuild = true
	}

	if needsBuild {
		if err := os.MkdirAll(outputDir, 0o755); err != nil {
			return nil, err
		}
		if err := s.runner.Run(ctx, s.projectRoot, []string{
			"GOOS=" + goos,
			"GOARCH=" + goarch,
			"CGO_ENABLED=0",
		}, []string{
			"go",
			"build",
			"-o",
			outputPath,
			"./cmd/opengfw-agent",
		}); err != nil {
			return nil, err
		}
		outputInfo, err = os.Stat(outputPath)
		if err != nil {
			return nil, err
		}
	}

	checksum, err := fileChecksum(outputPath)
	if err != nil {
		return nil, err
	}

	return &models.AgentBuildInfo{
		BinaryName:       defaultBinaryName,
		BinaryPath:       outputPath,
		GOOS:             goos,
		GOARCH:           goarch,
		Checksum:         "sha256:" + checksum,
		BuiltAt:          outputInfo.ModTime().UTC(),
		SourceModifiedAt: sourceModifiedAt.UTC(),
		Rebuilt:          needsBuild,
	}, nil
}

func (s *Service) EnsureBinaries(ctx context.Context, req models.AgentBuildRequest) ([]models.AgentBuildInfo, error) {
	targets := req.Targets
	if len(targets) == 0 {
		targets = []models.AgentBuildTarget{{
			GOOS:   req.GOOS,
			GOARCH: req.GOARCH,
		}}
	}

	builds := make([]models.AgentBuildInfo, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		goos := strings.TrimSpace(target.GOOS)
		if goos == "" {
			goos = strings.TrimSpace(req.GOOS)
		}
		goarch := strings.TrimSpace(target.GOARCH)
		if goarch == "" {
			goarch = strings.TrimSpace(req.GOARCH)
		}

		key := goos + "/" + goarch
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		info, err := s.EnsureBinary(ctx, models.AgentBuildRequest{
			GOOS:   goos,
			GOARCH: goarch,
			Force:  req.Force,
		})
		if err != nil {
			return nil, err
		}
		builds = append(builds, *info)
	}
	return builds, nil
}

func (s *Service) sourceModifiedAt() (time.Time, error) {
	var latest time.Time
	found := false
	for _, relative := range s.sourcePaths {
		path := filepath.Join(s.projectRoot, relative)
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return time.Time{}, err
		}
		if !info.IsDir() {
			found = true
			if info.ModTime().After(latest) {
				latest = info.ModTime()
			}
			continue
		}
		err = filepath.WalkDir(path, func(walkPath string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			name := entry.Name()
			if !(strings.HasSuffix(name, ".go") || name == "go.mod" || name == "go.sum") {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			found = true
			if info.ModTime().After(latest) {
				latest = info.ModTime()
			}
			return nil
		})
		if err != nil {
			return time.Time{}, err
		}
	}
	if !found {
		return time.Time{}, fmt.Errorf("agent source files not found under %s", s.projectRoot)
	}
	return latest, nil
}

func fileChecksum(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func findProjectRoot() (string, error) {
	candidates := make([]string, 0, 2)
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, cwd)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(exe))
	}
	for _, start := range candidates {
		if root, ok := searchProjectRoot(start); ok {
			return root, nil
		}
	}
	return "", fmt.Errorf("failed to locate OpenGFW project root")
}

func searchProjectRoot(start string) (string, bool) {
	current := start
	for {
		if fileExists(filepath.Join(current, "go.mod")) && fileExists(filepath.Join(current, "cmd", "opengfw-agent", "main.go")) {
			return current, true
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", false
		}
		current = parent
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
