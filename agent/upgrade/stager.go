package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"

	"github.com/apernet/OpenGFW/pkg/models"
)

type Stager struct {
	baseDir string
	client  *http.Client
}

func NewStager(baseDir string, client *http.Client) (*Stager, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("base directory is required")
	}
	if client == nil {
		client = &http.Client{}
	}
	dir := filepath.Join(baseDir, "downloads")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Stager{
		baseDir: dir,
		client:  client,
	}, nil
}

func (s *Stager) Stage(ctx context.Context, artifact models.ReleaseArtifact) (string, error) {
	if artifact.Version == "" {
		return "", fmt.Errorf("artifact version is required")
	}
	asset, err := resolveReleaseAsset(artifact, goruntime.GOOS, goruntime.GOARCH)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.DownloadURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return "", fmt.Errorf("artifact download failed: %s", resp.Status)
	}

	stageDir := filepath.Join(s.baseDir, artifact.Version)
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(stageDir, artifactFilename(asset))
	tmpPath := path + ".tmp"

	file, err := os.Create(tmpPath)
	if err != nil {
		return "", err
	}

	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(file, hash), resp.Body)
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return "", copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return "", closeErr
	}

	if err := verifyChecksum(hash.Sum(nil), asset.Checksum); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	return path, nil
}

func resolveReleaseAsset(artifact models.ReleaseArtifact, goos, goarch string) (models.ReleaseAsset, error) {
	if len(artifact.Assets) == 0 {
		if artifact.DownloadURL == "" {
			return models.ReleaseAsset{}, fmt.Errorf("artifact download URL is required")
		}
		return models.ReleaseAsset{
			GOOS:        goos,
			GOARCH:      goarch,
			BinaryName:  artifactFilename(models.ReleaseAsset{DownloadURL: artifact.DownloadURL}),
			DownloadURL: artifact.DownloadURL,
			Checksum:    artifact.Checksum,
		}, nil
	}
	for _, asset := range artifact.Assets {
		if asset.GOOS == goos && asset.GOARCH == goarch {
			if asset.DownloadURL == "" {
				return models.ReleaseAsset{}, fmt.Errorf("release asset download URL is required for %s/%s", goos, goarch)
			}
			return asset, nil
		}
	}
	return models.ReleaseAsset{}, fmt.Errorf("no release asset for %s/%s", goos, goarch)
}

func (s *Stager) ScheduleApply(stagedPath, targetPath, serviceName string) error {
	if stagedPath == "" || targetPath == "" || serviceName == "" {
		return fmt.Errorf("staged path, target path, and service name are required")
	}
	command := buildApplyCommand(stagedPath, targetPath, serviceName, "", "")
	return exec.Command("sh", "-c", command).Run()
}

func (s *Stager) ScheduleApplyVersion(stagedPath, targetPath, serviceName, version string) error {
	if stagedPath == "" || targetPath == "" || serviceName == "" {
		return fmt.Errorf("staged path, target path, and service name are required")
	}
	command := buildApplyCommand(stagedPath, targetPath, serviceName, filepath.Join(filepath.Dir(s.baseDir), "agent-version"), version)
	return exec.Command("sh", "-c", command).Run()
}

func artifactFilename(asset models.ReleaseAsset) string {
	parts := strings.Split(strings.TrimSpace(asset.DownloadURL), "/")
	name := parts[len(parts)-1]
	if name == "" || strings.Contains(name, "?") {
		name = ""
	}
	if idx := strings.IndexByte(name, '?'); idx >= 0 {
		name = name[:idx]
	}
	if name == "" {
		name = asset.BinaryName
	}
	if name == "" {
		name = "opengfw-agent"
	}
	return name
}

func verifyChecksum(sum []byte, checksum string) error {
	if checksum == "" {
		return nil
	}
	expected := strings.TrimSpace(strings.ToLower(checksum))
	expected = strings.TrimPrefix(expected, "sha256:")
	actual := hex.EncodeToString(sum)
	if actual != expected {
		return fmt.Errorf("checksum mismatch: got %s", actual)
	}
	return nil
}

func buildApplyCommand(stagedPath, targetPath, serviceName, versionFile, version string) string {
	steps := []string{"sleep 1"}
	if strings.TrimSpace(versionFile) != "" && strings.TrimSpace(version) != "" {
		steps = append(steps, fmt.Sprintf("printf %%s %s > %s", shellEscape(version), shellEscape(versionFile)))
	}
	steps = append(steps,
		fmt.Sprintf("install -m 0755 %s %s", shellEscape(stagedPath), shellEscape(targetPath)),
		fmt.Sprintf("systemctl restart %s", shellEscape(serviceName)),
	)
	swap := strings.Join(steps, " && ")
	return "nohup sh -lc " + shellEscape(swap) + " >/dev/null 2>&1 &"
}

func shellEscape(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}
