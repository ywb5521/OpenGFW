package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/apernet/OpenGFW/pkg/models"

	"golang.org/x/crypto/ssh"
)

type AgentBinaryBuilder interface {
	EnsureBinary(ctx context.Context, req models.AgentBuildRequest) (*models.AgentBuildInfo, error)
	EnsureBinaries(ctx context.Context, req models.AgentBuildRequest) ([]models.AgentBuildInfo, error)
}

type SSHInstaller struct {
	builder AgentBinaryBuilder
}

func NewSSHInstaller(builder AgentBinaryBuilder) *SSHInstaller {
	return &SSHInstaller{builder: builder}
}

func (i *SSHInstaller) Install(ctx context.Context, req models.BootstrapInstallRequest, bootstrapToken string) (models.BootstrapInstallResponse, error) {
	if req.Install.MasterURL == "" {
		return models.BootstrapInstallResponse{}, fmt.Errorf("install.masterUrl is required")
	}
	if req.SSH.Host == "" || req.SSH.User == "" {
		return models.BootstrapInstallResponse{}, fmt.Errorf("ssh.host and ssh.user are required")
	}
	if !req.SSH.InsecureIgnoreHostKey {
		return models.BootstrapInstallResponse{}, fmt.Errorf("host key verification is not configured; set insecureIgnoreHostKey explicitly for now")
	}

	installDir := req.Install.InstallDir
	if installDir == "" {
		installDir = "/usr/local/bin"
	}
	stateDir := req.Install.StateDir
	if stateDir == "" {
		stateDir = "/var/lib/opengfw-agent"
	}
	serviceName := req.Install.ServiceName
	if serviceName == "" {
		serviceName = "opengfw-agent"
	}

	client, err := dialSSH(req.SSH)
	if err != nil {
		return models.BootstrapInstallResponse{}, err
	}
	defer client.Close()

	localBinaryPath := req.Install.BinarySource
	var managedBinary *models.AgentBuildInfo
	if strings.TrimSpace(localBinaryPath) == "" {
		if i.builder == nil {
			return models.BootstrapInstallResponse{}, fmt.Errorf("managed agent binary builder is not configured")
		}
		goos := strings.TrimSpace(req.Install.TargetGOOS)
		goarch := strings.TrimSpace(req.Install.TargetGOARCH)
		if goos == "" || goarch == "" {
			detectedGOOS, detectedGOARCH, err := detectRemoteBuildTarget(client)
			if err != nil {
				return models.BootstrapInstallResponse{}, err
			}
			if goos == "" {
				goos = detectedGOOS
			}
			if goarch == "" {
				goarch = detectedGOARCH
			}
		}
		managedBinary, err = i.builder.EnsureBinary(ctx, models.AgentBuildRequest{
			GOOS:   goos,
			GOARCH: goarch,
			Force:  req.Install.RebuildBinary,
		})
		if err != nil {
			return models.BootstrapInstallResponse{}, err
		}
		localBinaryPath = managedBinary.BinaryPath
	}

	binaryName := strings.TrimSpace(req.Install.BinaryName)
	if binaryName == "" {
		binaryName = filepath.Base(localBinaryPath)
	}
	if binaryName == "" || binaryName == "." || binaryName == string(filepath.Separator) {
		binaryName = "opengfw-agent"
	}
	binaryPath := filepath.Join(installDir, binaryName)

	binFile, err := os.Open(localBinaryPath)
	if err != nil {
		return models.BootstrapInstallResponse{}, err
	}
	defer binFile.Close()

	if err := runRemoteCommand(client, req.Install.UseSudo, fmt.Sprintf("mkdir -p %s %s", shellEscape(installDir), shellEscape(stateDir)), nil); err != nil {
		return models.BootstrapInstallResponse{}, err
	}
	if err := uploadRemoteFile(client, req.Install.UseSudo, binFile, binaryPath, 0o755); err != nil {
		return models.BootstrapInstallResponse{}, err
	}

	serviceBytes := renderSystemdService(req, bootstrapToken, binaryPath, stateDir, serviceName)
	servicePath := "/etc/systemd/system/" + serviceName + ".service"
	if err := uploadRemoteFile(client, req.Install.UseSudo, bytes.NewReader(serviceBytes), servicePath, 0o644); err != nil {
		return models.BootstrapInstallResponse{}, err
	}
	if err := runRemoteCommand(client, req.Install.UseSudo, "systemctl daemon-reload", nil); err != nil {
		return models.BootstrapInstallResponse{}, err
	}
	if err := runRemoteCommand(client, req.Install.UseSudo, fmt.Sprintf("systemctl enable --now %s", shellEscape(serviceName)), nil); err != nil {
		return models.BootstrapInstallResponse{}, err
	}
	return models.BootstrapInstallResponse{
		ServiceName:   serviceName,
		BinaryPath:    binaryPath,
		StateDir:      stateDir,
		ManagedBinary: managedBinary,
	}, nil
}

func (i *SSHInstaller) BuildAgentBinary(ctx context.Context, req models.AgentBuildRequest) (*models.AgentBuildInfo, error) {
	if i.builder == nil {
		return nil, fmt.Errorf("managed agent binary builder is not configured")
	}
	return i.builder.EnsureBinary(ctx, req)
}

func (i *SSHInstaller) BuildAgentBinaries(ctx context.Context, req models.AgentBuildRequest) ([]models.AgentBuildInfo, error) {
	if i.builder == nil {
		return nil, fmt.Errorf("managed agent binary builder is not configured")
	}
	return i.builder.EnsureBinaries(ctx, req)
}

func dialSSH(cfg models.SSHConfig) (*ssh.Client, error) {
	authMethods := make([]ssh.AuthMethod, 0, 2)
	if cfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(cfg.Password))
	}
	if cfg.PrivateKeyPEM != "" {
		signer, err := ssh.ParsePrivateKey([]byte(cfg.PrivateKeyPEM))
		if err != nil {
			return nil, err
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("ssh password or private key is required")
	}

	port := cfg.Port
	if port == 0 {
		port = 22
	}
	timeout := 15 * time.Second
	if cfg.TimeoutSeconds > 0 {
		timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
	}
	sshConfig := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(port))
	return ssh.Dial("tcp", addr, sshConfig)
}

func uploadRemoteFile(client *ssh.Client, useSudo bool, content io.Reader, path string, mode os.FileMode) error {
	command := fmt.Sprintf("install -D -m %04o /dev/stdin %s", mode.Perm(), shellEscape(path))
	return runRemoteCommand(client, useSudo, command, content)
}

func runRemoteCommand(client *ssh.Client, useSudo bool, command string, stdin io.Reader) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	var stderr bytes.Buffer
	session.Stderr = &stderr
	if stdin != nil {
		session.Stdin = stdin
	}
	if useSudo {
		command = "sudo sh -lc " + shellEscape(command)
	} else {
		command = "sh -lc " + shellEscape(command)
	}
	if err := session.Run(command); err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return err
	}
	return nil
}

func runRemoteOutput(client *ssh.Client, command string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var stderr bytes.Buffer
	session.Stderr = &stderr
	output, err := session.Output("sh -lc " + shellEscape(command))
	if err != nil {
		if stderr.Len() > 0 {
			return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func detectRemoteBuildTarget(client *ssh.Client) (string, string, error) {
	osName, err := runRemoteOutput(client, "uname -s")
	if err != nil {
		return "", "", err
	}
	archName, err := runRemoteOutput(client, "uname -m")
	if err != nil {
		return "", "", err
	}

	goos, err := normalizeRemoteGOOS(osName)
	if err != nil {
		return "", "", err
	}
	goarch, err := normalizeRemoteGOARCH(archName)
	if err != nil {
		return "", "", err
	}
	return goos, goarch, nil
}

func normalizeRemoteGOOS(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "linux":
		return "linux", nil
	case "darwin":
		return "darwin", nil
	case "freebsd":
		return "freebsd", nil
	default:
		return "", fmt.Errorf("unsupported remote operating system %q", value)
	}
}

func normalizeRemoteGOARCH(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "x86_64", "amd64":
		return "amd64", nil
	case "aarch64", "arm64":
		return "arm64", nil
	case "i386", "i686", "386":
		return "386", nil
	default:
		return "", fmt.Errorf("unsupported remote architecture %q", value)
	}
}

func renderSystemdService(req models.BootstrapInstallRequest, bootstrapToken string, binaryPath string, stateDir string, serviceName string) []byte {
	args := []string{
		binaryPath,
		"--master", req.Install.MasterURL,
		"--state-dir", stateDir,
		"--name", req.Name,
	}
	if req.Hostname != "" {
		args = append(args, "--hostname", req.Hostname)
	}
	if req.ManagementIP != "" {
		args = append(args, "--management-ip", req.ManagementIP)
	}

	var buf bytes.Buffer
	buf.WriteString("[Unit]\n")
	buf.WriteString("Description=OpenGFW Agent\n")
	buf.WriteString("After=network-online.target\n")
	buf.WriteString("Wants=network-online.target\n\n")
	buf.WriteString("[Service]\n")
	buf.WriteString("Type=simple\n")
	buf.WriteString("User=root\n")
	buf.WriteString("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW\n")
	buf.WriteString("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\n")
	buf.WriteString(fmt.Sprintf("Environment=%s\n", strconv.Quote("OPENGFW_BOOTSTRAP_TOKEN="+bootstrapToken)))
	buf.WriteString(fmt.Sprintf("Environment=%s\n", strconv.Quote("OPENGFW_SERVICE_NAME="+serviceName)))
	buf.WriteString(fmt.Sprintf("Environment=%s\n", strconv.Quote("OPENGFW_BINARY_PATH="+binaryPath)))
	buf.WriteString(fmt.Sprintf("ExecStart=%s\n", systemdJoin(args)))
	buf.WriteString("Restart=always\n")
	buf.WriteString("RestartSec=5s\n")
	buf.WriteString(fmt.Sprintf("WorkingDirectory=%s\n", stateDir))
	buf.WriteString("\n[Install]\n")
	buf.WriteString("WantedBy=multi-user.target\n")
	return buf.Bytes()
}

func systemdJoin(args []string) string {
	parts := make([]string, 0, len(args))
	for _, arg := range args {
		parts = append(parts, strconv.Quote(arg))
	}
	return strings.Join(parts, " ")
}

func shellEscape(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}
