package bootstrap

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/apernet/OpenGFW/pkg/models"
)

func BuildScriptURL(masterURL, token, action string, install models.InstallConfig) (string, error) {
	base, err := parseMasterURL(masterURL)
	if err != nil {
		return "", err
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/bootstrap/scripts/" + url.PathEscape(token)

	query := base.Query()
	query.Set("masterUrl", masterURL)
	if value := strings.TrimSpace(action); value != "" {
		query.Set("action", value)
	}
	if value := strings.TrimSpace(install.InstallDir); value != "" {
		query.Set("installDir", value)
	}
	if value := strings.TrimSpace(install.StateDir); value != "" {
		query.Set("stateDir", value)
	}
	if value := strings.TrimSpace(install.ServiceName); value != "" {
		query.Set("serviceName", value)
	}
	if value := strings.TrimSpace(install.BinaryName); value != "" {
		query.Set("binaryName", value)
	}
	if value := strings.TrimSpace(install.TargetGOOS); value != "" {
		query.Set("goos", value)
	}
	if value := strings.TrimSpace(install.TargetGOARCH); value != "" {
		query.Set("goarch", value)
	}
	base.RawQuery = query.Encode()
	return base.String(), nil
}

func BuildInstallScriptURL(masterURL, token string, install models.InstallConfig) (string, error) {
	return BuildScriptURL(masterURL, token, "install", install)
}

func BuildUninstallScriptURL(masterURL, token string, install models.InstallConfig) (string, error) {
	return BuildScriptURL(masterURL, token, "uninstall", install)
}

func BuildBinaryDownloadURL(masterURL, token, goos, goarch string) (string, error) {
	base, err := parseMasterURL(masterURL)
	if err != nil {
		return "", err
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/bootstrap/binaries/" + url.PathEscape(token)
	query := base.Query()
	if value := strings.TrimSpace(goos); value != "" {
		query.Set("goos", value)
	}
	if value := strings.TrimSpace(goarch); value != "" {
		query.Set("goarch", value)
	}
	base.RawQuery = query.Encode()
	return base.String(), nil
}

func GenerateScriptCommand(scriptURL string, useSudo bool) string {
	executor := "sh"
	if useSudo {
		executor = "sudo sh"
	}
	return fmt.Sprintf("curl -fsSL %s | %s", shellEscape(scriptURL), executor)
}

func GenerateInstallCommand(scriptURL string, useSudo bool) string {
	return GenerateScriptCommand(scriptURL, useSudo)
}

func GenerateUninstallCommand(scriptURL string, useSudo bool) string {
	return GenerateScriptCommand(scriptURL, useSudo)
}

func RenderScript(req models.BootstrapInstallRequest, token, action string) (string, error) {
	switch strings.TrimSpace(action) {
	case "", "install":
		return RenderInstallScript(req, token)
	case "uninstall":
		return RenderUninstallScript(req, token)
	default:
		return "", fmt.Errorf("unsupported bootstrap action %q", action)
	}
}

func RenderInstallScript(req models.BootstrapInstallRequest, token string) (string, error) {
	masterURL := strings.TrimSpace(req.Install.MasterURL)
	if masterURL == "" {
		return "", fmt.Errorf("install.masterUrl is required")
	}

	installDir := strings.TrimSpace(req.Install.InstallDir)
	if installDir == "" {
		installDir = "/usr/local/bin"
	}
	stateDir := strings.TrimSpace(req.Install.StateDir)
	if stateDir == "" {
		stateDir = "/var/lib/opengfw-agent"
	}
	serviceName := strings.TrimSpace(req.Install.ServiceName)
	if serviceName == "" {
		serviceName = "opengfw-agent"
	}
	binaryName := strings.TrimSpace(req.Install.BinaryName)
	if binaryName == "" {
		binaryName = "opengfw-agent"
	}
	goos := strings.TrimSpace(req.Install.TargetGOOS)
	goarch := strings.TrimSpace(req.Install.TargetGOARCH)

	binaryPath := filepath.Join(installDir, binaryName)
	serviceContent := string(renderSystemdService(req, token, binaryPath, stateDir, serviceName))
	var script strings.Builder
	script.WriteString("#!/bin/sh\n")
	script.WriteString("set -eu\n\n")
	script.WriteString("if [ \"$(id -u)\" -ne 0 ]; then\n")
	script.WriteString("  echo \"This installer must run as root. Re-run the generated command with sudo.\" >&2\n")
	script.WriteString("  exit 1\n")
	script.WriteString("fi\n\n")
	script.WriteString("MASTER_URL=" + shellEscape(masterURL) + "\n")
	script.WriteString("TOKEN=" + shellEscape(token) + "\n")
	script.WriteString("INSTALL_DIR=" + shellEscape(installDir) + "\n")
	script.WriteString("STATE_DIR=" + shellEscape(stateDir) + "\n")
	script.WriteString("SERVICE_NAME=" + shellEscape(serviceName) + "\n")
	script.WriteString("BINARY_NAME=" + shellEscape(binaryName) + "\n")
	script.WriteString("GOOS=" + shellEscape(goos) + "\n")
	script.WriteString("GOARCH=" + shellEscape(goarch) + "\n")
	script.WriteString("TMP_BIN=$(mktemp)\n")
	script.WriteString("TMP_SERVICE=$(mktemp)\n")
	script.WriteString("cleanup() {\n")
	script.WriteString("  rm -f \"$TMP_BIN\" \"$TMP_SERVICE\"\n")
	script.WriteString("}\n")
	script.WriteString("trap cleanup EXIT\n\n")
	script.WriteString("download() {\n")
	script.WriteString("  src=\"$1\"\n")
	script.WriteString("  dst=\"$2\"\n")
	script.WriteString("  if command -v curl >/dev/null 2>&1; then\n")
	script.WriteString("    curl -fsSL \"$src\" -o \"$dst\"\n")
	script.WriteString("    return\n")
	script.WriteString("  fi\n")
	script.WriteString("  if command -v wget >/dev/null 2>&1; then\n")
	script.WriteString("    wget -qO \"$dst\" \"$src\"\n")
	script.WriteString("    return\n")
	script.WriteString("  fi\n")
	script.WriteString("  echo \"curl or wget is required\" >&2\n")
	script.WriteString("  exit 1\n")
	script.WriteString("}\n\n")
	script.WriteString("detect_goos() {\n")
	script.WriteString("  case \"$(uname -s)\" in\n")
	script.WriteString("    Linux) echo linux ;;\n")
	script.WriteString("    Darwin) echo darwin ;;\n")
	script.WriteString("    FreeBSD) echo freebsd ;;\n")
	script.WriteString("    *) echo \"unsupported operating system: $(uname -s)\" >&2; exit 1 ;;\n")
	script.WriteString("  esac\n")
	script.WriteString("}\n\n")
	script.WriteString("detect_goarch() {\n")
	script.WriteString("  case \"$(uname -m)\" in\n")
	script.WriteString("    x86_64|amd64) echo amd64 ;;\n")
	script.WriteString("    aarch64|arm64) echo arm64 ;;\n")
	script.WriteString("    i386|i686|386) echo 386 ;;\n")
	script.WriteString("    *) echo \"unsupported architecture: $(uname -m)\" >&2; exit 1 ;;\n")
	script.WriteString("  esac\n")
	script.WriteString("}\n\n")
	script.WriteString("if [ -z \"$GOOS\" ]; then GOOS=$(detect_goos); fi\n")
	script.WriteString("if [ -z \"$GOARCH\" ]; then GOARCH=$(detect_goarch); fi\n")
	script.WriteString("if [ \"$GOOS\" != \"linux\" ]; then\n")
	script.WriteString("  echo \"managed install is only supported on linux\" >&2\n")
	script.WriteString("  exit 1\n")
	script.WriteString("fi\n")
	script.WriteString("BINARY_URL=\"${MASTER_URL%/}/api/v1/bootstrap/binaries/${TOKEN}?goos=${GOOS}&goarch=${GOARCH}\"\n\n")
	script.WriteString("download \"$BINARY_URL\" \"$TMP_BIN\"\n")
	script.WriteString("install -D -m 0755 \"$TMP_BIN\" \"$INSTALL_DIR/$BINARY_NAME\"\n")
	script.WriteString("mkdir -p \"$STATE_DIR\"\n")
	script.WriteString("cat >\"$TMP_SERVICE\" <<'EOF'\n")
	script.WriteString(serviceContent)
	if !strings.HasSuffix(serviceContent, "\n") {
		script.WriteString("\n")
	}
	script.WriteString("EOF\n")
	script.WriteString("install -D -m 0644 \"$TMP_SERVICE\" \"/etc/systemd/system/${SERVICE_NAME}.service\"\n")
	script.WriteString("systemctl daemon-reload\n")
	script.WriteString("systemctl enable --now \"$SERVICE_NAME\"\n")
	script.WriteString("echo \"OpenGFW Agent installed: ${SERVICE_NAME}\" >&2\n")
	return script.String(), nil
}

func RenderUninstallScript(req models.BootstrapInstallRequest, token string) (string, error) {
	_ = token

	installDir := strings.TrimSpace(req.Install.InstallDir)
	if installDir == "" {
		installDir = "/usr/local/bin"
	}
	stateDir := strings.TrimSpace(req.Install.StateDir)
	if stateDir == "" {
		stateDir = "/var/lib/opengfw-agent"
	}
	serviceName := strings.TrimSpace(req.Install.ServiceName)
	if serviceName == "" {
		serviceName = "opengfw-agent"
	}
	binaryName := strings.TrimSpace(req.Install.BinaryName)
	if binaryName == "" {
		binaryName = "opengfw-agent"
	}

	var script strings.Builder
	script.WriteString("#!/bin/sh\n")
	script.WriteString("set -eu\n\n")
	script.WriteString("if [ \"$(id -u)\" -ne 0 ]; then\n")
	script.WriteString("  echo \"This uninstaller must run as root. Re-run the generated command with sudo.\" >&2\n")
	script.WriteString("  exit 1\n")
	script.WriteString("fi\n\n")
	script.WriteString("INSTALL_DIR=" + shellEscape(installDir) + "\n")
	script.WriteString("STATE_DIR=" + shellEscape(stateDir) + "\n")
	script.WriteString("SERVICE_NAME=" + shellEscape(serviceName) + "\n")
	script.WriteString("BINARY_NAME=" + shellEscape(binaryName) + "\n\n")
	script.WriteString("detect_goos() {\n")
	script.WriteString("  case \"$(uname -s)\" in\n")
	script.WriteString("    Linux) echo linux ;;\n")
	script.WriteString("    Darwin) echo darwin ;;\n")
	script.WriteString("    FreeBSD) echo freebsd ;;\n")
	script.WriteString("    *) echo \"unsupported operating system: $(uname -s)\" >&2; exit 1 ;;\n")
	script.WriteString("  esac\n")
	script.WriteString("}\n\n")
	script.WriteString("GOOS=$(detect_goos)\n")
	script.WriteString("if [ \"$GOOS\" = \"linux\" ] && command -v systemctl >/dev/null 2>&1; then\n")
	script.WriteString("  systemctl disable --now \"$SERVICE_NAME\" >/dev/null 2>&1 || true\n")
	script.WriteString("  rm -f \"/etc/systemd/system/${SERVICE_NAME}.service\"\n")
	script.WriteString("  systemctl daemon-reload >/dev/null 2>&1 || true\n")
	script.WriteString("fi\n")
	script.WriteString("rm -f \"$INSTALL_DIR/$BINARY_NAME\"\n")
	script.WriteString("rm -rf \"$STATE_DIR\"\n")
	script.WriteString("echo \"OpenGFW Agent removed: ${SERVICE_NAME}\" >&2\n")
	return script.String(), nil
}

func parseMasterURL(masterURL string) (*url.URL, error) {
	trimmed := strings.TrimSpace(masterURL)
	if trimmed == "" {
		return nil, fmt.Errorf("masterUrl is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("masterUrl must include scheme and host")
	}
	return parsed, nil
}
