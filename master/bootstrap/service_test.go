package bootstrap

import (
	"strings"
	"testing"

	"github.com/apernet/OpenGFW/pkg/models"
)

func TestRenderSystemdService(t *testing.T) {
	unit := string(renderSystemdService(models.BootstrapInstallRequest{
		Name:         "gw-1",
		Hostname:     "gw-1-host",
		ManagementIP: "10.0.0.10",
		AgentVersion: "0.1.0",
		Install: models.InstallConfig{
			MasterURL: "http://master:8080",
		},
	}, "token123", "/usr/local/bin/opengfw-agent", "/var/lib/opengfw-agent", "opengfw-agent"))

	if !strings.Contains(unit, `Environment="OPENGFW_BOOTSTRAP_TOKEN=token123"`) {
		t.Fatalf("expected bootstrap token env, got:\n%s", unit)
	}
	if !strings.Contains(unit, `"--master" "http://master:8080"`) {
		t.Fatalf("expected master URL in ExecStart, got:\n%s", unit)
	}
	if !strings.Contains(unit, `"--management-ip" "10.0.0.10"`) {
		t.Fatalf("expected management IP in ExecStart, got:\n%s", unit)
	}
	if strings.Contains(unit, `"--version" "0.1.0"`) {
		t.Fatalf("expected unit to avoid pinning agent version, got:\n%s", unit)
	}
}

func TestShellEscape(t *testing.T) {
	got := shellEscape("ab'cd")
	want := `'ab'\''cd'`
	if got != want {
		t.Fatalf("unexpected shell escape: got %s want %s", got, want)
	}
}
