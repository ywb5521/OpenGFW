package models

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"
)

type AgentStatus string

const (
	AgentStatusPending AgentStatus = "pending"
	AgentStatusOnline  AgentStatus = "online"
	AgentStatusOffline AgentStatus = "offline"
	AgentStatusError   AgentStatus = "error"
)

type RuntimeState string

const (
	RuntimeStateStopped  RuntimeState = "stopped"
	RuntimeStateStarting RuntimeState = "starting"
	RuntimeStateRunning  RuntimeState = "running"
	RuntimeStateApplying RuntimeState = "applying"
	RuntimeStateError    RuntimeState = "error"
)

type TaskType string

const (
	TaskTypeApplyBundle  TaskType = "apply_bundle"
	TaskTypeUpgradeAgent TaskType = "upgrade_agent"
)

type TaskStatus string

const (
	TaskStatusPending TaskStatus = "pending"
	TaskStatusSuccess TaskStatus = "success"
	TaskStatusFailed  TaskStatus = "failed"
)

type AgentIdentity struct {
	AgentID        string    `json:"agentId"`
	BootstrapToken string    `json:"bootstrapToken,omitempty"`
	RegisteredAt   time.Time `json:"registeredAt,omitempty"`
}

type AgentNode struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Hostname      string            `json:"hostname"`
	ManagementIP  string            `json:"managementIp,omitempty"`
	Labels        []string          `json:"labels,omitempty"`
	Status        AgentStatus       `json:"status"`
	AgentVersion  string            `json:"agentVersion,omitempty"`
	BundleVersion string            `json:"bundleVersion,omitempty"`
	LastSeenAt    time.Time         `json:"lastSeenAt,omitempty"`
	Capabilities  []string          `json:"capabilities,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type RuntimeStatus struct {
	State         RuntimeState `json:"state"`
	BundleVersion string       `json:"bundleVersion,omitempty"`
	UpdatedAt     time.Time    `json:"updatedAt,omitempty"`
	Message       string       `json:"message,omitempty"`
}

type RegistrationRequest struct {
	AgentID        string            `json:"agentId,omitempty"`
	BootstrapToken string            `json:"bootstrapToken,omitempty"`
	Name           string            `json:"name,omitempty"`
	Hostname       string            `json:"hostname,omitempty"`
	ManagementIP   string            `json:"managementIp,omitempty"`
	AgentVersion   string            `json:"agentVersion,omitempty"`
	Labels         []string          `json:"labels,omitempty"`
	Capabilities   []string          `json:"capabilities,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

type RegistrationResponse struct {
	AgentID              string      `json:"agentId"`
	Status               AgentStatus `json:"status"`
	CurrentBundleVersion string      `json:"currentBundleVersion,omitempty"`
	CurrentAgentVersion  string      `json:"currentAgentVersion,omitempty"`
	RegisteredAt         time.Time   `json:"registeredAt"`
}

type HeartbeatRequest struct {
	AgentID       string            `json:"agentId"`
	Name          string            `json:"name,omitempty"`
	Hostname      string            `json:"hostname,omitempty"`
	AgentVersion  string            `json:"agentVersion,omitempty"`
	BundleVersion string            `json:"bundleVersion,omitempty"`
	Runtime       RuntimeStatus     `json:"runtime"`
	Capabilities  []string          `json:"capabilities,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type HeartbeatResponse struct {
	Status     AgentStatus `json:"status"`
	ServerTime time.Time   `json:"serverTime"`
}

type ControlTask struct {
	ID        string          `json:"id"`
	AgentID   string          `json:"agentId"`
	Type      TaskType        `json:"type"`
	Status    TaskStatus      `json:"status"`
	CreatedAt time.Time       `json:"createdAt"`
	Message   string          `json:"message,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

type TaskListResponse struct {
	Total int           `json:"total,omitempty"`
	Tasks []ControlTask `json:"tasks"`
}

type AckTaskRequest struct {
	Status  TaskStatus `json:"status"`
	Message string     `json:"message,omitempty"`
}

type BundleTaskPayload struct {
	Bundle Bundle `json:"bundle"`
}

type ReleaseAsset struct {
	GOOS        string    `json:"goos,omitempty"`
	GOARCH      string    `json:"goarch,omitempty"`
	BinaryName  string    `json:"binaryName,omitempty"`
	DownloadURL string    `json:"downloadUrl,omitempty"`
	Checksum    string    `json:"checksum,omitempty"`
	BuiltAt     time.Time `json:"builtAt,omitempty"`
	BinaryPath  string    `json:"binaryPath,omitempty"`
}

type ReleaseArtifact struct {
	Version     string         `json:"version"`
	DownloadURL string         `json:"downloadUrl,omitempty"`
	Checksum    string         `json:"checksum,omitempty"`
	Notes       string         `json:"notes,omitempty"`
	Assets      []ReleaseAsset `json:"assets,omitempty"`
	CreatedAt   time.Time      `json:"createdAt,omitempty"`
}

type ReleaseTaskPayload struct {
	Artifact ReleaseArtifact `json:"artifact"`
}

type BundleRolloutRequest struct {
	BundleVersion string   `json:"bundleVersion"`
	AgentIDs      []string `json:"agentIds"`
}

type ReleaseRolloutRequest struct {
	Version  string   `json:"version"`
	AgentIDs []string `json:"agentIds"`
}

type AcceptedResponse struct {
	Accepted int `json:"accepted"`
}

type BootstrapInstallRequest struct {
	Name         string            `json:"name"`
	Hostname     string            `json:"hostname,omitempty"`
	ManagementIP string            `json:"managementIp,omitempty"`
	Labels       []string          `json:"labels,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	AgentVersion string            `json:"agentVersion,omitempty"`
	SSH          SSHConfig         `json:"ssh"`
	Install      InstallConfig     `json:"install"`
}

type SSHConfig struct {
	Host                  string `json:"host"`
	Port                  int    `json:"port,omitempty"`
	User                  string `json:"user"`
	Password              string `json:"password,omitempty"`
	PrivateKeyPEM         string `json:"privateKeyPem,omitempty"`
	TimeoutSeconds        int    `json:"timeoutSeconds,omitempty"`
	InsecureIgnoreHostKey bool   `json:"insecureIgnoreHostKey,omitempty"`
}

type InstallConfig struct {
	MasterURL      string `json:"masterUrl"`
	BinarySource   string `json:"binarySource,omitempty"`
	TargetGOOS     string `json:"targetGoos,omitempty"`
	TargetGOARCH   string `json:"targetGoarch,omitempty"`
	RebuildBinary  bool   `json:"rebuildBinary,omitempty"`
	InstallDir     string `json:"installDir,omitempty"`
	StateDir       string `json:"stateDir,omitempty"`
	ServiceName    string `json:"serviceName,omitempty"`
	BinaryName     string `json:"binaryName,omitempty"`
	UseSudo        bool   `json:"useSudo,omitempty"`
	BootstrapToken string `json:"bootstrapToken,omitempty"`
}

type BootstrapInstallResponse struct {
	NodeID           string          `json:"nodeId"`
	ServiceName      string          `json:"serviceName"`
	BinaryPath       string          `json:"binaryPath"`
	StateDir         string          `json:"stateDir"`
	InstallScriptURL string          `json:"installScriptUrl,omitempty"`
	InstallCommand   string          `json:"installCommand,omitempty"`
	BootstrapToken   string          `json:"bootstrapToken,omitempty"`
	ManagedBinary    *AgentBuildInfo `json:"managedBinary,omitempty"`
}

type NodeScriptResponse struct {
	NodeID             string `json:"nodeId"`
	ServiceName        string `json:"serviceName"`
	BinaryPath         string `json:"binaryPath"`
	StateDir           string `json:"stateDir"`
	BootstrapToken     string `json:"bootstrapToken"`
	InstallScriptURL   string `json:"installScriptUrl"`
	InstallCommand     string `json:"installCommand"`
	UninstallScriptURL string `json:"uninstallScriptUrl"`
	UninstallCommand   string `json:"uninstallCommand"`
}

type AgentBuildRequest struct {
	GOOS    string             `json:"goos,omitempty"`
	GOARCH  string             `json:"goarch,omitempty"`
	Force   bool               `json:"force,omitempty"`
	Targets []AgentBuildTarget `json:"targets,omitempty"`
}

type ManagedReleaseBuildRequest struct {
	Version string             `json:"version"`
	Notes   string             `json:"notes,omitempty"`
	Force   bool               `json:"force,omitempty"`
	Targets []AgentBuildTarget `json:"targets,omitempty"`
}

type AgentBuildTarget struct {
	GOOS   string `json:"goos,omitempty"`
	GOARCH string `json:"goarch,omitempty"`
}

type AgentBuildInfo struct {
	BinaryName       string    `json:"binaryName"`
	BinaryPath       string    `json:"binaryPath"`
	GOOS             string    `json:"goos"`
	GOARCH           string    `json:"goarch"`
	Checksum         string    `json:"checksum"`
	BuiltAt          time.Time `json:"builtAt"`
	SourceModifiedAt time.Time `json:"sourceModifiedAt,omitempty"`
	Rebuilt          bool      `json:"rebuilt"`
}

type AgentBuildResponse struct {
	Builds []AgentBuildInfo `json:"builds"`
}

type AuthStatusResponse struct {
	Authenticated bool               `json:"authenticated"`
	SetupRequired bool               `json:"setupRequired"`
	User          *AuthenticatedUser `json:"user,omitempty"`
	SessionToken  string             `json:"sessionToken,omitempty"`
}

type AuthenticatedUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type AuthSetupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type PasswordChangeRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

type NodeQuery struct {
	Status AgentStatus `json:"status,omitempty"`
	Label  string      `json:"label,omitempty"`
	Search string      `json:"search,omitempty"`
	Offset int         `json:"offset,omitempty"`
	Limit  int         `json:"limit,omitempty"`
}

type NodeListResponse struct {
	Total int         `json:"total"`
	Nodes []AgentNode `json:"nodes"`
}

type BundleQuery struct {
	Version string `json:"version,omitempty"`
	Search  string `json:"search,omitempty"`
	Offset  int    `json:"offset,omitempty"`
	Limit   int    `json:"limit,omitempty"`
}

type BundleListResponse struct {
	Total   int      `json:"total"`
	Bundles []Bundle `json:"bundles"`
}

type ReleaseQuery struct {
	Version string `json:"version,omitempty"`
	Search  string `json:"search,omitempty"`
	Offset  int    `json:"offset,omitempty"`
	Limit   int    `json:"limit,omitempty"`
}

type ReleaseListResponse struct {
	Total     int               `json:"total"`
	Artifacts []ReleaseArtifact `json:"artifacts"`
}

type TaskQuery struct {
	Status string   `json:"status,omitempty"`
	Type   TaskType `json:"type,omitempty"`
	Offset int      `json:"offset,omitempty"`
	Limit  int      `json:"limit,omitempty"`
}

func GenerateBootstrapToken() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}
