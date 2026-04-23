package models

import "time"

type Bundle struct {
	Version      string            `json:"version" yaml:"bundleVersion"`
	AgentVersion string            `json:"agentVersion,omitempty" yaml:"agentVersion,omitempty"`
	Readonly     bool              `json:"readonly,omitempty" yaml:"readonly,omitempty"`
	Runtime      RuntimeConfig     `json:"runtime" yaml:"runtime"`
	Telemetry    TelemetryProfile  `json:"telemetry" yaml:"telemetry"`
	Rules        []RuleSpec        `json:"rules" yaml:"rules"`
	Metadata     map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"createdAt,omitempty" yaml:"createdAt,omitempty"`
}

type RuntimeConfig struct {
	IO      RuntimeIOConfig     `json:"io" yaml:"io"`
	Workers RuntimeWorkerConfig `json:"workers" yaml:"workers"`
	Extra   map[string]string   `json:"extra,omitempty" yaml:"extra,omitempty"`
}

type RuntimeIOConfig struct {
	QueueSize uint32 `json:"queueSize" yaml:"queueSize"`
	RcvBuf    int    `json:"rcvBuf" yaml:"rcvBuf"`
	SndBuf    int    `json:"sndBuf" yaml:"sndBuf"`
	Local     bool   `json:"local" yaml:"local"`
	RST       bool   `json:"rst" yaml:"rst"`
}

type RuntimeWorkerConfig struct {
	Count                      int `json:"count" yaml:"count"`
	QueueSize                  int `json:"queueSize" yaml:"queueSize"`
	TCPMaxBufferedPagesTotal   int `json:"tcpMaxBufferedPagesTotal" yaml:"tcpMaxBufferedPagesTotal"`
	TCPMaxBufferedPagesPerConn int `json:"tcpMaxBufferedPagesPerConn" yaml:"tcpMaxBufferedPagesPerConn"`
	UDPMaxStreams              int `json:"udpMaxStreams" yaml:"udpMaxStreams"`
}

type RuleSpec struct {
	Name     string        `json:"name" yaml:"name"`
	Action   string        `json:"action,omitempty" yaml:"action,omitempty"`
	Log      bool          `json:"log,omitempty" yaml:"log,omitempty"`
	Modifier *ModifierSpec `json:"modifier,omitempty" yaml:"modifier,omitempty"`
	Expr     string        `json:"expr" yaml:"expr"`
}

type ModifierSpec struct {
	Name string         `json:"name" yaml:"name"`
	Args map[string]any `json:"args,omitempty" yaml:"args,omitempty"`
}

type TelemetryProfile struct {
	Analyzers []string        `json:"analyzers,omitempty" yaml:"analyzers,omitempty"`
	Events    TelemetryEvents `json:"events" yaml:"events"`
	Sampling  SamplingPolicy  `json:"sampling" yaml:"sampling"`
}

type TelemetryEvents struct {
	RuleHit        bool `json:"ruleHit" yaml:"ruleHit"`
	SuspiciousOnly bool `json:"suspiciousOnly" yaml:"suspiciousOnly"`
	FlowSummary    bool `json:"flowSummary" yaml:"flowSummary"`
}

type SamplingPolicy struct {
	BenignFlow float64 `json:"benignFlow" yaml:"benignFlow"`
}
