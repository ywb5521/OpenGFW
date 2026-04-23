package models

import "time"

type TrafficEvent struct {
	EventID   string         `json:"eventId"`
	AgentID   string         `json:"agentId"`
	Time      time.Time      `json:"time"`
	Type      string         `json:"type"`
	StreamID  int64          `json:"streamId,omitempty"`
	Proto     string         `json:"proto,omitempty"`
	SrcIP     string         `json:"srcIp,omitempty"`
	DstIP     string         `json:"dstIp,omitempty"`
	SrcPort   uint16         `json:"srcPort,omitempty"`
	DstPort   uint16         `json:"dstPort,omitempty"`
	RuleName  string         `json:"ruleName,omitempty"`
	Action    string         `json:"action,omitempty"`
	Props     map[string]any `json:"props,omitempty"`
	Suspicion int            `json:"suspicion,omitempty"`
	Tags      []string       `json:"tags,omitempty"`
	BundleVer string         `json:"bundleVer,omitempty"`
}

type MetricSample struct {
	AgentID string            `json:"agentId"`
	Time    time.Time         `json:"time"`
	Name    string            `json:"name"`
	Value   float64           `json:"value"`
	Labels  map[string]string `json:"labels,omitempty"`
}

type EventBatch struct {
	BatchID   string         `json:"batchId"`
	AgentID   string         `json:"agentId"`
	CreatedAt time.Time      `json:"createdAt"`
	Events    []TrafficEvent `json:"events"`
}

type MetricBatch struct {
	BatchID   string         `json:"batchId"`
	AgentID   string         `json:"agentId"`
	CreatedAt time.Time      `json:"createdAt"`
	Metrics   []MetricSample `json:"metrics"`
}

type ReportSummary struct {
	GeneratedAt       time.Time      `json:"generatedAt"`
	Nodes             int            `json:"nodes"`
	OnlineNodes       int            `json:"onlineNodes"`
	EventCount        int            `json:"eventCount"`
	MetricCount       int            `json:"metricCount"`
	SuspiciousEvents  int            `json:"suspiciousEvents"`
	EventsByType      map[string]int `json:"eventsByType"`
	EventsByProtocol  map[string]int `json:"eventsByProtocol"`
	MetricsByName     map[string]int `json:"metricsByName"`
	BundleAssignments int            `json:"bundleAssignments,omitempty"`
}

type EventQuery struct {
	AgentID      string    `json:"agentId,omitempty"`
	Search       string    `json:"search,omitempty"`
	Type         string    `json:"type,omitempty"`
	Proto        string    `json:"proto,omitempty"`
	RuleName     string    `json:"ruleName,omitempty"`
	Action       string    `json:"action,omitempty"`
	SrcIP        string    `json:"srcIp,omitempty"`
	DstIP        string    `json:"dstIp,omitempty"`
	Port         int       `json:"port,omitempty"`
	MinSuspicion int       `json:"minSuspicion,omitempty"`
	Offset       int       `json:"offset,omitempty"`
	Limit        int       `json:"limit,omitempty"`
	Since        time.Time `json:"since,omitempty"`
	Until        time.Time `json:"until,omitempty"`
}

type EventQueryResult struct {
	Total  int            `json:"total"`
	Events []TrafficEvent `json:"events"`
}

type RuleReportItem struct {
	RuleName  string    `json:"ruleName"`
	Hits      int       `json:"hits"`
	Actions   int       `json:"actions"`
	Agents    []string  `json:"agents,omitempty"`
	LastHitAt time.Time `json:"lastHitAt,omitempty"`
}

type ProtocolReportItem struct {
	Protocol         string    `json:"protocol"`
	Events           int       `json:"events"`
	SuspiciousEvents int       `json:"suspiciousEvents"`
	LastSeenAt       time.Time `json:"lastSeenAt,omitempty"`
}

type NodeReportItem struct {
	AgentID          string    `json:"agentId"`
	Name             string    `json:"name,omitempty"`
	Status           string    `json:"status,omitempty"`
	Events           int       `json:"events"`
	RuleHits         int       `json:"ruleHits"`
	SuspiciousEvents int       `json:"suspiciousEvents"`
	LastSeenAt       time.Time `json:"lastSeenAt,omitempty"`
}

type MetricReportItem struct {
	AgentID string            `json:"agentId,omitempty"`
	Name    string            `json:"name"`
	Value   float64           `json:"value"`
	Labels  map[string]string `json:"labels,omitempty"`
	Time    time.Time         `json:"time"`
}

type MetricQueryResult struct {
	Total   int                `json:"total"`
	Metrics []MetricReportItem `json:"metrics"`
}

type MetricQuery struct {
	AgentID string    `json:"agentId,omitempty"`
	Name    string    `json:"name,omitempty"`
	Offset  int       `json:"offset,omitempty"`
	Limit   int       `json:"limit,omitempty"`
	Since   time.Time `json:"since,omitempty"`
	Until   time.Time `json:"until,omitempty"`
}

type TimeRangeQuery struct {
	AgentID string    `json:"agentId,omitempty"`
	Since   time.Time `json:"since,omitempty"`
	Until   time.Time `json:"until,omitempty"`
	Limit   int       `json:"limit,omitempty"`
}

type TimeSeriesBucket struct {
	Timestamp  time.Time `json:"timestamp"`
	Events     int       `json:"events"`
	Suspicious int       `json:"suspicious"`
	RuleHits   int       `json:"ruleHits"`
}

type TimeSeriesResponse struct {
	Buckets []TimeSeriesBucket `json:"buckets"`
}
