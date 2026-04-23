package report

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/apernet/OpenGFW/master/ingest"
	"github.com/apernet/OpenGFW/master/node"
	"github.com/apernet/OpenGFW/pkg/models"
)

type Service struct {
	nodes  *node.Service
	ingest *ingest.Service
	query  QueryStore
}

func NewService(nodes *node.Service, ingest *ingest.Service) *Service {
	return NewServiceWithQueries(nodes, ingest, nil)
}

func NewServiceWithQueries(nodes *node.Service, ingest *ingest.Service, query QueryStore) *Service {
	return &Service{
		nodes:  nodes,
		ingest: ingest,
		query:  query,
	}
}

type QueryStore interface {
	QuerySummary() (models.ReportSummary, error)
	QueryEvents(models.EventQuery) (models.EventQueryResult, error)
	QueryRules(models.TimeRangeQuery) ([]models.RuleReportItem, error)
	QueryProtocols(models.TimeRangeQuery) ([]models.ProtocolReportItem, error)
	QueryNodeStats(models.TimeRangeQuery) ([]models.NodeReportItem, error)
	QueryMetrics(models.MetricQuery) (models.MetricQueryResult, error)
	QueryTrafficSeries(models.TimeRangeQuery) (models.TimeSeriesResponse, error)
	QueryEventBreakdown(models.TimeRangeQuery) (models.EventBreakdown, error)
}

func (s *Service) Summary() models.ReportSummary {
	nodeList := s.nodes.List()
	if s.query != nil {
		if summary, err := s.query.QuerySummary(); err == nil {
			summary.GeneratedAt = time.Now().UTC()
			summary.Nodes = len(nodeList)
			for _, node := range nodeList {
				if node.Status == models.AgentStatusOnline {
					summary.OnlineNodes++
				}
			}
			return summary
		}
	}
	snapshot := s.ingest.Snapshot()

	summary := models.ReportSummary{
		GeneratedAt:      time.Now().UTC(),
		Nodes:            len(nodeList),
		EventsByType:     make(map[string]int),
		EventsByProtocol: make(map[string]int),
		MetricsByName:    make(map[string]int),
	}
	for _, node := range nodeList {
		if node.Status == models.AgentStatusOnline {
			summary.OnlineNodes++
		}
	}
	for _, event := range snapshot.Events {
		summary.EventCount++
		summary.EventsByType[event.Type]++
		if event.Proto != "" {
			summary.EventsByProtocol[event.Proto]++
		}
		if isSuspiciousEvent(event) {
			summary.SuspiciousEvents++
		}
	}
	for _, metric := range snapshot.Metrics {
		summary.MetricCount++
		summary.MetricsByName[metric.Name]++
	}
	return summary
}

func (s *Service) Events(query models.EventQuery) models.EventQueryResult {
	if s.query != nil {
		if result, err := s.query.QueryEvents(query); err == nil {
			return result
		}
	}
	snapshot := s.ingest.Snapshot()
	events := make([]models.TrafficEvent, 0, len(snapshot.Events))
	for _, event := range snapshot.Events {
		if !withinRange(event.Time, query.Since, query.Until) {
			continue
		}
		if query.AgentID != "" && event.AgentID != query.AgentID {
			continue
		}
		if search := strings.ToLower(strings.TrimSpace(query.Search)); search != "" && !eventMatchesSearch(event, search) {
			continue
		}
		if query.Type != "" && event.Type != query.Type {
			continue
		}
		if query.Proto != "" && event.Proto != query.Proto {
			continue
		}
		if query.RuleName != "" && event.RuleName != query.RuleName {
			continue
		}
		if query.Action != "" && event.Action != query.Action {
			continue
		}
		if query.SrcIP != "" && event.SrcIP != query.SrcIP {
			continue
		}
		if query.DstIP != "" && event.DstIP != query.DstIP {
			continue
		}
		if query.Port > 0 && int(event.SrcPort) != query.Port && int(event.DstPort) != query.Port {
			continue
		}
		if event.Suspicion < query.MinSuspicion {
			continue
		}
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].Time.After(events[j].Time)
	})
	total := len(events)
	offset := normalizeOffset(query.Offset)
	if offset >= len(events) {
		return models.EventQueryResult{Total: total}
	}
	if offset > 0 {
		events = events[offset:]
	}
	limit := normalizeLimit(query.Limit, 100)
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return models.EventQueryResult{
		Total:  total,
		Events: events,
	}
}

func eventMatchesSearch(event models.TrafficEvent, search string) bool {
	if search == "" {
		return true
	}
	candidates := []string{
		event.EventID,
		event.AgentID,
		event.Type,
		event.Proto,
		event.RuleName,
		event.Action,
		event.SrcIP,
		event.DstIP,
		event.BundleVer,
		strings.Join(event.Tags, " "),
	}
	for _, candidate := range candidates {
		if strings.Contains(strings.ToLower(candidate), search) {
			return true
		}
	}
	if strings.Contains(strings.ToLower(strconv.FormatInt(event.StreamID, 10)), search) {
		return true
	}
	if strings.Contains(strings.ToLower(strconv.Itoa(int(event.SrcPort))), search) {
		return true
	}
	if strings.Contains(strings.ToLower(strconv.Itoa(int(event.DstPort))), search) {
		return true
	}
	if len(event.Props) > 0 {
		if payload, err := json.Marshal(event.Props); err == nil && strings.Contains(strings.ToLower(string(payload)), search) {
			return true
		}
	}
	return false
}

func (s *Service) SuspiciousEvents(limit int) models.EventQueryResult {
	return s.Events(models.EventQuery{
		MinSuspicion: 1,
		Limit:        limit,
	})
}

func (s *Service) Rules(query models.TimeRangeQuery) []models.RuleReportItem {
	if s.query != nil {
		if items, err := s.query.QueryRules(query); err == nil {
			return items
		}
	}
	snapshot := s.ingest.Snapshot()
	byRule := make(map[string]*models.RuleReportItem)
	for _, event := range snapshot.Events {
		if !withinRange(event.Time, query.Since, query.Until) {
			continue
		}
		if event.RuleName == "" {
			continue
		}
		item, ok := byRule[event.RuleName]
		if !ok {
			item = &models.RuleReportItem{RuleName: event.RuleName}
			byRule[event.RuleName] = item
		}
		if event.Type == "rule_hit" {
			item.Hits++
		}
		if event.Action != "" {
			item.Actions++
		}
		if event.Time.After(item.LastHitAt) {
			item.LastHitAt = event.Time
		}
		item.Agents = appendUnique(item.Agents, event.AgentID)
	}
	items := make([]models.RuleReportItem, 0, len(byRule))
	for _, item := range byRule {
		sort.Strings(item.Agents)
		items = append(items, *item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Hits == items[j].Hits {
			return items[i].RuleName < items[j].RuleName
		}
		return items[i].Hits > items[j].Hits
	})
	limit := normalizeLimit(query.Limit, 20)
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

func (s *Service) Protocols(query models.TimeRangeQuery) []models.ProtocolReportItem {
	if s.query != nil {
		if items, err := s.query.QueryProtocols(query); err == nil {
			return items
		}
	}
	snapshot := s.ingest.Snapshot()
	byProtocol := make(map[string]*models.ProtocolReportItem)
	for _, event := range snapshot.Events {
		if !withinRange(event.Time, query.Since, query.Until) {
			continue
		}
		protocol := event.Proto
		if protocol == "" {
			protocol = "unknown"
		}
		item, ok := byProtocol[protocol]
		if !ok {
			item = &models.ProtocolReportItem{Protocol: protocol}
			byProtocol[protocol] = item
		}
		item.Events++
		if isSuspiciousEvent(event) {
			item.SuspiciousEvents++
		}
		if event.Time.After(item.LastSeenAt) {
			item.LastSeenAt = event.Time
		}
	}
	items := make([]models.ProtocolReportItem, 0, len(byProtocol))
	for _, item := range byProtocol {
		items = append(items, *item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Events == items[j].Events {
			return items[i].Protocol < items[j].Protocol
		}
		return items[i].Events > items[j].Events
	})
	return items
}

func (s *Service) Nodes(query models.TimeRangeQuery) []models.NodeReportItem {
	nodeList := s.nodes.List()
	if s.query != nil {
		if items, err := s.query.QueryNodeStats(query); err == nil {
			byNode := make(map[string]*models.NodeReportItem, len(items))
			for i := range items {
				item := items[i]
				byNode[item.AgentID] = &item
			}
			for _, node := range nodeList {
				item, ok := byNode[node.ID]
				if !ok {
					item = &models.NodeReportItem{AgentID: node.ID}
					byNode[node.ID] = item
				}
				item.Name = node.Name
				item.Status = string(node.Status)
				if node.LastSeenAt.After(item.LastSeenAt) {
					item.LastSeenAt = node.LastSeenAt
				}
			}
			out := make([]models.NodeReportItem, 0, len(byNode))
			for _, item := range byNode {
				out = append(out, *item)
			}
			sort.Slice(out, func(i, j int) bool {
				if out[i].Events == out[j].Events {
					return out[i].AgentID < out[j].AgentID
				}
				return out[i].Events > out[j].Events
			})
			return out
		}
	}
	snapshot := s.ingest.Snapshot()

	byNode := make(map[string]*models.NodeReportItem, len(nodeList))
	for _, node := range nodeList {
		byNode[node.ID] = &models.NodeReportItem{
			AgentID:    node.ID,
			Name:       node.Name,
			Status:     string(node.Status),
			LastSeenAt: node.LastSeenAt,
		}
	}
	for _, event := range snapshot.Events {
		if !withinRange(event.Time, query.Since, query.Until) {
			continue
		}
		item, ok := byNode[event.AgentID]
		if !ok {
			item = &models.NodeReportItem{AgentID: event.AgentID}
			byNode[event.AgentID] = item
		}
		item.Events++
		if event.Type == "rule_hit" {
			item.RuleHits++
		}
		if isSuspiciousEvent(event) {
			item.SuspiciousEvents++
		}
		if event.Time.After(item.LastSeenAt) {
			item.LastSeenAt = event.Time
		}
	}
	items := make([]models.NodeReportItem, 0, len(byNode))
	for _, item := range byNode {
		items = append(items, *item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Events == items[j].Events {
			return items[i].AgentID < items[j].AgentID
		}
		return items[i].Events > items[j].Events
	})
	return items
}

func (s *Service) Metrics(query models.MetricQuery) models.MetricQueryResult {
	if s.query != nil {
		if result, err := s.query.QueryMetrics(query); err == nil {
			return result
		}
	}
	snapshot := s.ingest.Snapshot()
	items := make([]models.MetricReportItem, 0, len(snapshot.Metrics))
	for _, metric := range snapshot.Metrics {
		if !withinRange(metric.Time, query.Since, query.Until) {
			continue
		}
		if query.AgentID != "" && metric.AgentID != query.AgentID {
			continue
		}
		if query.Name != "" && !strings.EqualFold(metric.Name, query.Name) {
			continue
		}
		items = append(items, models.MetricReportItem{
			AgentID: metric.AgentID,
			Name:    metric.Name,
			Value:   metric.Value,
			Labels:  metric.Labels,
			Time:    metric.Time,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Time.Equal(items[j].Time) {
			return items[i].Name < items[j].Name
		}
		return items[i].Time.After(items[j].Time)
	})
	total := len(items)
	offset := normalizeOffset(query.Offset)
	if offset >= len(items) {
		return models.MetricQueryResult{Total: total}
	}
	if offset > 0 {
		items = items[offset:]
	}
	limit := normalizeLimit(query.Limit, 100)
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return models.MetricQueryResult{
		Total:   total,
		Metrics: items,
	}
}

func (s *Service) TrafficSeries(query models.TimeRangeQuery) models.TimeSeriesResponse {
	if s.query != nil {
		if result, err := s.query.QueryTrafficSeries(query); err == nil {
			return result
		}
	}
	snapshot := s.ingest.Snapshot()
	series := make(map[time.Time]*models.TimeSeriesBucket)
	for _, event := range snapshot.Events {
		if !withinRange(event.Time, query.Since, query.Until) {
			continue
		}
		if query.AgentID != "" && event.AgentID != query.AgentID {
			continue
		}
		bucketTime := event.Time.UTC().Truncate(time.Minute)
		bucket, ok := series[bucketTime]
		if !ok {
			bucket = &models.TimeSeriesBucket{Timestamp: bucketTime}
			series[bucketTime] = bucket
		}
		bucket.Events++
		if event.Type == "rule_hit" {
			bucket.RuleHits++
		}
		if isSuspiciousEvent(event) {
			bucket.Suspicious++
		}
	}
	buckets := make([]models.TimeSeriesBucket, 0, len(series))
	for _, bucket := range series {
		buckets = append(buckets, *bucket)
	}
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].Timestamp.Before(buckets[j].Timestamp)
	})
	limit := normalizeLimit(query.Limit, 120)
	if limit > 0 && len(buckets) > limit {
		buckets = buckets[len(buckets)-limit:]
	}
	return models.TimeSeriesResponse{Buckets: buckets}
}

func (s *Service) EventBreakdown(query models.TimeRangeQuery) models.EventBreakdown {
	if s.query != nil {
		if result, err := s.query.QueryEventBreakdown(query); err == nil {
			return result
		}
	}
	snapshot := s.ingest.Snapshot()
	bySource := make(map[string]*models.EventBreakdownItem)
	byDestination := make(map[string]*models.EventBreakdownItem)
	bySNI := make(map[string]*models.EventBreakdownItem)
	byProtocol := make(map[string]*models.EventBreakdownItem)

	for _, event := range snapshot.Events {
		if !withinRange(event.Time, query.Since, query.Until) {
			continue
		}
		if query.AgentID != "" && event.AgentID != query.AgentID {
			continue
		}
		if src := strings.TrimSpace(event.SrcIP); src != "" {
			addEventBreakdownItem(bySource, src, event)
		}
		if dst := strings.TrimSpace(event.DstIP); dst != "" {
			addEventBreakdownItem(byDestination, dst, event)
		}
		if sni := extractEventSNI(event); sni != "" {
			addEventBreakdownItem(bySNI, sni, event)
		}
		protocol := strings.TrimSpace(event.Proto)
		if protocol == "" {
			protocol = "unknown"
		}
		addEventBreakdownItem(byProtocol, protocol, event)
	}

	limit := normalizeLimit(query.Limit, 8)
	return models.EventBreakdown{
		SourceIPs:      rankEventBreakdownItems(bySource, limit),
		DestinationIPs: rankEventBreakdownItems(byDestination, limit),
		SNIs:           rankEventBreakdownItems(bySNI, limit),
		Protocols:      rankEventBreakdownItems(byProtocol, limit),
	}
}

func normalizeLimit(limit int, fallback int) int {
	if limit <= 0 {
		return fallback
	}
	return limit
}

func normalizeOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
}

func appendUnique(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func isSuspiciousEvent(event models.TrafficEvent) bool {
	return event.Type == "suspicious_flow" || event.Suspicion > 0
}

func withinRange(ts time.Time, since, until time.Time) bool {
	if !since.IsZero() && ts.Before(since) {
		return false
	}
	if !until.IsZero() && ts.After(until) {
		return false
	}
	return true
}

func addEventBreakdownItem(groups map[string]*models.EventBreakdownItem, key string, event models.TrafficEvent) {
	if key == "" {
		return
	}
	item, ok := groups[key]
	if !ok {
		item = &models.EventBreakdownItem{Value: key}
		groups[key] = item
	}
	item.Events++
	if isSuspiciousEvent(event) {
		item.SuspiciousEvents++
	}
	if event.Time.After(item.LastSeenAt) {
		item.LastSeenAt = event.Time
	}
}

func rankEventBreakdownItems(groups map[string]*models.EventBreakdownItem, limit int) []models.EventBreakdownItem {
	items := make([]models.EventBreakdownItem, 0, len(groups))
	for _, item := range groups {
		items = append(items, *item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Events == items[j].Events {
			return items[i].Value < items[j].Value
		}
		return items[i].Events > items[j].Events
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

func extractEventSNI(event models.TrafficEvent) string {
	if sni := extractNestedString(event.Props, "tls", "req", "sni"); sni != "" {
		return sni
	}
	return extractNestedString(event.Props, "quic", "req", "sni")
}

func extractNestedString(root map[string]any, keys ...string) string {
	if len(root) == 0 || len(keys) == 0 {
		return ""
	}
	var current any = root
	for _, key := range keys {
		nextMap, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = nextMap[key]
		if !ok {
			return ""
		}
	}
	value, ok := current.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}
