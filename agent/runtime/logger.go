package runtime

import (
	"fmt"

	"github.com/apernet/OpenGFW/agent/report"
	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/engine"
	"github.com/apernet/OpenGFW/pkg/models"
	"github.com/apernet/OpenGFW/ruleset"

	"go.uber.org/zap"
)

var _ engine.Logger = (*eventLogger)(nil)
var _ ruleset.Logger = (*eventLogger)(nil)

type eventLogger struct {
	logger            *zap.Logger
	collector         *report.Collector
	bundleVersionFunc func() string
	profileFunc       func() models.TelemetryProfile
}

func newEventLogger(logger *zap.Logger, collector *report.Collector, bundleVersionFunc func() string, profileFunc func() models.TelemetryProfile) *eventLogger {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &eventLogger{
		logger:            logger,
		collector:         collector,
		bundleVersionFunc: bundleVersionFunc,
		profileFunc:       profileFunc,
	}
}

func (l *eventLogger) WorkerStart(id int) {
	l.logger.Debug("worker started", zap.Int("id", id))
}

func (l *eventLogger) WorkerStop(id int) {
	l.logger.Debug("worker stopped", zap.Int("id", id))
}

func (l *eventLogger) TCPStreamNew(workerID int, info ruleset.StreamInfo) {
	l.logger.Debug("new TCP stream",
		zap.Int("workerID", workerID),
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()))
	l.addMetric("streams_total", 1, map[string]string{"proto": "tcp"})
}

func (l *eventLogger) TCPStreamPropUpdate(info ruleset.StreamInfo, close bool) {
	l.logger.Debug("TCP stream property update",
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.Any("props", info.Props),
		zap.Bool("close", close))
	l.addMetric("stream_prop_updates_total", 1, map[string]string{"proto": "tcp"})
}

func (l *eventLogger) TCPStreamAction(info ruleset.StreamInfo, action ruleset.Action, noMatch bool) {
	l.logger.Info("TCP stream action",
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.String("action", action.String()),
		zap.Bool("noMatch", noMatch))
	if l.shouldEmitFlowSummary(info.Props) {
		l.emit(infoToEvent("stream_action", info, action.String(), "", cloneCombinedProps(info.Props), l.bundleVersion()))
	}
	l.emitSuspiciousIfNeeded(info, action.String())
	l.addMetric("stream_actions_total", 1, map[string]string{
		"proto":    "tcp",
		"action":   action.String(),
		"no_match": fmt.Sprintf("%t", noMatch),
	})
}

func (l *eventLogger) UDPStreamNew(workerID int, info ruleset.StreamInfo) {
	l.logger.Debug("new UDP stream",
		zap.Int("workerID", workerID),
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()))
	l.addMetric("streams_total", 1, map[string]string{"proto": "udp"})
}

func (l *eventLogger) UDPStreamPropUpdate(info ruleset.StreamInfo, close bool) {
	l.logger.Debug("UDP stream property update",
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.Any("props", info.Props),
		zap.Bool("close", close))
	l.addMetric("stream_prop_updates_total", 1, map[string]string{"proto": "udp"})
}

func (l *eventLogger) UDPStreamAction(info ruleset.StreamInfo, action ruleset.Action, noMatch bool) {
	l.logger.Info("UDP stream action",
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.String("action", action.String()),
		zap.Bool("noMatch", noMatch))
	if l.shouldEmitFlowSummary(info.Props) {
		l.emit(infoToEvent("stream_action", info, action.String(), "", cloneCombinedProps(info.Props), l.bundleVersion()))
	}
	l.emitSuspiciousIfNeeded(info, action.String())
	l.addMetric("stream_actions_total", 1, map[string]string{
		"proto":    "udp",
		"action":   action.String(),
		"no_match": fmt.Sprintf("%t", noMatch),
	})
}

func (l *eventLogger) ModifyError(info ruleset.StreamInfo, err error) {
	l.logger.Error("modify error",
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.Error(err))
	l.emit(infoToEvent("modify_error", info, "", "", map[string]any{"error": err.Error()}, l.bundleVersion()))
}

func (l *eventLogger) AnalyzerDebugf(streamID int64, name string, format string, args ...interface{}) {
	l.logger.Debug("analyzer debug message",
		zap.Int64("id", streamID),
		zap.String("name", name),
		zap.String("msg", fmt.Sprintf(format, args...)))
}

func (l *eventLogger) AnalyzerInfof(streamID int64, name string, format string, args ...interface{}) {
	l.logger.Info("analyzer info message",
		zap.Int64("id", streamID),
		zap.String("name", name),
		zap.String("msg", fmt.Sprintf(format, args...)))
}

func (l *eventLogger) AnalyzerErrorf(streamID int64, name string, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.logger.Error("analyzer error message",
		zap.Int64("id", streamID),
		zap.String("name", name),
		zap.String("msg", msg))
	l.emit(models.TrafficEvent{
		Type:      "analyzer_error",
		StreamID:  streamID,
		Props:     map[string]any{"name": name, "message": msg},
		BundleVer: l.bundleVersion(),
	})
}

func (l *eventLogger) Log(info ruleset.StreamInfo, name string) {
	l.logger.Info("ruleset log",
		zap.String("name", name),
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.Any("props", info.Props))
	if l.shouldEmitRuleHit(info.Props) {
		event := infoToEvent("rule_hit", info, "", name, cloneCombinedProps(info.Props), l.bundleVersion())
		event.Suspicion = suspicionScore(info.Props)
		l.emit(event)
	}
	l.emitSuspiciousIfNeeded(info, "")
	l.addMetric("rule_hits_total", 1, map[string]string{"rule": name})
}

func (l *eventLogger) MatchError(info ruleset.StreamInfo, name string, err error) {
	l.logger.Error("ruleset match error",
		zap.String("name", name),
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.Error(err))
	event := infoToEvent("ruleset_match_error", info, "", name, map[string]any{"error": err.Error()}, l.bundleVersion())
	l.emit(event)
}

func (l *eventLogger) emitSuspiciousIfNeeded(info ruleset.StreamInfo, action string) {
	score := suspicionScore(info.Props)
	if score == 0 {
		return
	}
	event := infoToEvent("suspicious_flow", info, action, "", cloneCombinedProps(info.Props), l.bundleVersion())
	event.Suspicion = score
	l.emit(event)
	l.addMetric("suspicious_flows_total", 1, map[string]string{"proto": info.Protocol.String()})
}

func (l *eventLogger) emit(event models.TrafficEvent) {
	if l.collector == nil {
		return
	}
	l.collector.Emit(event)
}

func (l *eventLogger) addMetric(name string, value float64, labels map[string]string) {
	if l.collector == nil {
		return
	}
	l.collector.AddMetric(models.MetricSample{
		Name:   name,
		Value:  value,
		Labels: labels,
	})
}

func (l *eventLogger) bundleVersion() string {
	if l.bundleVersionFunc == nil {
		return ""
	}
	return l.bundleVersionFunc()
}

func (l *eventLogger) profile() models.TelemetryProfile {
	if l.profileFunc == nil {
		return models.TelemetryProfile{}
	}
	return l.profileFunc()
}

func (l *eventLogger) shouldEmitRuleHit(props analyzer.CombinedPropMap) bool {
	profile := l.profile()
	if !profile.Events.RuleHit {
		return false
	}
	if profile.Events.SuspiciousOnly && suspicionScore(props) == 0 {
		return false
	}
	return true
}

func (l *eventLogger) shouldEmitFlowSummary(props analyzer.CombinedPropMap) bool {
	profile := l.profile()
	if !profile.Events.FlowSummary {
		return false
	}
	if profile.Events.SuspiciousOnly && suspicionScore(props) == 0 {
		return false
	}
	return true
}

func infoToEvent(eventType string, info ruleset.StreamInfo, action string, ruleName string, props map[string]any, bundleVersion string) models.TrafficEvent {
	return models.TrafficEvent{
		Type:      eventType,
		StreamID:  info.ID,
		Proto:     info.Protocol.String(),
		SrcIP:     info.SrcIP.String(),
		DstIP:     info.DstIP.String(),
		SrcPort:   info.SrcPort,
		DstPort:   info.DstPort,
		RuleName:  ruleName,
		Action:    action,
		Props:     props,
		BundleVer: bundleVersion,
	}
}

func cloneCombinedProps(props analyzer.CombinedPropMap) map[string]any {
	if len(props) == 0 {
		return nil
	}
	out := make(map[string]any, len(props))
	for key, value := range props {
		out[key] = clonePropMap(value)
	}
	return out
}

func clonePropMap(props analyzer.PropMap) map[string]any {
	if len(props) == 0 {
		return nil
	}
	out := make(map[string]any, len(props))
	for key, value := range props {
		if nested, ok := value.(analyzer.PropMap); ok {
			out[key] = clonePropMap(nested)
			continue
		}
		out[key] = value
	}
	return out
}

func suspicionScore(props analyzer.CombinedPropMap) int {
	score := 0
	if isTrue(props.Get("fet", "yes")) {
		score += 50
	}
	if isTrue(props.Get("trojan", "yes")) {
		score += 80
	}
	return score
}

func isTrue(v any) bool {
	b, ok := v.(bool)
	return ok && b
}
