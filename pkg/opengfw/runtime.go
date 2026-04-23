package opengfw

import (
	"context"
	"fmt"
	"net"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/tcp"
	"github.com/apernet/OpenGFW/analyzer/udp"
	"github.com/apernet/OpenGFW/engine"
	gfwio "github.com/apernet/OpenGFW/io"
	"github.com/apernet/OpenGFW/modifier"
	modUDP "github.com/apernet/OpenGFW/modifier/udp"
	"github.com/apernet/OpenGFW/pkg/models"
	"github.com/apernet/OpenGFW/pkg/telemetry"
	"github.com/apernet/OpenGFW/ruleset"
)

type CompileOptions struct {
	Logger               ruleset.Logger
	GeoSiteFilename      string
	GeoIPFilename        string
	ProtectedDialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

type noopRulesetLogger struct{}

func (l *noopRulesetLogger) Log(info ruleset.StreamInfo, name string) {}

func (l *noopRulesetLogger) MatchError(info ruleset.StreamInfo, name string, err error) {}

func DefaultAnalyzers() []analyzer.Analyzer {
	return []analyzer.Analyzer{
		&tcp.FETAnalyzer{},
		&tcp.HTTPAnalyzer{},
		&tcp.SocksAnalyzer{},
		&tcp.SSHAnalyzer{},
		&tcp.TLSAnalyzer{},
		&tcp.TrojanAnalyzer{},
		&udp.DNSAnalyzer{},
		&udp.OpenVPNAnalyzer{},
		&udp.QUICAnalyzer{},
		&udp.WireGuardAnalyzer{},
	}
}

func DefaultModifiers() []modifier.Modifier {
	return []modifier.Modifier{
		&modUDP.DNSModifier{},
	}
}

func DefaultTelemetryBundle(version string) models.Bundle {
	profile := telemetry.DefaultProfile()
	analyzers := DefaultAnalyzers()
	profile.Analyzers = make([]string, 0, len(analyzers))
	for _, analyzer := range analyzers {
		if analyzer == nil {
			continue
		}
		profile.Analyzers = append(profile.Analyzers, analyzer.Name())
	}
	return models.Bundle{
		Version: version,
		Runtime: models.RuntimeConfig{
			IO: models.RuntimeIOConfig{
				Local: true,
			},
		},
		Telemetry: profile,
	}
}

func MergeWithDefaultTelemetry(bundle models.Bundle) models.Bundle {
	base := DefaultTelemetryBundle(bundle.Version)
	bundle.Runtime.IO.Local = base.Runtime.IO.Local || bundle.Runtime.IO.Local
	bundle.Telemetry = base.Telemetry
	return bundle
}

func BuildEngineConfig(runtime models.RuntimeConfig, logger engine.Logger) (*engine.Config, error) {
	packetIO, err := gfwio.NewNFQueuePacketIO(gfwio.NFQueuePacketIOConfig{
		QueueSize:   runtime.IO.QueueSize,
		ReadBuffer:  runtime.IO.RcvBuf,
		WriteBuffer: runtime.IO.SndBuf,
		Local:       runtime.IO.Local,
		RST:         runtime.IO.RST,
	})
	if err != nil {
		return nil, err
	}
	return &engine.Config{
		Logger:                           logger,
		IO:                               packetIO,
		Workers:                          runtime.Workers.Count,
		WorkerQueueSize:                  runtime.Workers.QueueSize,
		WorkerTCPMaxBufferedPagesTotal:   runtime.Workers.TCPMaxBufferedPagesTotal,
		WorkerTCPMaxBufferedPagesPerConn: runtime.Workers.TCPMaxBufferedPagesPerConn,
		WorkerUDPMaxStreams:              runtime.Workers.UDPMaxStreams,
	}, nil
}

func CompileBundle(bundle models.Bundle, options CompileOptions) (ruleset.Ruleset, error) {
	rs, err := CompileRuleSpecs(bundle.Rules, options)
	if err != nil {
		return nil, err
	}
	return WrapRulesetWithTelemetry(rs, bundle.Telemetry)
}

func CompileRuleSpecs(ruleSpecs []models.RuleSpec, options CompileOptions) (ruleset.Ruleset, error) {
	exprRules := make([]ruleset.ExprRule, 0, len(ruleSpecs))
	for _, rule := range ruleSpecs {
		exprRule := ruleset.ExprRule{
			Name:   rule.Name,
			Action: rule.Action,
			Log:    rule.Log,
			Expr:   rule.Expr,
		}
		if rule.Modifier != nil {
			exprRule.Modifier = ruleset.ModifierEntry{
				Name: rule.Modifier.Name,
				Args: rule.Modifier.Args,
			}
		}
		exprRules = append(exprRules, exprRule)
	}
	return CompileExprRules(exprRules, options)
}

func CompileExprRules(exprRules []ruleset.ExprRule, options CompileOptions) (ruleset.Ruleset, error) {
	logger := options.Logger
	if logger == nil {
		logger = &noopRulesetLogger{}
	}
	return ruleset.CompileExprRules(exprRules, DefaultAnalyzers(), DefaultModifiers(), &ruleset.BuiltinConfig{
		Logger:               logger,
		GeoSiteFilename:      options.GeoSiteFilename,
		GeoIpFilename:        options.GeoIPFilename,
		ProtectedDialContext: options.ProtectedDialContext,
	})
}

type telemetryRuleset struct {
	base  ruleset.Ruleset
	extra []analyzer.Analyzer
}

func (r *telemetryRuleset) Analyzers(info ruleset.StreamInfo) []analyzer.Analyzer {
	baseAnalyzers := r.base.Analyzers(info)
	if len(r.extra) == 0 {
		return baseAnalyzers
	}
	seen := make(map[string]struct{}, len(baseAnalyzers)+len(r.extra))
	out := make([]analyzer.Analyzer, 0, len(baseAnalyzers)+len(r.extra))
	for _, analyzer := range baseAnalyzers {
		if analyzer == nil {
			continue
		}
		name := analyzer.Name()
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, analyzer)
	}
	for _, analyzer := range r.extra {
		if analyzer == nil {
			continue
		}
		name := analyzer.Name()
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, analyzer)
	}
	return out
}

func (r *telemetryRuleset) Match(info ruleset.StreamInfo) ruleset.MatchResult {
	return r.base.Match(info)
}

func WrapRulesetWithTelemetry(rs ruleset.Ruleset, profile models.TelemetryProfile) (ruleset.Ruleset, error) {
	profile = telemetry.NormalizeProfile(profile)
	if len(profile.Analyzers) == 0 {
		return rs, nil
	}

	defaultByName := make(map[string]analyzer.Analyzer)
	for _, analyzer := range DefaultAnalyzers() {
		defaultByName[analyzer.Name()] = analyzer
	}

	extra := make([]analyzer.Analyzer, 0, len(profile.Analyzers))
	for _, name := range profile.Analyzers {
		analyzer, ok := defaultByName[name]
		if !ok {
			return nil, fmt.Errorf("unknown telemetry analyzer %q", name)
		}
		extra = append(extra, analyzer)
	}

	return &telemetryRuleset{
		base:  rs,
		extra: extra,
	}, nil
}
