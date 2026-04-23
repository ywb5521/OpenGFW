package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/apernet/OpenGFW/pkg/models"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgresStore struct {
	db *sql.DB
}

type PruneResult struct {
	DeletedEvents  int64
	DeletedMetrics int64
}

type postgresMigration struct {
	Version    int
	Name       string
	Statements []string
}

const createMigrationsTableSQL = `
CREATE TABLE IF NOT EXISTS master_schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
`

var postgresMigrations = []postgresMigration{
	{
		Version: 1,
		Name:    "core_metadata",
		Statements: []string{
			`CREATE TABLE IF NOT EXISTS master_sequences (
  name TEXT PRIMARY KEY,
  value BIGINT NOT NULL
)`,
			`CREATE TABLE IF NOT EXISTS master_nodes (
  id TEXT PRIMARY KEY,
  payload JSONB NOT NULL
)`,
			`CREATE TABLE IF NOT EXISTS master_bootstrap_tokens (
  token TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL
)`,
			`CREATE TABLE IF NOT EXISTS master_policy_bundles (
  version TEXT PRIMARY KEY,
  payload JSONB NOT NULL
)`,
			`CREATE TABLE IF NOT EXISTS master_policy_tasks (
  agent_id TEXT NOT NULL,
  task_id TEXT PRIMARY KEY,
  payload JSONB NOT NULL
)`,
			`CREATE TABLE IF NOT EXISTS master_release_artifacts (
  version TEXT PRIMARY KEY,
  payload JSONB NOT NULL
)`,
			`CREATE TABLE IF NOT EXISTS master_release_tasks (
  agent_id TEXT NOT NULL,
  task_id TEXT PRIMARY KEY,
  payload JSONB NOT NULL
)`,
		},
	},
	{
		Version: 2,
		Name:    "traffic_events",
		Statements: []string{
			`CREATE TABLE IF NOT EXISTS master_traffic_events (
  event_id TEXT PRIMARY KEY,
  event_time TIMESTAMPTZ NOT NULL,
  agent_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  proto TEXT,
  rule_name TEXT,
  suspicion INTEGER NOT NULL DEFAULT 0,
  payload JSONB NOT NULL
)`,
			`CREATE INDEX IF NOT EXISTS idx_master_traffic_events_time ON master_traffic_events (event_time DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_master_traffic_events_agent_time ON master_traffic_events (agent_id, event_time DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_master_traffic_events_type_time ON master_traffic_events (event_type, event_time DESC)`,
		},
	},
	{
		Version: 3,
		Name:    "metric_samples",
		Statements: []string{
			`CREATE TABLE IF NOT EXISTS master_metric_samples (
  id BIGSERIAL PRIMARY KEY,
  sample_time TIMESTAMPTZ NOT NULL,
  agent_id TEXT,
  metric_name TEXT NOT NULL,
  payload JSONB NOT NULL
)`,
			`CREATE INDEX IF NOT EXISTS idx_master_metric_samples_time ON master_metric_samples (sample_time DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_master_metric_samples_name_time ON master_metric_samples (metric_name, sample_time DESC)`,
		},
	},
	{
		Version: 4,
		Name:    "admin_auth",
		Statements: []string{
			`CREATE TABLE IF NOT EXISTS master_admin_users (
  id BIGSERIAL PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
			`CREATE TABLE IF NOT EXISTS master_admin_sessions (
  token TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES master_admin_users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
			`CREATE INDEX IF NOT EXISTS idx_master_admin_sessions_expires_at ON master_admin_sessions (expires_at ASC)`,
		},
	},
}

func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	if dsn == "" {
		return nil, fmt.Errorf("database dsn is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetMaxIdleConns(10)
	db.SetMaxOpenConns(20)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	store := &PostgresStore{db: db}
	if err := store.ensureSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *PostgresStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *PostgresStore) ensureSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, createMigrationsTableSQL); err != nil {
		return err
	}
	applied, err := s.loadAppliedMigrations(ctx)
	if err != nil {
		return err
	}
	for _, migration := range postgresMigrations {
		if applied[migration.Version] {
			continue
		}
		if err := s.applyMigration(ctx, migration); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresStore) applyMigration(ctx context.Context, migration postgresMigration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, statement := range migration.Statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO master_schema_migrations (version, name, applied_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (version) DO NOTHING
	`, migration.Version, migration.Name); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) LoadNodes() (NodeSnapshot, error) {
	nodes := make(map[string]*models.AgentNode)
	rows, err := s.db.Query(`SELECT id, payload FROM master_nodes`)
	if err != nil {
		return NodeSnapshot{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var payload []byte
		if err := rows.Scan(&id, &payload); err != nil {
			return NodeSnapshot{}, err
		}
		var node models.AgentNode
		if err := json.Unmarshal(payload, &node); err != nil {
			return NodeSnapshot{}, err
		}
		nodes[id] = &node
	}
	if err := rows.Err(); err != nil {
		return NodeSnapshot{}, err
	}

	bootstrap := make(map[string]string)
	tokenRows, err := s.db.Query(`SELECT token, agent_id FROM master_bootstrap_tokens`)
	if err != nil {
		return NodeSnapshot{}, err
	}
	defer tokenRows.Close()
	for tokenRows.Next() {
		var token, agentID string
		if err := tokenRows.Scan(&token, &agentID); err != nil {
			return NodeSnapshot{}, err
		}
		bootstrap[token] = agentID
	}
	if err := tokenRows.Err(); err != nil {
		return NodeSnapshot{}, err
	}

	seq, err := s.loadSequence("nodes")
	if err != nil {
		return NodeSnapshot{}, err
	}
	return NodeSnapshot{
		Nodes:     nodes,
		Bootstrap: bootstrap,
		Seq:       seq,
	}, nil
}

func (s *PostgresStore) SaveNodes(snapshot NodeSnapshot) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM master_nodes`); err != nil {
		return err
	}
	for id, node := range snapshot.Nodes {
		payload, err := json.Marshal(node)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO master_nodes (id, payload) VALUES ($1, $2)`, id, payload); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(`DELETE FROM master_bootstrap_tokens`); err != nil {
		return err
	}
	for token, agentID := range snapshot.Bootstrap {
		if _, err := tx.Exec(`INSERT INTO master_bootstrap_tokens (token, agent_id) VALUES ($1, $2)`, token, agentID); err != nil {
			return err
		}
	}

	if err := saveSequenceTx(tx, "nodes", snapshot.Seq); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) LoadPolicies() (PolicySnapshot, error) {
	bundles := make(map[string]models.Bundle)
	rows, err := s.db.Query(`SELECT version, payload FROM master_policy_bundles`)
	if err != nil {
		return PolicySnapshot{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var version string
		var payload []byte
		if err := rows.Scan(&version, &payload); err != nil {
			return PolicySnapshot{}, err
		}
		var bundle models.Bundle
		if err := json.Unmarshal(payload, &bundle); err != nil {
			return PolicySnapshot{}, err
		}
		bundles[version] = bundle
	}
	if err := rows.Err(); err != nil {
		return PolicySnapshot{}, err
	}

	tasks, err := s.loadTasks(`SELECT agent_id, task_id, payload FROM master_policy_tasks`)
	if err != nil {
		return PolicySnapshot{}, err
	}
	seq, err := s.loadSequence("policies")
	if err != nil {
		return PolicySnapshot{}, err
	}
	return PolicySnapshot{
		Bundles: bundles,
		Tasks:   tasks,
		Seq:     seq,
	}, nil
}

func (s *PostgresStore) SavePolicies(snapshot PolicySnapshot) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM master_policy_bundles`); err != nil {
		return err
	}
	for version, bundle := range snapshot.Bundles {
		payload, err := json.Marshal(bundle)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO master_policy_bundles (version, payload) VALUES ($1, $2)`, version, payload); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM master_policy_tasks`); err != nil {
		return err
	}
	if err := saveTasksTx(tx, `INSERT INTO master_policy_tasks (agent_id, task_id, payload) VALUES ($1, $2, $3)`, snapshot.Tasks); err != nil {
		return err
	}
	if err := saveSequenceTx(tx, "policies", snapshot.Seq); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) LoadReleases() (ReleaseSnapshot, error) {
	artifacts := make(map[string]models.ReleaseArtifact)
	rows, err := s.db.Query(`SELECT version, payload FROM master_release_artifacts`)
	if err != nil {
		return ReleaseSnapshot{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var version string
		var payload []byte
		if err := rows.Scan(&version, &payload); err != nil {
			return ReleaseSnapshot{}, err
		}
		var artifact models.ReleaseArtifact
		if err := json.Unmarshal(payload, &artifact); err != nil {
			return ReleaseSnapshot{}, err
		}
		artifacts[version] = artifact
	}
	if err := rows.Err(); err != nil {
		return ReleaseSnapshot{}, err
	}
	tasks, err := s.loadTasks(`SELECT agent_id, task_id, payload FROM master_release_tasks`)
	if err != nil {
		return ReleaseSnapshot{}, err
	}
	seq, err := s.loadSequence("releases")
	if err != nil {
		return ReleaseSnapshot{}, err
	}
	return ReleaseSnapshot{
		Artifacts: artifacts,
		Tasks:     tasks,
		Seq:       seq,
	}, nil
}

func (s *PostgresStore) SaveReleases(snapshot ReleaseSnapshot) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM master_release_artifacts`); err != nil {
		return err
	}
	for version, artifact := range snapshot.Artifacts {
		payload, err := json.Marshal(artifact)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO master_release_artifacts (version, payload) VALUES ($1, $2)`, version, payload); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM master_release_tasks`); err != nil {
		return err
	}
	if err := saveTasksTx(tx, `INSERT INTO master_release_tasks (agent_id, task_id, payload) VALUES ($1, $2, $3)`, snapshot.Tasks); err != nil {
		return err
	}
	if err := saveSequenceTx(tx, "releases", snapshot.Seq); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) LoadIngest(maxEvents, maxMetrics int) (IngestSnapshot, error) {
	eventLimit := maxEvents
	if eventLimit <= 0 {
		eventLimit = 10000
	}
	metricLimit := maxMetrics
	if metricLimit <= 0 {
		metricLimit = 10000
	}
	events, err := s.loadEvents(eventLimit)
	if err != nil {
		return IngestSnapshot{}, err
	}
	metrics, err := s.loadMetrics(metricLimit)
	if err != nil {
		return IngestSnapshot{}, err
	}
	return IngestSnapshot{
		Events:  events,
		Metrics: metrics,
	}, nil
}

func (s *PostgresStore) AppendEvents(events []models.TrafficEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, event := range events {
		payload, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`
			INSERT INTO master_traffic_events (event_id, event_time, agent_id, event_type, proto, rule_name, suspicion, payload)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (event_id) DO UPDATE SET
				event_time = EXCLUDED.event_time,
				agent_id = EXCLUDED.agent_id,
				event_type = EXCLUDED.event_type,
				proto = EXCLUDED.proto,
				rule_name = EXCLUDED.rule_name,
				suspicion = EXCLUDED.suspicion,
				payload = EXCLUDED.payload
		`, event.EventID, event.Time, event.AgentID, event.Type, nullableString(event.Proto), nullableString(event.RuleName), event.Suspicion, payload); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) AppendMetrics(metrics []models.MetricSample) error {
	if len(metrics) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, metric := range metrics {
		payload, err := json.Marshal(metric)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`
			INSERT INTO master_metric_samples (sample_time, agent_id, metric_name, payload)
			VALUES ($1, $2, $3, $4)
		`, metric.Time, nullableString(metric.AgentID), metric.Name, payload); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) PruneOldData(ctx context.Context, eventRetention, metricRetention time.Duration) (PruneResult, error) {
	var result PruneResult
	if eventRetention > 0 {
		cutoff := time.Now().UTC().Add(-eventRetention)
		res, err := s.db.ExecContext(ctx, `DELETE FROM master_traffic_events WHERE event_time < $1`, cutoff)
		if err != nil {
			return result, err
		}
		result.DeletedEvents, _ = res.RowsAffected()
	}
	if metricRetention > 0 {
		cutoff := time.Now().UTC().Add(-metricRetention)
		res, err := s.db.ExecContext(ctx, `DELETE FROM master_metric_samples WHERE sample_time < $1`, cutoff)
		if err != nil {
			return result, err
		}
		result.DeletedMetrics, _ = res.RowsAffected()
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM master_admin_sessions WHERE expires_at < NOW()`); err != nil {
		return result, err
	}
	return result, nil
}

func (s *PostgresStore) HasAdminUsers() (bool, error) {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM master_admin_users`).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *PostgresStore) BootstrapAdminUser(username, passwordHash string) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`LOCK TABLE master_admin_users IN EXCLUSIVE MODE`); err != nil {
		return 0, err
	}

	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM master_admin_users`).Scan(&count); err != nil {
		return 0, err
	}
	if count > 0 {
		return 0, fmt.Errorf("admin already configured")
	}

	var id int64
	if err := tx.QueryRow(`
		INSERT INTO master_admin_users (username, password_hash)
		VALUES ($1, $2)
		RETURNING id
	`, username, passwordHash).Scan(&id); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

func (s *PostgresStore) CreateAdminUser(username, passwordHash string) (int64, error) {
	var id int64
	err := s.db.QueryRow(`
		INSERT INTO master_admin_users (username, password_hash)
		VALUES ($1, $2)
		RETURNING id
	`, username, passwordHash).Scan(&id)
	return id, err
}

func (s *PostgresStore) GetAdminUserByUsername(username string) (int64, string, string, error) {
	var id int64
	var dbUsername string
	var passwordHash string
	err := s.db.QueryRow(`
		SELECT id, username, password_hash
		FROM master_admin_users
		WHERE username = $1
	`, username).Scan(&id, &dbUsername, &passwordHash)
	if errorsIsNoRows(err) {
		return 0, "", "", ErrNotFound
	}
	return id, dbUsername, passwordHash, err
}

func (s *PostgresStore) GetAdminUserByID(id int64) (string, error) {
	var username string
	err := s.db.QueryRow(`SELECT username FROM master_admin_users WHERE id = $1`, id).Scan(&username)
	if errorsIsNoRows(err) {
		return "", ErrNotFound
	}
	return username, err
}

func (s *PostgresStore) UpdateAdminPassword(userID int64, passwordHash string) error {
	_, err := s.db.Exec(`
		UPDATE master_admin_users
		SET password_hash = $2, updated_at = NOW()
		WHERE id = $1
	`, userID, passwordHash)
	return err
}

func (s *PostgresStore) CreateAdminSession(token string, userID int64, expiresAt time.Time) error {
	_, err := s.db.Exec(`
		INSERT INTO master_admin_sessions (token, user_id, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (token) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			expires_at = EXCLUDED.expires_at
	`, token, userID, expiresAt)
	return err
}

func (s *PostgresStore) GetAdminSession(token string) (int64, string, time.Time, error) {
	var userID int64
	var username string
	var expiresAt time.Time
	err := s.db.QueryRow(`
		SELECT s.user_id, u.username, s.expires_at
		FROM master_admin_sessions s
		JOIN master_admin_users u ON u.id = s.user_id
		WHERE s.token = $1
	`, token).Scan(&userID, &username, &expiresAt)
	if errorsIsNoRows(err) {
		return 0, "", time.Time{}, ErrNotFound
	}
	return userID, username, expiresAt, err
}

func (s *PostgresStore) DeleteAdminSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM master_admin_sessions WHERE token = $1`, token)
	return err
}

func (s *PostgresStore) QuerySummary() (models.ReportSummary, error) {
	summary := models.ReportSummary{
		GeneratedAt:      time.Now().UTC(),
		EventsByType:     make(map[string]int),
		EventsByProtocol: make(map[string]int),
		MetricsByName:    make(map[string]int),
	}

	if err := s.db.QueryRow(`
		SELECT COUNT(*), COALESCE(SUM(CASE WHEN event_type = 'suspicious_flow' OR suspicion > 0 THEN 1 ELSE 0 END), 0)
		FROM master_traffic_events
	`).Scan(&summary.EventCount, &summary.SuspiciousEvents); err != nil {
		return models.ReportSummary{}, err
	}

	eventRows, err := s.db.Query(`SELECT event_type, COUNT(*) FROM master_traffic_events GROUP BY event_type`)
	if err != nil {
		return models.ReportSummary{}, err
	}
	defer eventRows.Close()
	for eventRows.Next() {
		var eventType string
		var count int
		if err := eventRows.Scan(&eventType, &count); err != nil {
			return models.ReportSummary{}, err
		}
		summary.EventsByType[eventType] = count
	}
	if err := eventRows.Err(); err != nil {
		return models.ReportSummary{}, err
	}

	protoRows, err := s.db.Query(`SELECT COALESCE(NULLIF(proto, ''), 'unknown'), COUNT(*) FROM master_traffic_events GROUP BY COALESCE(NULLIF(proto, ''), 'unknown')`)
	if err != nil {
		return models.ReportSummary{}, err
	}
	defer protoRows.Close()
	for protoRows.Next() {
		var proto string
		var count int
		if err := protoRows.Scan(&proto, &count); err != nil {
			return models.ReportSummary{}, err
		}
		summary.EventsByProtocol[proto] = count
	}
	if err := protoRows.Err(); err != nil {
		return models.ReportSummary{}, err
	}

	if err := s.db.QueryRow(`SELECT COUNT(*) FROM master_metric_samples`).Scan(&summary.MetricCount); err != nil {
		return models.ReportSummary{}, err
	}
	metricRows, err := s.db.Query(`SELECT metric_name, COUNT(*) FROM master_metric_samples GROUP BY metric_name`)
	if err != nil {
		return models.ReportSummary{}, err
	}
	defer metricRows.Close()
	for metricRows.Next() {
		var name string
		var count int
		if err := metricRows.Scan(&name, &count); err != nil {
			return models.ReportSummary{}, err
		}
		summary.MetricsByName[name] = count
	}
	if err := metricRows.Err(); err != nil {
		return models.ReportSummary{}, err
	}
	return summary, nil
}

func (s *PostgresStore) QueryEvents(query models.EventQuery) (models.EventQueryResult, error) {
	whereSQL, args := buildEventWhere(query)

	countSQL := `SELECT COUNT(*) FROM master_traffic_events`
	if whereSQL != "" {
		countSQL += " WHERE " + whereSQL
	}
	var total int
	if err := s.db.QueryRow(countSQL, args...).Scan(&total); err != nil {
		return models.EventQueryResult{}, err
	}

	limit := normalizeLimit(query.Limit, 100)
	offset := normalizeOffset(query.Offset)
	sqlArgs := append([]any{}, args...)
	sqlArgs = append(sqlArgs, limit, offset)
	dataSQL := `SELECT payload FROM master_traffic_events`
	if whereSQL != "" {
		dataSQL += " WHERE " + whereSQL
	}
	dataSQL += fmt.Sprintf(" ORDER BY event_time DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)

	rows, err := s.db.Query(dataSQL, sqlArgs...)
	if err != nil {
		return models.EventQueryResult{}, err
	}
	defer rows.Close()

	var events []models.TrafficEvent
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return models.EventQueryResult{}, err
		}
		var event models.TrafficEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return models.EventQueryResult{}, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return models.EventQueryResult{}, err
	}
	return models.EventQueryResult{
		Total:  total,
		Events: events,
	}, nil
}

func (s *PostgresStore) QueryRules(query models.TimeRangeQuery) ([]models.RuleReportItem, error) {
	whereSQL, args := buildTimeWhere("event_time", query.Since, query.Until)
	sqlText := `
		SELECT
			rule_name,
			COUNT(*) FILTER (WHERE event_type = 'rule_hit') AS hits,
			COUNT(*) FILTER (WHERE COALESCE(payload->>'action', '') <> '') AS actions,
			ARRAY_REMOVE(ARRAY_AGG(DISTINCT agent_id), NULL) AS agents,
			MAX(event_time) AS last_hit_at
		FROM master_traffic_events
		WHERE rule_name IS NOT NULL AND rule_name <> ''
	`
	if whereSQL != "" {
		sqlText += " AND " + whereSQL
	}
	sqlText += `
		GROUP BY rule_name
		ORDER BY hits DESC, rule_name ASC
	`
	limit := normalizeLimit(query.Limit, 20)
	sqlText += fmt.Sprintf(" LIMIT $%d", len(args)+1)
	args = append(args, limit)

	rows, err := s.db.Query(sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []models.RuleReportItem
	for rows.Next() {
		var item models.RuleReportItem
		if err := rows.Scan(&item.RuleName, &item.Hits, &item.Actions, &item.Agents, &item.LastHitAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) QueryProtocols(query models.TimeRangeQuery) ([]models.ProtocolReportItem, error) {
	whereSQL, args := buildTimeWhere("event_time", query.Since, query.Until)
	sqlText := `
		SELECT
			COALESCE(NULLIF(proto, ''), 'unknown') AS protocol,
			COUNT(*) AS events,
			COUNT(*) FILTER (WHERE event_type = 'suspicious_flow' OR suspicion > 0) AS suspicious_events,
			MAX(event_time) AS last_seen_at
		FROM master_traffic_events
	`
	if whereSQL != "" {
		sqlText += " WHERE " + whereSQL
	}
	sqlText += `
		GROUP BY COALESCE(NULLIF(proto, ''), 'unknown')
		ORDER BY events DESC, protocol ASC
	`
	rows, err := s.db.Query(sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []models.ProtocolReportItem
	for rows.Next() {
		var item models.ProtocolReportItem
		if err := rows.Scan(&item.Protocol, &item.Events, &item.SuspiciousEvents, &item.LastSeenAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) QueryNodeStats(query models.TimeRangeQuery) ([]models.NodeReportItem, error) {
	whereSQL, args := buildTimeWhere("event_time", query.Since, query.Until)
	sqlText := `
		SELECT
			agent_id,
			COUNT(*) AS events,
			COUNT(*) FILTER (WHERE event_type = 'rule_hit') AS rule_hits,
			COUNT(*) FILTER (WHERE event_type = 'suspicious_flow' OR suspicion > 0) AS suspicious_events,
			MAX(event_time) AS last_seen_at
		FROM master_traffic_events
	`
	if whereSQL != "" {
		sqlText += " WHERE " + whereSQL
	}
	sqlText += `
		GROUP BY agent_id
		ORDER BY events DESC, agent_id ASC
	`
	rows, err := s.db.Query(sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []models.NodeReportItem
	for rows.Next() {
		var item models.NodeReportItem
		if err := rows.Scan(&item.AgentID, &item.Events, &item.RuleHits, &item.SuspiciousEvents, &item.LastSeenAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) QueryMetrics(query models.MetricQuery) (models.MetricQueryResult, error) {
	whereSQL, args := buildMetricWhere(query)
	countSQL := `SELECT COUNT(*) FROM master_metric_samples`
	if whereSQL != "" {
		countSQL += " WHERE " + whereSQL
	}
	var total int
	if err := s.db.QueryRow(countSQL, args...).Scan(&total); err != nil {
		return models.MetricQueryResult{}, err
	}

	limit := normalizeLimit(query.Limit, 100)
	offset := normalizeOffset(query.Offset)
	sqlArgs := append([]any{}, args...)
	sqlArgs = append(sqlArgs, limit, offset)

	dataSQL := `SELECT payload FROM master_metric_samples`
	if whereSQL != "" {
		dataSQL += " WHERE " + whereSQL
	}
	dataSQL += fmt.Sprintf(" ORDER BY sample_time DESC, id DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	rows, err := s.db.Query(dataSQL, sqlArgs...)
	if err != nil {
		return models.MetricQueryResult{}, err
	}
	defer rows.Close()

	var metrics []models.MetricReportItem
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return models.MetricQueryResult{}, err
		}
		var sample models.MetricSample
		if err := json.Unmarshal(payload, &sample); err != nil {
			return models.MetricQueryResult{}, err
		}
		metrics = append(metrics, models.MetricReportItem{
			AgentID: sample.AgentID,
			Name:    sample.Name,
			Value:   sample.Value,
			Labels:  sample.Labels,
			Time:    sample.Time,
		})
	}
	if err := rows.Err(); err != nil {
		return models.MetricQueryResult{}, err
	}
	return models.MetricQueryResult{
		Total:   total,
		Metrics: metrics,
	}, nil
}

func (s *PostgresStore) QueryTrafficSeries(query models.TimeRangeQuery) (models.TimeSeriesResponse, error) {
	whereSQL, args := buildTimeWhere("event_time", query.Since, query.Until)
	if query.AgentID != "" {
		args = append(args, query.AgentID)
		clause := fmt.Sprintf("agent_id = $%d", len(args))
		if whereSQL == "" {
			whereSQL = clause
		} else {
			whereSQL += " AND " + clause
		}
	}
	sqlText := `
		SELECT
			date_trunc('minute', event_time) AS bucket,
			COUNT(*) AS events,
			COUNT(*) FILTER (WHERE event_type = 'suspicious_flow' OR suspicion > 0) AS suspicious,
			COUNT(*) FILTER (WHERE event_type = 'rule_hit') AS rule_hits
		FROM master_traffic_events
	`
	if whereSQL != "" {
		sqlText += " WHERE " + whereSQL
	}
	sqlText += `
		GROUP BY bucket
		ORDER BY bucket ASC
	`
	rows, err := s.db.Query(sqlText, args...)
	if err != nil {
		return models.TimeSeriesResponse{}, err
	}
	defer rows.Close()

	var buckets []models.TimeSeriesBucket
	for rows.Next() {
		var bucket models.TimeSeriesBucket
		if err := rows.Scan(&bucket.Timestamp, &bucket.Events, &bucket.Suspicious, &bucket.RuleHits); err != nil {
			return models.TimeSeriesResponse{}, err
		}
		buckets = append(buckets, bucket)
	}
	if err := rows.Err(); err != nil {
		return models.TimeSeriesResponse{}, err
	}
	limit := normalizeLimit(query.Limit, 120)
	if limit > 0 && len(buckets) > limit {
		buckets = buckets[len(buckets)-limit:]
	}
	return models.TimeSeriesResponse{Buckets: buckets}, nil
}

func (s *PostgresStore) QueryEventBreakdown(query models.TimeRangeQuery) (models.EventBreakdown, error) {
	whereSQL, args := buildTimeWhere("event_time", query.Since, query.Until)
	if query.AgentID != "" {
		args = append(args, query.AgentID)
		clause := fmt.Sprintf("agent_id = $%d", len(args))
		if whereSQL == "" {
			whereSQL = clause
		} else {
			whereSQL += " AND " + clause
		}
	}

	limit := normalizeLimit(query.Limit, 8)
	sourceIPs, err := s.queryEventBreakdownItems("payload->>'srcIp'", false, whereSQL, args, limit)
	if err != nil {
		return models.EventBreakdown{}, err
	}
	destinationIPs, err := s.queryEventBreakdownItems("payload->>'dstIp'", false, whereSQL, args, limit)
	if err != nil {
		return models.EventBreakdown{}, err
	}
	snis, err := s.queryEventBreakdownItems("COALESCE(NULLIF(payload->'props'->'tls'->'req'->>'sni', ''), NULLIF(payload->'props'->'quic'->'req'->>'sni', ''))", false, whereSQL, args, limit)
	if err != nil {
		return models.EventBreakdown{}, err
	}
	protocols, err := s.queryEventBreakdownItems("proto", true, whereSQL, args, limit)
	if err != nil {
		return models.EventBreakdown{}, err
	}

	return models.EventBreakdown{
		SourceIPs:      sourceIPs,
		DestinationIPs: destinationIPs,
		SNIs:           snis,
		Protocols:      protocols,
	}, nil
}

func (s *PostgresStore) SaveSequence(name string, value uint64) error {
	_, err := s.db.Exec(`
		INSERT INTO master_sequences (name, value)
		VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value
	`, name, value)
	return err
}

func (s *PostgresStore) UpsertNode(node models.AgentNode) error {
	payload, err := json.Marshal(node)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO master_nodes (id, payload)
		VALUES ($1, $2)
		ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload
	`, node.ID, payload)
	return err
}

func (s *PostgresStore) DeleteNode(id string) error {
	_, err := s.db.Exec(`DELETE FROM master_nodes WHERE id = $1`, id)
	return err
}

func (s *PostgresStore) ListNodes() ([]models.AgentNode, error) {
	rows, err := s.db.Query(`SELECT payload FROM master_nodes ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodes []models.AgentNode
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var node models.AgentNode
		if err := json.Unmarshal(payload, &node); err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, rows.Err()
}

func (s *PostgresStore) SaveBootstrapToken(token, agentID string) error {
	_, err := s.db.Exec(`
		INSERT INTO master_bootstrap_tokens (token, agent_id)
		VALUES ($1, $2)
		ON CONFLICT (token) DO UPDATE SET agent_id = EXCLUDED.agent_id
	`, token, agentID)
	return err
}

func (s *PostgresStore) ConsumeBootstrapToken(token string) (string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var agentID string
	if err := tx.QueryRow(`SELECT agent_id FROM master_bootstrap_tokens WHERE token = $1`, token).Scan(&agentID); err != nil {
		if errorsIsNoRows(err) {
			return "", ErrNotFound
		}
		return "", err
	}
	if _, err := tx.Exec(`DELETE FROM master_bootstrap_tokens WHERE token = $1`, token); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return agentID, nil
}

func (s *PostgresStore) DeleteBootstrapToken(token string) error {
	_, err := s.db.Exec(`DELETE FROM master_bootstrap_tokens WHERE token = $1`, token)
	return err
}

func (s *PostgresStore) UpsertPolicyBundle(bundle models.Bundle) error {
	payload, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO master_policy_bundles (version, payload)
		VALUES ($1, $2)
		ON CONFLICT (version) DO UPDATE SET payload = EXCLUDED.payload
	`, bundle.Version, payload)
	return err
}

func (s *PostgresStore) ListPolicyBundles() ([]models.Bundle, error) {
	rows, err := s.db.Query(`SELECT payload FROM master_policy_bundles ORDER BY version ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var bundles []models.Bundle
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var bundle models.Bundle
		if err := json.Unmarshal(payload, &bundle); err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}
	return bundles, rows.Err()
}

func (s *PostgresStore) UpsertPolicyTask(task models.ControlTask) error {
	payload, err := json.Marshal(task)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO master_policy_tasks (agent_id, task_id, payload)
		VALUES ($1, $2, $3)
		ON CONFLICT (task_id) DO UPDATE SET
			agent_id = EXCLUDED.agent_id,
			payload = EXCLUDED.payload
	`, task.AgentID, task.ID, payload)
	return err
}

func (s *PostgresStore) ListPolicyTasks(agentID string) ([]models.ControlTask, error) {
	rows, err := s.db.Query(`SELECT payload FROM master_policy_tasks WHERE agent_id = $1 ORDER BY task_id ASC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tasks []models.ControlTask
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var task models.ControlTask
		if err := json.Unmarshal(payload, &task); err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	return tasks, rows.Err()
}

func (s *PostgresStore) UpsertReleaseArtifact(artifact models.ReleaseArtifact) error {
	payload, err := json.Marshal(artifact)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO master_release_artifacts (version, payload)
		VALUES ($1, $2)
		ON CONFLICT (version) DO UPDATE SET payload = EXCLUDED.payload
	`, artifact.Version, payload)
	return err
}

func (s *PostgresStore) ListReleaseArtifacts() ([]models.ReleaseArtifact, error) {
	rows, err := s.db.Query(`SELECT payload FROM master_release_artifacts ORDER BY version ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var artifacts []models.ReleaseArtifact
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var artifact models.ReleaseArtifact
		if err := json.Unmarshal(payload, &artifact); err != nil {
			return nil, err
		}
		artifacts = append(artifacts, artifact)
	}
	return artifacts, rows.Err()
}

func (s *PostgresStore) UpsertReleaseTask(task models.ControlTask) error {
	payload, err := json.Marshal(task)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO master_release_tasks (agent_id, task_id, payload)
		VALUES ($1, $2, $3)
		ON CONFLICT (task_id) DO UPDATE SET
			agent_id = EXCLUDED.agent_id,
			payload = EXCLUDED.payload
	`, task.AgentID, task.ID, payload)
	return err
}

func (s *PostgresStore) ListReleaseTasks(agentID string) ([]models.ControlTask, error) {
	rows, err := s.db.Query(`SELECT payload FROM master_release_tasks WHERE agent_id = $1 ORDER BY task_id ASC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tasks []models.ControlTask
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var task models.ControlTask
		if err := json.Unmarshal(payload, &task); err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	return tasks, rows.Err()
}

func (s *PostgresStore) loadSequence(name string) (uint64, error) {
	var value uint64
	err := s.db.QueryRow(`SELECT value FROM master_sequences WHERE name = $1`, name).Scan(&value)
	if errorsIsNoRows(err) {
		return 0, nil
	}
	return value, err
}

func (s *PostgresStore) loadAppliedMigrations(ctx context.Context) (map[int]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM master_schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	applied := make(map[int]bool)
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return applied, nil
}

func (s *PostgresStore) loadTasks(query string) (map[string]map[string]*models.ControlTask, error) {
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tasks := make(map[string]map[string]*models.ControlTask)
	for rows.Next() {
		var agentID, taskID string
		var payload []byte
		if err := rows.Scan(&agentID, &taskID, &payload); err != nil {
			return nil, err
		}
		var task models.ControlTask
		if err := json.Unmarshal(payload, &task); err != nil {
			return nil, err
		}
		if _, ok := tasks[agentID]; !ok {
			tasks[agentID] = make(map[string]*models.ControlTask)
		}
		taskCopy := task
		tasks[agentID][taskID] = &taskCopy
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tasks, nil
}

func (s *PostgresStore) loadEvents(limit int) ([]models.TrafficEvent, error) {
	rows, err := s.db.Query(`
		SELECT payload
		FROM master_traffic_events
		ORDER BY event_time DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []models.TrafficEvent
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var event models.TrafficEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	reverseEvents(events)
	return events, nil
}

func (s *PostgresStore) loadMetrics(limit int) ([]models.MetricSample, error) {
	rows, err := s.db.Query(`
		SELECT payload
		FROM master_metric_samples
		ORDER BY sample_time DESC, id DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []models.MetricSample
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var metric models.MetricSample
		if err := json.Unmarshal(payload, &metric); err != nil {
			return nil, err
		}
		metrics = append(metrics, metric)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	reverseMetrics(metrics)
	return metrics, nil
}

func saveSequenceTx(tx *sql.Tx, name string, value uint64) error {
	_, err := tx.Exec(`
		INSERT INTO master_sequences (name, value)
		VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value
	`, name, value)
	return err
}

func saveTasksTx(tx *sql.Tx, query string, tasks map[string]map[string]*models.ControlTask) error {
	for agentID, taskMap := range tasks {
		for taskID, task := range taskMap {
			payload, err := json.Marshal(task)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(query, agentID, taskID, payload); err != nil {
				return err
			}
		}
	}
	return nil
}

func reverseEvents(events []models.TrafficEvent) {
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
}

func reverseMetrics(metrics []models.MetricSample) {
	for i, j := 0, len(metrics)-1; i < j; i, j = i+1, j-1 {
		metrics[i], metrics[j] = metrics[j], metrics[i]
	}
}

func (s *PostgresStore) queryEventBreakdownItems(valueExpr string, includeUnknown bool, whereSQL string, args []any, limit int) ([]models.EventBreakdownItem, error) {
	groupExpr := fmt.Sprintf("NULLIF(%s, '')", valueExpr)
	if includeUnknown {
		groupExpr = fmt.Sprintf("COALESCE(NULLIF(%s, ''), 'unknown')", valueExpr)
	}

	sqlText := `
		SELECT
			value,
			COUNT(*) AS events,
			COUNT(*) FILTER (WHERE event_type = 'suspicious_flow' OR suspicion > 0) AS suspicious_events,
			MAX(event_time) AS last_seen_at
		FROM (
			SELECT
				event_time,
				event_type,
				suspicion,
				` + groupExpr + ` AS value
			FROM master_traffic_events
	`
	if whereSQL != "" {
		sqlText += " WHERE " + whereSQL
	}
	sqlText += `
		) grouped
		WHERE value IS NOT NULL
		GROUP BY value
		ORDER BY events DESC, value ASC
	`
	queryArgs := append([]any{}, args...)
	queryArgs = append(queryArgs, limit)
	sqlText += fmt.Sprintf(" LIMIT $%d", len(queryArgs))

	rows, err := s.db.Query(sqlText, queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]models.EventBreakdownItem, 0)
	for rows.Next() {
		var item models.EventBreakdownItem
		if err := rows.Scan(&item.Value, &item.Events, &item.SuspiciousEvents, &item.LastSeenAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func errorsIsNoRows(err error) bool {
	return err == sql.ErrNoRows
}

func buildEventWhere(query models.EventQuery) (string, []any) {
	var clauses []string
	var args []any
	add := func(clause string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}
	if query.AgentID != "" {
		add("agent_id = $%d", query.AgentID)
	}
	if query.Search != "" {
		pattern := "%" + strings.TrimSpace(query.Search) + "%"
		args = append(args, pattern)
		eventIndex := len(args)
		args = append(args, pattern)
		streamIndex := len(args)
		args = append(args, pattern)
		ruleIndex := len(args)
		args = append(args, pattern)
		payloadIndex := len(args)
		clauses = append(clauses, fmt.Sprintf("(event_id ILIKE $%d OR CAST((payload->>'streamId') AS TEXT) ILIKE $%d OR COALESCE(rule_name, '') ILIKE $%d OR CAST(payload AS TEXT) ILIKE $%d)", eventIndex, streamIndex, ruleIndex, payloadIndex))
	}
	if query.Type != "" {
		add("event_type = $%d", query.Type)
	}
	if query.Proto != "" {
		add("proto = $%d", query.Proto)
	}
	if query.RuleName != "" {
		add("rule_name = $%d", query.RuleName)
	}
	if query.Action != "" {
		add("payload->>'action' = $%d", query.Action)
	}
	if query.SrcIP != "" {
		add("payload->>'srcIp' = $%d", query.SrcIP)
	}
	if query.DstIP != "" {
		add("payload->>'dstIp' = $%d", query.DstIP)
	}
	if query.Port > 0 {
		args = append(args, query.Port)
		srcIndex := len(args)
		args = append(args, query.Port)
		dstIndex := len(args)
		clauses = append(clauses, fmt.Sprintf("((payload->>'srcPort')::int = $%d OR (payload->>'dstPort')::int = $%d)", srcIndex, dstIndex))
	}
	if query.MinSuspicion > 0 {
		add("suspicion >= $%d", query.MinSuspicion)
	}
	timeClause, timeArgs := buildTimeWhere("event_time", query.Since, query.Until)
	if timeClause != "" {
		for _, arg := range timeArgs {
			args = append(args, arg)
		}
		renumbered := renumberPlaceholders(timeClause, len(args)-len(timeArgs))
		clauses = append(clauses, renumbered)
	}
	return strings.Join(clauses, " AND "), args
}

func buildMetricWhere(query models.MetricQuery) (string, []any) {
	var clauses []string
	var args []any
	add := func(clause string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}
	if query.AgentID != "" {
		add("agent_id = $%d", query.AgentID)
	}
	if query.Name != "" {
		add("metric_name = $%d", query.Name)
	}
	timeClause, timeArgs := buildTimeWhere("sample_time", query.Since, query.Until)
	if timeClause != "" {
		for _, arg := range timeArgs {
			args = append(args, arg)
		}
		renumbered := renumberPlaceholders(timeClause, len(args)-len(timeArgs))
		clauses = append(clauses, renumbered)
	}
	return strings.Join(clauses, " AND "), args
}

func buildTimeWhere(column string, since, until time.Time) (string, []any) {
	var clauses []string
	var args []any
	if !since.IsZero() {
		args = append(args, since)
		clauses = append(clauses, fmt.Sprintf("%s >= $%d", column, len(args)))
	}
	if !until.IsZero() {
		args = append(args, until)
		clauses = append(clauses, fmt.Sprintf("%s <= $%d", column, len(args)))
	}
	return strings.Join(clauses, " AND "), args
}

func renumberPlaceholders(clause string, offset int) string {
	for i := 9; i >= 1; i-- {
		clause = strings.ReplaceAll(clause, fmt.Sprintf("$%d", i), fmt.Sprintf("$%d", i+offset))
	}
	return clause
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
