package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/apernet/OpenGFW/master/agentbuild"
	"github.com/apernet/OpenGFW/master/api"
	"github.com/apernet/OpenGFW/master/auth"
	"github.com/apernet/OpenGFW/master/bootstrap"
	"github.com/apernet/OpenGFW/master/ingest"
	"github.com/apernet/OpenGFW/master/node"
	"github.com/apernet/OpenGFW/master/policy"
	"github.com/apernet/OpenGFW/master/release"
	reportsvc "github.com/apernet/OpenGFW/master/report"
	masterstate "github.com/apernet/OpenGFW/master/state"

	"go.uber.org/zap"
)

func main() {
	listen := flag.String("listen", ":8080", "master listen address")
	databaseURL := flag.String("database-url", envOrDefault("OPENGFW_DATABASE_URL", envOrDefault("DATABASE_URL", "")), "PostgreSQL database URL")
	projectRoot := flag.String("project-root", envOrDefault("OPENGFW_PROJECT_ROOT", ""), "OpenGFW project root used for managed agent builds")
	eventRetention := flag.Duration("event-retention", 0, "traffic event retention duration, 0 disables pruning")
	metricRetention := flag.Duration("metric-retention", 0, "metric retention duration, 0 disables pruning")
	retentionInterval := flag.Duration("retention-interval", time.Hour, "database retention sweep interval")
	flag.Parse()

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	if *databaseURL == "" {
		logger.Fatal("database-url is required")
	}

	store, err := masterstate.NewPostgresStore(context.Background(), *databaseURL)
	if err != nil {
		logger.Fatal("failed to initialize master state store", zap.Error(err))
	}
	defer store.Close()

	nodeSnapshot, err := store.LoadNodes()
	if err != nil && !errors.Is(err, masterstate.ErrNotFound) {
		logger.Fatal("failed to load node state", zap.Error(err))
	}
	policySnapshot, err := store.LoadPolicies()
	if err != nil && !errors.Is(err, masterstate.ErrNotFound) {
		logger.Fatal("failed to load policy state", zap.Error(err))
	}
	releaseSnapshot, err := store.LoadReleases()
	if err != nil && !errors.Is(err, masterstate.ErrNotFound) {
		logger.Fatal("failed to load release state", zap.Error(err))
	}
	ingestSnapshot, err := store.LoadIngest(10000, 10000)
	if err != nil && !errors.Is(err, masterstate.ErrNotFound) {
		logger.Fatal("failed to load ingest state", zap.Error(err))
	}

	nodeSvc := node.NewServiceWithSnapshotAndStore(nodeSnapshot, nil, store)
	policySvc := policy.NewServiceWithSnapshotAndStore(policySnapshot, nil, store)
	releaseSvc := release.NewServiceWithSnapshotAndStore(releaseSnapshot, nil, store)
	ingestSvc := ingest.NewServiceWithSnapshotAndAppenders(10000, 10000, ingestSnapshot, nil, store.AppendEvents, store.AppendMetrics)
	reportSvc := reportsvc.NewServiceWithQueries(nodeSvc, ingestSvc, store)
	agentBuilder, err := agentbuild.NewService(agentbuild.Config{ProjectRoot: *projectRoot})
	if err != nil {
		logger.Warn("managed agent binary builder disabled", zap.Error(err))
	}
	bootstrapInstaller := bootstrap.NewSSHInstaller(agentBuilder)
	authSvc := auth.NewService(store)
	server := api.NewServer(logger, nodeSvc, policySvc, releaseSvc, ingestSvc, reportSvc, bootstrapInstaller, authSvc)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if (*eventRetention > 0 || *metricRetention > 0) && *retentionInterval > 0 {
		go func() {
			ticker := time.NewTicker(*retentionInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					result, err := store.PruneOldData(ctx, *eventRetention, *metricRetention)
					if err != nil {
						logger.Warn("database retention sweep failed", zap.Error(err))
						continue
					}
					if result.DeletedEvents == 0 && result.DeletedMetrics == 0 {
						continue
					}
					logger.Info("database retention sweep completed",
						zap.Int64("deletedEvents", result.DeletedEvents),
						zap.Int64("deletedMetrics", result.DeletedMetrics))
				}
			}
		}()
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("master server starting", zap.String("listen", *listen))
		errCh <- server.ListenAndServe(*listen)
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("master server exited", zap.Error(err))
		}
		return
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("master shutdown failed", zap.Error(err))
	}
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
