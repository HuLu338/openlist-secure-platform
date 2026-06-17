package main

import (
	"log"
	"net/http"

	"openlist-secure-platform/internal/adapters/openlist"
	"openlist-secure-platform/internal/appconfig"
	"openlist-secure-platform/internal/core/service"
	"openlist-secure-platform/internal/httpapi"
	"openlist-secure-platform/internal/storage/sqlite"
)

func main() {
	cfg := appconfig.Default()

	scanStore, err := sqlite.NewDB(cfg.SQLiteDSN)
	if err != nil {
		log.Fatalf("failed to initialize sqlite database: %v", err)
	}
	defer func() {
		if closeErr := scanStore.Close(); closeErr != nil {
			log.Printf("failed to close sqlite database: %v", closeErr)
		}
	}()

	ruleProvider := openlist.NewOpenListRuleProvider()
	if err := scanStore.InitializeDefaultSecurityRules(openlist.DefaultSecurityRules()); err != nil {
		log.Fatalf("failed to initialize default security rules: %v", err)
	}

	configReader := openlist.NewOpenListConfigReader()
	configScanner := openlist.NewOpenListConfigScanner(configReader, ruleProvider, scanStore, scanStore)
	alertService := service.NewAlertService(scanStore)
	policyService := service.NewPolicyService(scanStore, scanStore)
	recommendationService := service.NewRecommendationService(scanStore)
	scanService := service.NewScanService(configScanner, scanStore, scanStore, scanStore, scanStore)
	logParser := openlist.NewOpenListLogParser()
	eventService := service.NewEventService(logParser, scanStore, scanStore, scanStore)
	assistantService := service.NewAssistantService(
		scanStore,
		scanStore,
		scanStore,
		scanStore,
		scanStore,
		scanStore,
		scanStore,
		scanStore,
		service.WithAssistantGatewayConfig(cfg.AssistantMode, cfg.OpenAIAPIKey, cfg.OpenAIModel),
	)

	server := &http.Server{
		Addr: cfg.HTTPAddress,
		Handler: httpapi.NewRouter(
			scanService,
			scanStore,
			eventService,
			scanStore,
			alertService,
			scanStore,
			scanStore,
			scanStore,
			policyService,
			scanStore,
			recommendationService,
			scanStore,
			scanStore,
			scanStore,
			assistantService,
			scanStore,
			scanStore,
			scanStore,
			cfg.AdminAPIKey,
		),
	}

	log.Printf("starting server on %s", cfg.HTTPAddress)
	log.Printf("sqlite database path: %s", cfg.SQLiteDSN)

	// TODO: add pagination for scan history queries.
	// TODO: add filtering by platform and date range queries.
	// TODO: add dashboard aggregation endpoints.
	// TODO: add log event history APIs in a later phase.
	// TODO: add alert notification delivery.
	// TODO: add real-time alert rule engine and threshold customization.
	// TODO: add dashboard charts and time-range metrics.
	// TODO: add recommendation deduplication and remediation categories.
	// TODO: add multiple named policies, per-platform policies, and custom rules.
	// TODO: add log analysis flow in a later phase.
	// TODO: support more platform adapters beyond OpenList in future work.
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server stopped with error: %v", err)
	}
}
