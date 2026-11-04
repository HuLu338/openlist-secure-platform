package appconfig

import "os"

const DevelopmentAdminAPIKey = "change-me-dev-key"

type AppConfig struct {
	HTTPAddress        string
	OpenListConfigPath string
	SQLiteDSN          string
	AdminAPIKey        string
	AssistantMode      string
	OpenAIAPIKey       string
	OpenAIModel        string
}

func Default() AppConfig {
	assistantMode := envOrDefault("ASSISTANT_MODE", "local")
	openAIModel := envOrDefault("OPENAI_MODEL", "gpt-4.1-mini")

	return AppConfig{
		HTTPAddress:        ":8080",
		OpenListConfigPath: "",
		SQLiteDSN:          "./data/scan_history.db",
		// This fallback is for local development/testing only and should be changed in production.
		AdminAPIKey:   envOrDefault("OPENLIST_SECURITY_API_KEY", DevelopmentAdminAPIKey),
		AssistantMode: assistantMode,
		OpenAIAPIKey:  os.Getenv("OPENAI_API_KEY"),
		OpenAIModel:   openAIModel,
	}
}

func envOrDefault(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}
