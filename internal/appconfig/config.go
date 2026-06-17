package appconfig

import "os"

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
		AdminAPIKey:        "change-me-dev-key",
		AssistantMode:      assistantMode,
		OpenAIAPIKey:       os.Getenv("OPENAI_API_KEY"),
		OpenAIModel:        openAIModel,
	}
}

func envOrDefault(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}
