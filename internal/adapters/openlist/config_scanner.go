package openlist

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"openlist-secure-platform/internal/core/contracts"
	"openlist-secure-platform/internal/core/model"
)

type OpenListConfigScanner struct {
	Reader       *OpenListConfigReader
	Provider     contracts.RuleProvider
	PolicyReader contracts.PolicyReader
	RuleReader   contracts.SecurityRuleReader
}

func NewOpenListConfigScanner(reader *OpenListConfigReader, provider contracts.RuleProvider, policyReader contracts.PolicyReader, ruleReaders ...contracts.SecurityRuleReader) *OpenListConfigScanner {
	var ruleReader contracts.SecurityRuleReader
	if len(ruleReaders) > 0 {
		ruleReader = ruleReaders[0]
	}

	return &OpenListConfigScanner{
		Reader:       reader,
		Provider:     provider,
		PolicyReader: policyReader,
		RuleReader:   ruleReader,
	}
}

func (s *OpenListConfigScanner) ScanConfig(configPath string) (*model.ScanReport, error) {
	if s.Reader == nil {
		return nil, fmt.Errorf("openlist config reader is not configured")
	}

	log.Printf("running OpenList config scan for path: %s", configPath)

	configData, err := s.Reader.Read(configPath)
	if err != nil {
		return nil, err
	}

	policy := s.loadPolicy()
	risks := make([]model.RiskItem, 0)
	for _, rule := range s.rules() {
		if !rule.Enabled {
			continue
		}

		if s.matchesRule(rule.RuleID, configData, policy) {
			risks = append(risks, model.RiskItem{
				RuleID:         rule.RuleID,
				Title:          rule.Title,
				Severity:       rule.Severity,
				Description:    rule.Description,
				Recommendation: rule.Recommendation,
			})
		}
	}

	report := &model.ScanReport{
		Platform:            "openlist",
		ScanTime:            time.Now(),
		TargetPath:          configPath,
		TriggeredRulesCount: len(risks),
		Risks:               risks,
	}

	log.Printf("OpenList config scan matched %d risks", len(risks))

	// TODO: refine key mappings against more real OpenList config samples.
	// TODO: keep this adapter isolated when multi-platform adapters are added later.
	return report, nil
}

func (s *OpenListConfigScanner) rules() []model.SecurityRule {
	if s.RuleReader != nil {
		rules, err := s.RuleReader.ListSecurityRules()
		if err == nil && len(rules) > 0 {
			return rules
		}
		// TODO: add structured logging when rule loading falls back to adapter defaults.
	}

	if s.Provider == nil {
		return []model.SecurityRule{}
	}

	providerRules := s.Provider.Rules()
	rules := make([]model.SecurityRule, 0, len(providerRules))
	for _, rule := range providerRules {
		rules = append(rules, model.SecurityRule{
			RuleID:         rule.ID,
			Platform:       "openlist",
			Title:          rule.Title,
			Severity:       rule.Severity,
			Enabled:        true,
			Description:    rule.Description,
			Recommendation: rule.Recommendation,
			UpdatedAt:      time.Now(),
		})
	}

	// TODO: support custom user-defined rules and per-platform rule sets.
	// TODO: add rule categories, rule versioning, and an advanced condition engine.
	return rules
}

func (s *OpenListConfigScanner) matchesRule(ruleID string, config map[string]any, policy model.SecurityPolicy) bool {
	switch ruleID {
	case "openlist-tls-skip-verify":
		return isTrue(config, "scheme.skip_tls_verify")
	case "openlist-jwt-secret-weak":
		secret, ok := getString(config, "security.jwt_secret")
		if !ok {
			return true
		}
		return len(strings.TrimSpace(secret)) < 16
	case "openlist-token-validity-too-long":
		hours, ok := getHours(config, "security.token_expire_hours")
		return ok && hours > float64(policy.LongTokenHoursThreshold)
	case "openlist-https-disabled":
		return isFalse(config, "scheme.https")
	case "openlist-logging-disabled":
		return isFalse(config, "log.enable")
	case "openlist-ftp-enabled":
		return isTrue(config, "services.ftp_enable")
	case "openlist-sftp-enabled":
		return isTrue(config, "services.sftp_enable")
	default:
		return false
	}
}

func (s *OpenListConfigScanner) loadPolicy() model.SecurityPolicy {
	defaultPolicy := model.DefaultSecurityPolicy()
	if s.PolicyReader == nil {
		// TODO: centralize policy fallback handling across scanners and services.
		return defaultPolicy
	}

	policy, err := s.PolicyReader.GetPolicy()
	if err != nil || policy == nil {
		// TODO: add structured logging when policy loading falls back to defaults.
		return defaultPolicy
	}

	return *policy
}

func isTrue(config map[string]any, paths ...string) bool {
	value, ok := getValueFromPaths(config, paths...)
	if !ok {
		return false
	}

	result, ok := toBool(value)
	return ok && result
}

func isFalse(config map[string]any, paths ...string) bool {
	value, ok := getValueFromPaths(config, paths...)
	if !ok {
		return false
	}

	result, ok := toBool(value)
	return ok && !result
}

func getString(config map[string]any, paths ...string) (string, bool) {
	value, ok := getValueFromPaths(config, paths...)
	if !ok {
		return "", false
	}

	return toString(value)
}

func getHours(config map[string]any, paths ...string) (float64, bool) {
	value, ok := getValueFromPaths(config, paths...)
	if !ok {
		return 0, false
	}

	return toHours(value)
}

func getValueFromPaths(config map[string]any, paths ...string) (any, bool) {
	for _, path := range paths {
		value, ok := getValueByPath(config, path)
		if ok {
			return value, true
		}
	}

	return nil, false
}

func getValueByPath(config map[string]any, path string) (any, bool) {
	parts := strings.Split(path, ".")
	var current any = config

	for _, part := range parts {
		currentMap, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}

		next, ok := findMapValue(currentMap, part)
		if !ok {
			return nil, false
		}

		current = next
	}

	return current, true
}

func findMapValue(data map[string]any, key string) (any, bool) {
	if value, ok := data[key]; ok {
		return value, true
	}

	normalizedTarget := normalizeKey(key)
	for currentKey, value := range data {
		if normalizeKey(currentKey) == normalizedTarget {
			return value, true
		}
	}

	return nil, false
}

func normalizeKey(value string) string {
	replacer := strings.NewReplacer("_", "", "-", "", " ", "")
	return strings.ToLower(replacer.Replace(value))
}

func toBool(value any) (bool, bool) {
	switch typedValue := value.(type) {
	case bool:
		return typedValue, true
	case string:
		switch strings.ToLower(strings.TrimSpace(typedValue)) {
		case "true", "1", "yes", "enabled", "on":
			return true, true
		case "false", "0", "no", "disabled", "off":
			return false, true
		default:
			return false, false
		}
	case float64:
		return typedValue != 0, true
	default:
		return false, false
	}
}

func toString(value any) (string, bool) {
	switch typedValue := value.(type) {
	case string:
		return typedValue, true
	default:
		return "", false
	}
}

func toHours(value any) (float64, bool) {
	switch typedValue := value.(type) {
	case float64:
		if typedValue > 1000 {
			return typedValue / 3600, true
		}
		return typedValue, true
	case string:
		trimmed := strings.TrimSpace(typedValue)
		if trimmed == "" {
			return 0, false
		}

		if duration, err := time.ParseDuration(trimmed); err == nil {
			return duration.Hours(), true
		}

		number, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return 0, false
		}

		if number > 1000 {
			return number / 3600, true
		}
		return number, true
	default:
		return 0, false
	}
}
