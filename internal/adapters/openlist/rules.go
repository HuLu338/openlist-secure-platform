package openlist

import (
	"time"

	"openlist-secure-platform/internal/core/model"
)

type OpenListRuleProvider struct{}

func NewOpenListRuleProvider() *OpenListRuleProvider {
	return &OpenListRuleProvider{}
}

func (p *OpenListRuleProvider) Rules() []model.ScanRule {
	securityRules := DefaultSecurityRules()
	scanRules := make([]model.ScanRule, 0, len(securityRules))
	for _, rule := range securityRules {
		scanRules = append(scanRules, model.ScanRule{
			ID:             rule.RuleID,
			Title:          rule.Title,
			Severity:       rule.Severity,
			Description:    rule.Description,
			Recommendation: rule.Recommendation,
		})
	}

	return scanRules
}

func DefaultSecurityRules() []model.SecurityRule {
	now := time.Now()
	return []model.SecurityRule{
		{
			RuleID:         "openlist-tls-skip-verify",
			Platform:       "openlist",
			Title:          "TLS Certificate Verification Skipped",
			Severity:       "high",
			Enabled:        true,
			Description:    "The configuration appears to allow skipping TLS certificate verification.",
			Recommendation: "Disable insecure skip verify so upstream TLS certificates are validated.",
			UpdatedAt:      now,
		},
		{
			RuleID:         "openlist-jwt-secret-weak",
			Platform:       "openlist",
			Title:          "JWT Secret Too Weak",
			Severity:       "critical",
			Enabled:        true,
			Description:    "The JWT secret is missing or too short for safe production use.",
			Recommendation: "Set a long random JWT secret with at least 16 characters.",
			UpdatedAt:      now,
		},
		{
			RuleID:         "openlist-token-validity-too-long",
			Platform:       "openlist",
			Title:          "Token Validity Too Long",
			Severity:       "medium",
			Enabled:        true,
			Description:    "Authentication tokens stay valid for too long, increasing exposure if leaked.",
			Recommendation: "Reduce token validity to 24 hours or less for this first version.",
			UpdatedAt:      now,
		},
		{
			RuleID:         "openlist-https-disabled",
			Platform:       "openlist",
			Title:          "HTTPS Not Enabled",
			Severity:       "high",
			Enabled:        true,
			Description:    "The configuration appears to expose the service without HTTPS enabled.",
			Recommendation: "Enable HTTPS or place OpenList behind a trusted TLS reverse proxy.",
			UpdatedAt:      now,
		},
		{
			RuleID:         "openlist-logging-disabled",
			Platform:       "openlist",
			Title:          "Logging Disabled",
			Severity:       "low",
			Enabled:        true,
			Description:    "Logging appears to be disabled, which reduces visibility during incidents.",
			Recommendation: "Enable basic application logging for operational and security visibility.",
			UpdatedAt:      now,
		},
		{
			RuleID:         "openlist-ftp-enabled",
			Platform:       "openlist",
			Title:          "FTP Enabled",
			Severity:       "medium",
			Enabled:        true,
			Description:    "FTP support appears to be enabled, which can increase attack surface.",
			Recommendation: "Disable FTP unless your deployment explicitly requires it.",
			UpdatedAt:      now,
		},
		{
			RuleID:         "openlist-sftp-enabled",
			Platform:       "openlist",
			Title:          "SFTP Enabled",
			Severity:       "low",
			Enabled:        true,
			Description:    "SFTP support appears to be enabled, which should be reviewed if unused.",
			Recommendation: "Disable SFTP if it is not needed, or keep it hardened and monitored.",
			UpdatedAt:      now,
		},
	}
}
