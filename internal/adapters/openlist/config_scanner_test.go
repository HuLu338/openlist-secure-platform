package openlist

import (
	"os"
	"path/filepath"
	"testing"

	"openlist-secure-platform/internal/core/model"
	"openlist-secure-platform/internal/core/scoring"
)

type testPolicyReader struct {
	policy model.SecurityPolicy
}

func (r testPolicyReader) GetPolicy() (*model.SecurityPolicy, error) {
	return &r.policy, nil
}

type testRuleReader struct {
	rules []model.SecurityRule
}

func (r testRuleReader) ListSecurityRules() ([]model.SecurityRule, error) {
	return r.rules, nil
}

func (r testRuleReader) GetSecurityRule(ruleID string) (*model.SecurityRule, error) {
	for _, rule := range r.rules {
		if rule.RuleID == ruleID {
			return &rule, nil
		}
	}
	return nil, nil
}

func TestOpenListConfigScannerRiskyConfig(t *testing.T) {
	configPath := writeTempConfig(t, `{
		"scheme": {
			"https": false,
			"skip_tls_verify": true
		},
		"security": {
			"jwt_secret": "123456",
			"token_expire_hours": 720
		},
		"log": {
			"enable": false
		},
		"services": {
			"ftp_enable": true,
			"sftp_enable": true
		}
	}`)

	scanner := NewOpenListConfigScanner(
		NewOpenListConfigReader(),
		NewOpenListRuleProvider(),
		testPolicyReader{policy: model.DefaultSecurityPolicy()},
	)

	report, err := scanner.ScanConfig(configPath)
	if err != nil {
		t.Fatalf("ScanConfig() returned error: %v", err)
	}

	wantRuleIDs := []string{
		"openlist-tls-skip-verify",
		"openlist-jwt-secret-weak",
		"openlist-token-validity-too-long",
		"openlist-https-disabled",
		"openlist-logging-disabled",
		"openlist-ftp-enabled",
		"openlist-sftp-enabled",
	}

	if len(report.Risks) != len(wantRuleIDs) {
		t.Fatalf("len(report.Risks) = %d, want %d", len(report.Risks), len(wantRuleIDs))
	}

	gotRuleIDs := make(map[string]bool)
	for _, risk := range report.Risks {
		gotRuleIDs[risk.RuleID] = true
	}

	for _, ruleID := range wantRuleIDs {
		if !gotRuleIDs[ruleID] {
			t.Fatalf("expected risk %q was not triggered", ruleID)
		}
	}
}

func TestOpenListConfigScannerDisabledRuleDoesNotTrigger(t *testing.T) {
	configPath := writeTempConfig(t, `{
		"scheme": {
			"https": true,
			"skip_tls_verify": false
		},
		"security": {
			"jwt_secret": "123456",
			"token_expire_hours": 24
		},
		"log": {
			"enable": true
		},
		"services": {
			"ftp_enable": false,
			"sftp_enable": false
		}
	}`)

	rules := DefaultSecurityRules()
	for i := range rules {
		if rules[i].RuleID == "openlist-jwt-secret-weak" {
			rules[i].Enabled = false
		}
	}

	scanner := NewOpenListConfigScanner(
		NewOpenListConfigReader(),
		NewOpenListRuleProvider(),
		testPolicyReader{policy: model.DefaultSecurityPolicy()},
		testRuleReader{rules: rules},
	)

	report, err := scanner.ScanConfig(configPath)
	if err != nil {
		t.Fatalf("ScanConfig() returned error: %v", err)
	}

	if hasRisk(report.Risks, "openlist-jwt-secret-weak") {
		t.Fatalf("disabled JWT rule should not trigger")
	}
}

func TestOpenListConfigScannerChangedSeverityAffectsScore(t *testing.T) {
	configPath := writeTempConfig(t, `{
		"scheme": {
			"https": true,
			"skip_tls_verify": false
		},
		"security": {
			"jwt_secret": "this-is-a-long-secret",
			"token_expire_hours": 24
		},
		"log": {
			"enable": false
		},
		"services": {
			"ftp_enable": false,
			"sftp_enable": false
		}
	}`)

	rules := DefaultSecurityRules()
	for i := range rules {
		if rules[i].RuleID == "openlist-logging-disabled" {
			rules[i].Severity = "high"
		}
	}

	scanner := NewOpenListConfigScanner(
		NewOpenListConfigReader(),
		NewOpenListRuleProvider(),
		testPolicyReader{policy: model.DefaultSecurityPolicy()},
		testRuleReader{rules: rules},
	)

	report, err := scanner.ScanConfig(configPath)
	if err != nil {
		t.Fatalf("ScanConfig() returned error: %v", err)
	}

	if len(report.Risks) != 1 {
		t.Fatalf("len(report.Risks) = %d, want 1", len(report.Risks))
	}
	if report.Risks[0].Severity != "high" {
		t.Fatalf("logging disabled severity = %q, want high", report.Risks[0].Severity)
	}

	score := scoring.CalculateTotalScore(report.Risks)
	if score != 80 {
		t.Fatalf("score = %d, want 80", score)
	}
}

func TestOpenListConfigScannerSafeConfig(t *testing.T) {
	configPath := writeTempConfig(t, `{
		"scheme": {
			"https": true,
			"skip_tls_verify": false
		},
		"security": {
			"jwt_secret": "this-is-a-long-secret",
			"token_expire_hours": 24
		},
		"log": {
			"enable": true
		},
		"services": {
			"ftp_enable": false,
			"sftp_enable": false
		}
	}`)

	scanner := NewOpenListConfigScanner(
		NewOpenListConfigReader(),
		NewOpenListRuleProvider(),
		testPolicyReader{policy: model.DefaultSecurityPolicy()},
	)

	report, err := scanner.ScanConfig(configPath)
	if err != nil {
		t.Fatalf("ScanConfig() returned error: %v", err)
	}

	if len(report.Risks) != 0 {
		t.Fatalf("len(report.Risks) = %d, want 0", len(report.Risks))
	}
}

func TestOpenListConfigScannerTokenThresholdPolicy(t *testing.T) {
	configPath := writeTempConfig(t, `{
		"scheme": {
			"https": true,
			"skip_tls_verify": false
		},
		"security": {
			"jwt_secret": "this-is-a-long-secret",
			"token_expire_hours": 100
		},
		"log": {
			"enable": true
		},
		"services": {
			"ftp_enable": false,
			"sftp_enable": false
		}
	}`)

	strictPolicy := model.DefaultSecurityPolicy()
	strictPolicy.LongTokenHoursThreshold = 72
	strictScanner := NewOpenListConfigScanner(
		NewOpenListConfigReader(),
		NewOpenListRuleProvider(),
		testPolicyReader{policy: strictPolicy},
	)

	strictReport, err := strictScanner.ScanConfig(configPath)
	if err != nil {
		t.Fatalf("strict ScanConfig() returned error: %v", err)
	}
	if !hasRisk(strictReport.Risks, "openlist-token-validity-too-long") {
		t.Fatalf("expected token validity risk when threshold is 72 hours")
	}

	lenientPolicy := model.DefaultSecurityPolicy()
	lenientPolicy.LongTokenHoursThreshold = 168
	lenientScanner := NewOpenListConfigScanner(
		NewOpenListConfigReader(),
		NewOpenListRuleProvider(),
		testPolicyReader{policy: lenientPolicy},
	)

	lenientReport, err := lenientScanner.ScanConfig(configPath)
	if err != nil {
		t.Fatalf("lenient ScanConfig() returned error: %v", err)
	}
	if hasRisk(lenientReport.Risks, "openlist-token-validity-too-long") {
		t.Fatalf("did not expect token validity risk when threshold is 168 hours")
	}
}

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "openlist-config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	return path
}

func hasRisk(risks []model.RiskItem, ruleID string) bool {
	for _, risk := range risks {
		if risk.RuleID == ruleID {
			return true
		}
	}

	return false
}
