package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openlist-secure-platform/internal/core/model"
)

type fakeRuleStore struct{}

func (s fakeRuleStore) UpdateSecurityRule(ruleID string, enabled *bool, severity string) error {
	return nil
}

type fakeRuleReader struct{}

func (r fakeRuleReader) ListSecurityRules() ([]model.SecurityRule, error) {
	return []model.SecurityRule{}, nil
}

func (r fakeRuleReader) GetSecurityRule(ruleID string) (*model.SecurityRule, error) {
	return &model.SecurityRule{RuleID: ruleID, Severity: "low", Enabled: true}, nil
}

func TestRuleByIDHandlerRejectsInvalidSeverity(t *testing.T) {
	router := &Router{
		ruleReader: fakeRuleReader{},
		ruleStore:  fakeRuleStore{},
	}

	request := httptest.NewRequest(
		http.MethodPatch,
		"/rules/openlist-jwt-secret-weak",
		strings.NewReader(`{"severity":"very-high"}`),
	)
	response := httptest.NewRecorder()

	router.ruleByIDHandler(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}

	if !strings.Contains(response.Body.String(), `"code":"bad_request"`) {
		t.Fatalf("response body does not contain bad_request error: %s", response.Body.String())
	}
}
