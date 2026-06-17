package service

import (
	"strings"
	"testing"

	"openlist-secure-platform/internal/core/model"
)

type assistantRecommendationReader struct {
	latest []model.Recommendation
}

func (r assistantRecommendationReader) ListRecommendationsFiltered(status, priority string, scanReportID *int64) ([]model.Recommendation, error) {
	return r.latest, nil
}

func (r assistantRecommendationReader) GetLatestRecommendations() ([]model.Recommendation, error) {
	return r.latest, nil
}

func (r assistantRecommendationReader) GetRecommendationsByScanID(scanID int64) ([]model.Recommendation, error) {
	return r.latest, nil
}

func (r assistantRecommendationReader) GetRecommendationByID(id int64) (*model.Recommendation, error) {
	return nil, nil
}

func TestDetectAssistantIntent(t *testing.T) {
	tests := []struct {
		question string
		want     string
	}{
		{question: "What is the current security status?", want: IntentSystemStatus},
		{question: "Why is the latest scan score low?", want: IntentLowScoreReason},
		{question: "What should I fix first?", want: IntentFixPriority},
		{question: "Explain the latest alert", want: IntentLatestAlertExplanation},
		{question: "Any suspicious 401 audit activity?", want: IntentSuspiciousAPIActivity},
		{question: "How does the policy threshold affect rules?", want: IntentRulePolicyExplanation},
		{question: "hello", want: IntentGeneralHelp},
	}

	for _, test := range tests {
		t.Run(test.question, func(t *testing.T) {
			got := DetectAssistantIntent(test.question)
			if got != test.want {
				t.Fatalf("DetectAssistantIntent() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestAssistantGeneralHelpFallback(t *testing.T) {
	assistant := NewAssistantService(nil, nil, nil, nil, nil, nil, nil, nil)

	response, err := assistant.Ask("can you help me")
	if err != nil {
		t.Fatalf("Ask() returned error: %v", err)
	}

	if response.Intent != IntentGeneralHelp {
		t.Fatalf("response.Intent = %q, want %q", response.Intent, IntentGeneralHelp)
	}
	if response.Confidence != "low" {
		t.Fatalf("response.Confidence = %q, want low", response.Confidence)
	}
}

func TestAssistantRejectsEmptyQuestion(t *testing.T) {
	assistant := NewAssistantService(nil, nil, nil, nil, nil, nil, nil, nil)

	_, err := assistant.Ask("   ")
	if err == nil {
		t.Fatalf("Ask() expected error for empty question")
	}
}

func TestAssistantFixPriorityUsesRecommendations(t *testing.T) {
	assistant := NewAssistantService(
		nil,
		nil,
		nil,
		assistantRecommendationReader{latest: []model.Recommendation{
			{
				Title:          "Enable Logging",
				Priority:       "medium",
				Recommendation: "Turn logging back on.",
			},
			{
				Title:          "JWT Secret Too Weak",
				Priority:       "high",
				Recommendation: "Use a longer random JWT secret.",
			},
		}},
		nil,
		nil,
		nil,
		nil,
	)

	response, err := assistant.Ask("What should I fix first?")
	if err != nil {
		t.Fatalf("Ask() returned error: %v", err)
	}

	if response.Intent != IntentFixPriority {
		t.Fatalf("response.Intent = %q, want %q", response.Intent, IntentFixPriority)
	}
	if response.Confidence != "high" {
		t.Fatalf("response.Confidence = %q, want high", response.Confidence)
	}

	jwtIndex := strings.Index(response.Answer, "JWT Secret Too Weak")
	loggingIndex := strings.Index(response.Answer, "Enable Logging")
	if jwtIndex == -1 || loggingIndex == -1 {
		t.Fatalf("response answer does not include expected recommendations: %s", response.Answer)
	}
	if jwtIndex > loggingIndex {
		t.Fatalf("high priority recommendation should appear before medium priority recommendation: %s", response.Answer)
	}
}
