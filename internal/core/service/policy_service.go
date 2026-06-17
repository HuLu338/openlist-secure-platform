package service

import (
	"errors"
	"time"

	"openlist-secure-platform/internal/core/contracts"
	"openlist-secure-platform/internal/core/model"
)

type PolicyService struct {
	Reader contracts.PolicyReader
	Store  contracts.PolicyStore
}

func NewPolicyService(reader contracts.PolicyReader, store contracts.PolicyStore) *PolicyService {
	return &PolicyService{
		Reader: reader,
		Store:  store,
	}
}

func (s *PolicyService) GetPolicy() (*model.SecurityPolicy, error) {
	if s.Reader == nil {
		return nil, errors.New("policy reader is not configured")
	}

	return s.Reader.GetPolicy()
}

func (s *PolicyService) UpdatePolicy(lowScore, loginFailures, longToken *int) (*model.SecurityPolicy, error) {
	if s.Reader == nil || s.Store == nil {
		return nil, errors.New("policy store is not configured")
	}

	policy, err := s.Reader.GetPolicy()
	if err != nil {
		return nil, err
	}
	if policy == nil {
		defaultPolicy := model.DefaultSecurityPolicy()
		policy = &defaultPolicy
	}

	if lowScore != nil {
		if *lowScore <= 0 {
			return nil, errors.New("invalid low_score_threshold")
		}
		policy.LowScoreThreshold = *lowScore
	}

	if loginFailures != nil {
		if *loginFailures <= 0 {
			return nil, errors.New("invalid multiple_login_failures_threshold")
		}
		policy.MultipleLoginFailuresThreshold = *loginFailures
	}

	if longToken != nil {
		if *longToken <= 0 {
			return nil, errors.New("invalid long_token_hours_threshold")
		}
		policy.LongTokenHoursThreshold = *longToken
	}

	policy.UpdatedAt = time.Now()
	if err := s.Store.UpdatePolicy(policy); err != nil {
		return nil, err
	}

	// TODO: support multiple named policies and per-platform policies.
	// TODO: support rule enable/disable flags and user-defined custom rules.
	return policy, nil
}
