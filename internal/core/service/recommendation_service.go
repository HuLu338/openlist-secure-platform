package service

import (
	"errors"

	"openlist-secure-platform/internal/core/contracts"
)

type RecommendationService struct {
	Store contracts.RecommendationStore
}

func NewRecommendationService(store contracts.RecommendationStore) *RecommendationService {
	return &RecommendationService{Store: store}
}

func (s *RecommendationService) UpdateStatus(id int64, status string) error {
	if s.Store == nil {
		return errors.New("recommendation store is not configured")
	}

	if id <= 0 {
		return errors.New("invalid recommendation id")
	}

	if status != "accepted" && status != "dismissed" && status != "open" {
		return errors.New("invalid recommendation status")
	}

	// TODO: add richer risk acceptance workflow for recommendations.
	return s.Store.UpdateRecommendationStatus(id, status)
}
