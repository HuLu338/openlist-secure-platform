package service

import (
	"errors"

	"openlist-secure-platform/internal/core/contracts"
)

type AlertService struct {
	Store contracts.AlertStore
}

func NewAlertService(store contracts.AlertStore) *AlertService {
	return &AlertService{Store: store}
}

func (s *AlertService) CloseAlert(id int64) error {
	if s.Store == nil {
		return errors.New("alert store is not configured")
	}

	if id <= 0 {
		return errors.New("invalid alert id")
	}

	// TODO: add alert suppression and audit metadata for close actions.
	return s.Store.CloseAlert(id)
}
