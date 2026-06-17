package contracts

import "openlist-secure-platform/internal/core/model"

type RuleProvider interface {
	Rules() []model.ScanRule
}
