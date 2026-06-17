package contracts

import "openlist-secure-platform/internal/core/model"

type ConfigScanner interface {
	ScanConfig(configPath string) (*model.ScanReport, error)
}
