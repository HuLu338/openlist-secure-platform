package contracts

import "openlist-secure-platform/internal/core/model"

type LogCollector interface {
	ParseLogFile(logPath string) ([]model.SecurityEvent, error)
}
