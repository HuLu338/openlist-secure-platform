package openlist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenListLogParserEventTypes(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "openlist.log")
	logContent := strings.Join([]string{
		"2026-04-24T01:20:00+08:00 login success user=admin ip=10.0.0.1",
		"2026-04-24T01:21:00+08:00 login failed user=bob ip=10.0.0.2",
		"2026-04-24T01:22:00+08:00 file accessed path=/docs/report.pdf user=alice ip=10.0.0.3",
		"2026-04-24T01:23:00+08:00 file deleted path=/docs/old.txt user=admin ip=127.0.0.1",
		"2026-04-24T01:24:00+08:00 admin changed target=settings user=admin ip=10.0.0.4",
		"2026-04-24T01:25:00+08:00 background task completed",
	}, "\n")

	if err := os.WriteFile(logPath, []byte(logContent), 0o600); err != nil {
		t.Fatalf("failed to write temp log: %v", err)
	}

	parser := NewOpenListLogParser()
	events, err := parser.ParseLogFile(logPath)
	if err != nil {
		t.Fatalf("ParseLogFile() returned error: %v", err)
	}

	wantTypes := []string{
		"login_success",
		"login_failed",
		"file_access",
		"file_delete",
		"admin_action",
		"unknown",
	}
	wantSeverities := []string{
		"low",
		"medium",
		"low",
		"medium",
		"high",
		"low",
	}

	if len(events) != len(wantTypes) {
		t.Fatalf("len(events) = %d, want %d", len(events), len(wantTypes))
	}

	for i, event := range events {
		if event.EventType != wantTypes[i] {
			t.Fatalf("events[%d].EventType = %q, want %q", i, event.EventType, wantTypes[i])
		}
		if event.Severity != wantSeverities[i] {
			t.Fatalf("events[%d].Severity = %q, want %q", i, event.Severity, wantSeverities[i])
		}
		if event.Platform != "openlist" {
			t.Fatalf("events[%d].Platform = %q, want openlist", i, event.Platform)
		}
		if event.RawMessage == "" {
			t.Fatalf("events[%d].RawMessage is empty", i)
		}
	}
}
