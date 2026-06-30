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
		"2026-04-24T01:25:00+08:00 webdav access path=/webdav/docs/report.pdf user=alice ip=10.0.0.5",
		"2026-04-24T01:26:00+08:00 webdav write path=/webdav/docs/upload.txt user=alice ip=10.0.0.5",
		"2026-04-24T01:27:00+08:00 webdav delete path=/webdav/docs/old.txt user=admin ip=127.0.0.1",
		"2026-04-24T01:28:00+08:00 webdav manage permission path=/webdav user=admin ip=127.0.0.1",
		"2026-04-24T01:29:00+08:00 token issued user=alice ip=10.0.0.6",
		"2026-04-24T01:30:00+08:00 token used user=alice ip=10.0.0.6",
		"2026-04-24T01:31:00+08:00 invalid token user=bob ip=10.0.0.7",
		"2026-04-24T01:32:00+08:00 token refreshed user=alice ip=10.0.0.6",
		"2026-04-24T01:33:00+08:00 background task completed",
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
		"webdav_access",
		"webdav_write",
		"webdav_delete",
		"webdav_manage",
		"token_issued",
		"token_used",
		"token_invalid",
		"token_refreshed",
		"unknown",
	}
	wantSeverities := []string{
		"low",
		"medium",
		"low",
		"medium",
		"high",
		"low",
		"medium",
		"high",
		"high",
		"low",
		"low",
		"medium",
		"low",
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
