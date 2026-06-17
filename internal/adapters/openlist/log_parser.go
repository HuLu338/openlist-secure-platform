package openlist

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"openlist-secure-platform/internal/core/model"
)

var (
	ipPattern     = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	quotedPattern = regexp.MustCompile(`"([^"]+)"`)
)

type OpenListLogParser struct{}

func NewOpenListLogParser() *OpenListLogParser {
	return &OpenListLogParser{}
}

func (p *OpenListLogParser) ParseLogFile(logPath string) ([]model.SecurityEvent, error) {
	if logPath == "" {
		return nil, fmt.Errorf("log path is required")
	}

	file, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	events := make([]model.SecurityEvent, 0)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		events = append(events, p.parseLine(line))
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return events, nil
}

func (p *OpenListLogParser) parseLine(line string) model.SecurityEvent {
	eventType := detectEventType(line)
	return model.SecurityEvent{
		Platform:   "openlist",
		EventTime:  parseEventTime(line),
		EventType:  eventType,
		Severity:   eventSeverity(eventType),
		Actor:      extractActor(line),
		Target:     extractTarget(line),
		SourceIP:   extractSourceIP(line),
		RawMessage: line,
	}
}

func detectEventType(line string) string {
	lowerLine := strings.ToLower(line)

	switch {
	case strings.Contains(lowerLine, "login success"):
		return "login_success"
	case strings.Contains(lowerLine, "login failed"):
		return "login_failed"
	case strings.Contains(lowerLine, "file accessed") || strings.Contains(lowerLine, "file access"):
		return "file_access"
	case strings.Contains(lowerLine, "file deleted") || strings.Contains(lowerLine, "file delete"):
		return "file_delete"
	case strings.Contains(lowerLine, "admin changed") || strings.Contains(lowerLine, "admin action") || strings.Contains(lowerLine, "changed setting"):
		return "admin_action"
	default:
		return "unknown"
	}
}

func eventSeverity(eventType string) string {
	switch eventType {
	case "login_failed", "file_delete":
		return "medium"
	case "admin_action":
		return "high"
	default:
		return "low"
	}
}

func parseEventTime(line string) time.Time {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return time.Now()
	}

	candidates := []string{
		strings.Trim(fields[0], "[]"),
	}

	if len(fields) > 1 {
		candidates = append(candidates, strings.Trim(fields[0]+" "+fields[1], "[]"))
	}

	layouts := []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	}

	for _, candidate := range candidates {
		for _, layout := range layouts {
			if parsed, err := time.Parse(layout, candidate); err == nil {
				return parsed
			}
		}
	}

	// TODO: support exact OpenList log timestamp formats when sample logs are finalized.
	return time.Now()
}

func extractActor(line string) string {
	lowerLine := strings.ToLower(line)

	keys := []string{"actor=", "user=", "username=", "admin="}
	for _, key := range keys {
		if value, ok := extractValueAfterKey(line, lowerLine, key); ok {
			return value
		}
	}

	return ""
}

func extractTarget(line string) string {
	lowerLine := strings.ToLower(line)

	keys := []string{"target=", "path=", "file=", "resource="}
	for _, key := range keys {
		if value, ok := extractValueAfterKey(line, lowerLine, key); ok {
			return value
		}
	}

	if matches := quotedPattern.FindAllStringSubmatch(line, -1); len(matches) > 0 {
		return matches[len(matches)-1][1]
	}

	return ""
}

func extractSourceIP(line string) string {
	matches := ipPattern.FindAllString(line, -1)
	for _, match := range matches {
		if net.ParseIP(match) != nil {
			return match
		}
	}

	return ""
}

func extractValueAfterKey(line string, lowerLine string, key string) (string, bool) {
	index := strings.Index(lowerLine, key)
	if index == -1 {
		return "", false
	}

	start := index + len(key)
	if start >= len(line) {
		return "", false
	}

	value := line[start:]
	for end, char := range value {
		if char == ' ' || char == ',' {
			value = value[:end]
			break
		}
	}

	value = strings.Trim(value, `"'[]`)
	if value == "" {
		return "", false
	}

	return value, true
}
