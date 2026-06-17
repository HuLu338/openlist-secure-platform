package openlist

import (
	"encoding/json"
	"fmt"
	"os"
)

type OpenListConfigReader struct{}

func NewOpenListConfigReader() *OpenListConfigReader {
	return &OpenListConfigReader{}
}

func (r *OpenListConfigReader) Read(configPath string) (map[string]any, error) {
	if configPath == "" {
		return nil, fmt.Errorf("config path is required")
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config map[string]any
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, err
	}

	// TODO: refine this reader if a stricter OpenList config schema is needed later.
	return config, nil
}
