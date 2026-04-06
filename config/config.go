package config

import (
	"encoding/json"
	"os"
)

type Endpoint struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

type Config struct {
	BaseURL     string            `json:"base_url"`
	AuthToken   string            `json:"auth_token,omitempty"`
	Endpoints   []Endpoint        `json:"endpoints"`
	Timeout     int               `json:"timeout_seconds"`
	Concurrency int               `json:"concurrency"`
	Headers     map[string]string `json:"global_headers,omitempty"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 10
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 5
	}

	return &cfg, nil
}
