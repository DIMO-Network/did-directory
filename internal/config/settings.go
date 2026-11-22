package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Settings holds all configuration for the did-directory service.
type Settings struct {
	Port                int    `yaml:"PORT"`
	MonitoringPort      int    `yaml:"MONITORING_PORT"`
	DatabaseURL         string `yaml:"DATABASE_URL"`
	LogLevel            string `yaml:"LOG_LEVEL"`
	MaxOperationsPerDID int    `yaml:"MAX_OPERATIONS_PER_DID"`
	ExportPageSize      int    `yaml:"EXPORT_PAGE_SIZE"`
}

// DefaultMaxOperationsPerDID is MAX_OPERATIONS_PER_DID when it is not set.
const DefaultMaxOperationsPerDID = 1000

// LoadConfig reads a YAML settings file and returns the parsed Settings.
// Environment variables override YAML values when set.
func LoadConfig(path string) (*Settings, error) {
	s := &Settings{
		Port:                8080,
		MonitoringPort:      8888,
		LogLevel:            "info",
		MaxOperationsPerDID: DefaultMaxOperationsPerDID,
		ExportPageSize:      100,
	}

	data, err := os.ReadFile(path)
	if err == nil {
		if err := yaml.Unmarshal(data, s); err != nil {
			return nil, err
		}
	}

	// Environment variable overrides.
	if v := os.Getenv("DATABASE_URL"); v != "" {
		s.DatabaseURL = v
	}
	if v := os.Getenv("PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			s.Port = p
		}
	}
	if v := os.Getenv("MONITORING_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			s.MonitoringPort = p
		}
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		s.LogLevel = v
	}
	if v := os.Getenv("MAX_OPERATIONS_PER_DID"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("MAX_OPERATIONS_PER_DID must be a positive integer, got %q", v)
		}
		s.MaxOperationsPerDID = n
	}
	if v := os.Getenv("EXPORT_PAGE_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("EXPORT_PAGE_SIZE must be a positive integer, got %q", v)
		}
		s.ExportPageSize = n
	}

	return s, nil
}
