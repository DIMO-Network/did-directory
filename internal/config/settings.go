package config

import (
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

// LoadConfig reads a YAML settings file and returns the parsed Settings.
// Environment variables override YAML values when set.
func LoadConfig(path string) (*Settings, error) {
	s := &Settings{
		Port:                8080,
		MonitoringPort:      8888,
		LogLevel:            "info",
		MaxOperationsPerDID: 1000,
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

	return s, nil
}
