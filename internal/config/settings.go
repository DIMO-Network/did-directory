package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Settings holds all configuration for the did-directory service.
type Settings struct {
	Port                 int    `yaml:"PORT"`
	MonitoringPort       int    `yaml:"MONITORING_PORT"`
	DatabaseURL          string `yaml:"DATABASE_URL"`
	LogLevel             string `yaml:"LOG_LEVEL"`
	MaxOperationsPerDID  int    `yaml:"MAX_OPERATIONS_PER_DID"`
	ExportPageSize       int    `yaml:"EXPORT_PAGE_SIZE"`
}

// LoadConfig reads a YAML settings file and returns the parsed Settings.
func LoadConfig(path string) (*Settings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	s := &Settings{
		Port:                8080,
		MonitoringPort:      8888,
		LogLevel:            "info",
		MaxOperationsPerDID: 1000,
		ExportPageSize:      100,
	}

	if err := yaml.Unmarshal(data, s); err != nil {
		return nil, err
	}

	return s, nil
}
