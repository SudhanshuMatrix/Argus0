// Package config loads and validates the Argus configuration from a YAML file.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration struct for Argus. It is populated
// from configs/default.yaml (or a path provided by --config flag).
type Config struct {
	// Agent contains settings for the eBPF collection agent.
	Agent AgentConfig `yaml:"agent"`

	// Prometheus contains the HTTP server settings.
	Prometheus PrometheusConfig `yaml:"prometheus"`

	// Logging controls log level and format.
	Logging LoggingConfig `yaml:"logging"`
}

// AgentConfig configures the eBPF collection agent.
type AgentConfig struct {
	// Interface is the network interface to monitor (e.g., "eth0", "ens3").
	Interface string `yaml:"interface"`

	// CollectInterval is how often the agent reads the BPF flow_map.
	// Shorter intervals reduce latency but increase CPU usage.
	CollectInterval time.Duration `yaml:"collect_interval"`

	// CacheTTL is how long process metadata is cached before re-reading /proc.
	CacheTTL time.Duration `yaml:"cache_ttl"`
}

// PrometheusConfig configures the Prometheus metrics endpoint.
type PrometheusConfig struct {
	// ListenAddr is the address:port for the /metrics HTTP endpoint.
	ListenAddr string `yaml:"listen_addr"`
}

// LoggingConfig controls log verbosity and output format.
type LoggingConfig struct {
	// Level is the minimum log level: "trace", "debug", "info", "warn", "error".
	Level string `yaml:"level"`

	// Format is "json" or "text". Use "json" in production for structured logs.
	Format string `yaml:"format"`
}

// Load reads the configuration file at the given path and returns a populated
// Config. If path is empty, it falls back to "configs/default.yaml".
func Load(path string) (*Config, error) {
	// Load environment variables from .env file if it exists.
	// We ignore the error because .env might not exist in production or testing
	// environments where variables are set directly.
	_ = godotenv.Load()

	if path == "" {
		path = "configs/default.yaml"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}

	// Apply defaults for any zero-value fields.
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}

	// Override values using environment variables if defined.
	cfg.applyEnvOverrides()

	return &cfg, nil
}

// applyDefaults fills in sensible defaults for fields that were not set in
// the configuration file.
func (c *Config) applyDefaults() error {
	if c.Agent.Interface == "" {
		c.Agent.Interface = "eth0"
	}
	if c.Agent.CollectInterval == 0 {
		c.Agent.CollectInterval = 5 * time.Second
	}
	if c.Agent.CacheTTL == 0 {
		c.Agent.CacheTTL = 30 * time.Second
	}
	if c.Prometheus.ListenAddr == "" {
		c.Prometheus.ListenAddr = ":9090"
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	return nil
}

// applyEnvOverrides overrides the configuration settings using environment variables.
func (c *Config) applyEnvOverrides() {
	if val := os.Getenv("ARGUS_INTERFACE"); val != "" {
		c.Agent.Interface = val
	} else if val := os.Getenv("INTERFACE"); val != "" {
		c.Agent.Interface = val
	}

	if val := os.Getenv("ARGUS_COLLECT_INTERVAL"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			c.Agent.CollectInterval = d
		}
	}

	if val := os.Getenv("ARGUS_CACHE_TTL"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			c.Agent.CacheTTL = d
		}
	}

	// Support both PORT (e.g. 9090) and ARGUS_LISTEN_ADDR (e.g. :9090)
	if val := os.Getenv("PORT"); val != "" {
		if val[0] != ':' {
			c.Prometheus.ListenAddr = ":" + val
		} else {
			c.Prometheus.ListenAddr = val
		}
	}
	if val := os.Getenv("ARGUS_LISTEN_ADDR"); val != "" {
		c.Prometheus.ListenAddr = val
	}

	if val := os.Getenv("ARGUS_LOG_LEVEL"); val != "" {
		c.Logging.Level = val
	}

	if val := os.Getenv("ARGUS_LOG_FORMAT"); val != "" {
		c.Logging.Format = val
	}
}
