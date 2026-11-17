// Package config loads and validates Argus configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const MaxMapCapacity = 100_000

type Config struct {
	Agent      AgentConfig      `yaml:"agent"`
	Prometheus PrometheusConfig `yaml:"prometheus"`
	Logging    LoggingConfig    `yaml:"logging"`
}

type AgentConfig struct {
	Interface       string        `yaml:"interface"`
	CollectInterval time.Duration `yaml:"collect_interval"`
	MapCapacity     uint32        `yaml:"map_capacity"`
	CacheTTL        time.Duration `yaml:"cache_ttl"` // Deprecated process metadata setting.
}

type PrometheusConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Load applies file settings, then .env and process environment overrides.
func Load(path string) (*Config, error) {
	cfg := Config{
		Agent:      AgentConfig{"eth0", 5 * time.Second, MaxMapCapacity, 30 * time.Second},
		Prometheus: PrometheusConfig{"127.0.0.1:9090"},
		Logging:    LoggingConfig{"info", "json"},
	}
	if err := cfg.readFile(path); err != nil {
		return nil, err
	}
	dotenv, err := godotenv.Read(".env")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("Load .env: %w", err)
	}
	lookup := func(key string) (string, bool) {
		if value, exists := os.LookupEnv(key); exists {
			return value, true
		}
		value, exists := dotenv[key]
		return value, exists
	}
	if err := cfg.applyEnv(lookup); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) readFile(path string) error {
	implicit := path == ""
	if implicit {
		path = "configs/default.yaml"
	}
	data, err := os.ReadFile(path)
	if implicit && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("readFile %q: %w", path, err)
	}
	if err := c.decode(data); err != nil {
		return fmt.Errorf("readFile %q: %w", path, err)
	}
	return nil
}

func (c *Config) decode(data []byte) error {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return err
	}
	if hasNull(&node) {
		return errors.New("YAML values must not be null")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	if err := dec.Decode(&node); !errors.Is(err, io.EOF) {
		return errors.New("expected a single YAML document")
	}
	return nil
}

func hasNull(node *yaml.Node) bool {
	if node.Tag == "!!null" {
		return true
	}
	for _, child := range node.Content {
		if hasNull(child) {
			return true
		}
	}
	return false
}

func (c *Config) applyEnv(lookup func(string) (string, bool)) error {
	for _, item := range []struct {
		key string
		dst *string
	}{
		{"INTERFACE", &c.Agent.Interface},
		{"ARGUS_INTERFACE", &c.Agent.Interface},
		{"ARGUS_LOG_LEVEL", &c.Logging.Level},
		{"ARGUS_LOG_FORMAT", &c.Logging.Format},
	} {
		if value, set := lookup(item.key); set {
			*item.dst = value
		}
	}
	for _, item := range []struct {
		key string
		dst *time.Duration
	}{
		{"ARGUS_COLLECT_INTERVAL", &c.Agent.CollectInterval},
		{"ARGUS_CACHE_TTL", &c.Agent.CacheTTL},
	} {
		if value, set := lookup(item.key); set {
			duration, err := time.ParseDuration(value)
			if err != nil || duration <= 0 {
				return fmt.Errorf("%s must be a positive duration", item.key)
			}
			*item.dst = duration
		}
	}
	if value, set := lookup("ARGUS_MAP_CAPACITY"); set {
		capacity, err := strconv.ParseUint(value, 10, 32)
		if err != nil || capacity == 0 || capacity > MaxMapCapacity {
			return fmt.Errorf("ARGUS_MAP_CAPACITY must be between 1 and %d", MaxMapCapacity)
		}
		c.Agent.MapCapacity = uint32(capacity)
	}
	if value, set := lookup("ARGUS_LISTEN_ADDR"); set {
		c.Prometheus.ListenAddr = value
	} else if value, set := lookup("PORT"); set {
		c.Prometheus.ListenAddr = net.JoinHostPort("127.0.0.1", strings.TrimPrefix(value, ":"))
	}
	return nil
}

func (c *Config) validate() error {
	if err := ValidateInterface(c.Agent.Interface); err != nil {
		return err
	}
	if c.Agent.CollectInterval < 100*time.Millisecond || c.Agent.CollectInterval > 5*time.Minute {
		return errors.New("collect_interval must be between 100ms and 5m")
	}
	if c.Agent.MapCapacity == 0 || c.Agent.MapCapacity > MaxMapCapacity {
		return fmt.Errorf("map_capacity must be between 1 and %d", MaxMapCapacity)
	}
	if c.Agent.CacheTTL <= 0 {
		return errors.New("deprecated cache_ttl must be positive if set")
	}
	host, port, err := net.SplitHostPort(c.Prometheus.ListenAddr)
	if err != nil || host == "" {
		return errors.New("listen_addr must include an explicit IP address or localhost and a numeric port")
	}
	if _, err := netip.ParseAddr(host); err != nil && host != "localhost" {
		return errors.New("listen_addr must use an IP address or localhost")
	}
	if p, err := strconv.ParseUint(port, 10, 16); err != nil || p == 0 {
		return errors.New("listen_addr port must be between 1 and 65535")
	}
	if _, err := logrus.ParseLevel(c.Logging.Level); err != nil {
		return fmt.Errorf("validate log level: %w", err)
	}
	if c.Logging.Format != "json" && c.Logging.Format != "text" {
		return errors.New("log format must be json or text")
	}
	return nil
}

func ValidateInterface(name string) error {
	if name == "" || len(name) > 15 || name == "." || name == ".." || strings.ContainsAny(name, "/:") ||
		strings.ContainsFunc(name, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return fmt.Errorf("invalid Linux interface name %q", name)
	}
	return nil
}
