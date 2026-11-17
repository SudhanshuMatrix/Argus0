package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadStrictYAML(t *testing.T) {
	for _, tt := range []struct {
		name string
		yaml string
	}{
		{"unknown field", "agent: {map_capcity: 42}\n"},
		{"extra document", "{}\n---\n{}\n"},
		{"null", "agent: {map_capacity: null}\n"},
		{"zero duration", "agent: {collect_interval: 0s}\n"},
		{"duration exceeds bound", "agent: {collect_interval: 10m}\n"},
		{"zero capacity", "agent: {map_capacity: 0}\n"},
		{"capacity exceeds bound", "agent: {map_capacity: 100001}\n"},
		{"implicit wildcard", "prometheus: {listen_addr: ':9090'}\n"},
		{"invalid port", "prometheus: {listen_addr: '127.0.0.1:65536'}\n"},
		{"invalid interface", "agent: {interface: 'eth 0'}\n"},
		{"invalid log level", "logging: {level: loud}\n"},
		{"invalid log format", "logging: {format: yaml}\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "argus.yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			if cfg, err := Load(path); err == nil {
				t.Fatalf("invalid config accepted: %+v", cfg)
			}
		})
	}
}

func TestLoadDefaultsAndOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "argus.yaml")
	if err := os.WriteFile(path, []byte("agent: {interface: test0, map_capacity: 128}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent.Interface != "test0" || cfg.Agent.MapCapacity != 128 ||
		cfg.Agent.CollectInterval != 5*time.Second || cfg.Prometheus.ListenAddr != "127.0.0.1:9090" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}

	t.Setenv("INTERFACE", "legacy0")
	t.Setenv("ARGUS_INTERFACE", "override0")
	t.Setenv("ARGUS_COLLECT_INTERVAL", "2s")
	t.Setenv("ARGUS_MAP_CAPACITY", "42")
	t.Setenv("PORT", "8081")
	cfg, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent.Interface != "override0" || cfg.Agent.CollectInterval != 2*time.Second ||
		cfg.Agent.MapCapacity != 42 || cfg.Prometheus.ListenAddr != "127.0.0.1:8081" {
		t.Fatalf("unexpected overrides: %+v", cfg)
	}
	t.Setenv("ARGUS_LISTEN_ADDR", "[::1]:8082")
	cfg, err = Load(path)
	if err != nil || cfg.Prometheus.ListenAddr != "[::1]:8082" {
		t.Fatalf("explicit address must override PORT: %+v, %v", cfg, err)
	}
}

func TestLoadRejectsInvalidEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "argus.yaml")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ key, value string }{
		{"ARGUS_COLLECT_INTERVAL", ""},
		{"ARGUS_COLLECT_INTERVAL", "nonsense"},
		{"ARGUS_COLLECT_INTERVAL", "-1s"},
		{"ARGUS_CACHE_TTL", "wrong"},
		{"ARGUS_MAP_CAPACITY", "-1"},
		{"ARGUS_MAP_CAPACITY", "0"},
		{"ARGUS_MAP_CAPACITY", "100001"},
		{"ARGUS_INTERFACE", ""},
		{"ARGUS_LISTEN_ADDR", ""},
		{"ARGUS_LOG_LEVEL", ""},
		{"ARGUS_LOG_FORMAT", ""},
	} {
		t.Run(tt.key+"/"+tt.value, func(t *testing.T) {
			t.Setenv(tt.key, tt.value)
			if cfg, err := Load(path); err == nil {
				t.Fatalf("invalid environment accepted: %+v", cfg)
			}
		})
	}
}
