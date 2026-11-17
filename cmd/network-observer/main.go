package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/sudhanshu-singh/argus/internal/api"
	"github.com/sudhanshu-singh/argus/internal/bpf"
	"github.com/sudhanshu-singh/argus/internal/collector"
	"github.com/sudhanshu-singh/argus/internal/config"
	"github.com/sudhanshu-singh/argus/internal/exporter"
	"github.com/sudhanshu-singh/argus/internal/store"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "argus: fatal error: %v\n", err)
		os.Exit(1)
	}
}

func run() (err error) {
	configPath := flag.String("config", "", "Path to config YAML (default: configs/default.yaml)")
	iface := flag.String("interface", "", "Network interface to monitor (overrides config)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	var interfaceSet bool
	flag.Visit(func(f *flag.Flag) {
		interfaceSet = interfaceSet || f.Name == "interface"
	})
	if interfaceSet {
		if err := config.ValidateInterface(*iface); err != nil {
			return err
		}
		cfg.Agent.Interface = *iface
	}

	log := setupLogger(cfg.Logging.Level, cfg.Logging.Format)
	log.WithFields(logrus.Fields{
		"version":   version,
		"interface": cfg.Agent.Interface,
	}).Info("Argus network observer starting")

	// --- Check privileges ---
	// CAP_BPF / root is required to load eBPF programs.
	if os.Getuid() != 0 {
		log.Warn("Not running as root — BPF program loading may fail. " +
			"Run with sudo or grant CAP_BPF + CAP_NET_ADMIN.")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	bpfObjs, err := bpf.Load(cfg.Agent.Interface, cfg.Agent.MapCapacity, log)
	if err != nil {
		return fmt.Errorf("loading eBPF programs onto %q: %w", cfg.Agent.Interface, err)
	}
	defer func() {
		if closeErr := bpfObjs.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("releasing BPF resources: %w", closeErr))
		}
	}()

	flowStore := store.NewFlowStore(60)
	flowStore.SetAttached(true)

	promExporter, err := exporter.NewPrometheusExporter(cfg.Agent.Interface, log)
	if err != nil {
		return fmt.Errorf("creating Prometheus exporter: %w", err)
	}

	apiHandler := api.NewHandler(flowStore, cfg.Agent.Interface, log, 3*cfg.Agent.CollectInterval)

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- promExporter.ServeMetrics(ctx, cfg.Prometheus.ListenAddr, func(mux *http.ServeMux) {
			apiHandler.RegisterRoutes(mux)
			apiHandler.RegisterDashboardRoute(mux)
		})
		cancel()
	}()

	flowCollector := collector.NewCollector(
		bpfObjs, promExporter, cfg.Agent.MapCapacity, cfg.Agent.CollectInterval, log, flowStore,
	)

	log.WithFields(logrus.Fields{
		"interface":        cfg.Agent.Interface,
		"collect_interval": cfg.Agent.CollectInterval,
		"metrics_addr":     cfg.Prometheus.ListenAddr,
	}).Info("Argus agent running")

	collectorErr := flowCollector.Run(ctx)
	cancel()
	if err := <-serverDone; err != nil {
		return fmt.Errorf("HTTP server: %w", err)
	}
	if collectorErr != nil && !errors.Is(collectorErr, context.Canceled) {
		return fmt.Errorf("collector: %w", collectorErr)
	}

	log.Info("Argus agent stopped gracefully")
	return nil
}

func setupLogger(level, format string) *logrus.Logger {
	log := logrus.New()

	parsedLevel, _ := logrus.ParseLevel(level)
	log.SetLevel(parsedLevel)

	switch format {
	case "json":
		log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
		})
	default:
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		})
	}

	log.SetOutput(os.Stdout)
	return log
}
