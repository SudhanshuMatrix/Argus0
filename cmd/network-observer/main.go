package main

import (
	"context"
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
	"github.com/sudhanshu-singh/argus/internal/enricher"
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

func run() error {
	configPath := flag.String("config", "", "Path to config YAML (default: configs/default.yaml)")
	iface := flag.String("interface", "", "Network interface to monitor (overrides config)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if *iface != "" {
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.WithField("signal", sig).Info("Received shutdown signal")
		cancel()
	}()

	bpfObjs, err := bpf.Load(cfg.Agent.Interface, log)
	if err != nil {
		return fmt.Errorf("loading eBPF programs onto %q: %w", cfg.Agent.Interface, err)
	}
	// Ensure programs are detached from the interface on any exit path.
	defer func() {
		log.Info("Cleaning up eBPF programs...")
		bpfObjs.Close()
		log.Info("eBPF programs detached successfully")
	}()

	flowStore := store.NewFlowStore(60)

	promExporter, err := exporter.NewPrometheusExporter(cfg.Agent.Interface, log)
	if err != nil {
		return fmt.Errorf("creating Prometheus exporter: %w", err)
	}

	apiHandler := api.NewHandler(flowStore, cfg.Agent.Interface, log)

	go func() {
		err := promExporter.ServeMetrics(ctx, cfg.Prometheus.ListenAddr, func(mux *http.ServeMux) {
			apiHandler.RegisterRoutes(mux)
			apiHandler.RegisterDashboardRoute(mux)
		})
		if err != nil {
			log.WithError(err).Error("HTTP server error")
			cancel()
		}
	}()

	procEnricher := enricher.NewProcessEnricher(cfg.Agent.CacheTTL, log)

	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				procEnricher.PurgeExpired()
			}
		}
	}()

	exporters := []exporter.Exporter{promExporter}

	flowCollector := collector.NewCollector(
		bpfObjs,
		procEnricher,
		exporters,
		cfg.Agent.CollectInterval,
		log,
		flowStore,
	)

	log.WithFields(logrus.Fields{
		"interface":        cfg.Agent.Interface,
		"collect_interval": cfg.Agent.CollectInterval,
		"metrics_addr":     cfg.Prometheus.ListenAddr,
	}).Info("Argus agent running")

	if err := flowCollector.Run(ctx); err != nil && err != context.Canceled {
		return fmt.Errorf("collector error: %w", err)
	}

	log.Info("Argus agent stopped gracefully")
	return nil
}

func setupLogger(level, format string) *logrus.Logger {
	log := logrus.New()

	parsedLevel, err := logrus.ParseLevel(level)
	if err != nil {
		parsedLevel = logrus.InfoLevel
	}
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
