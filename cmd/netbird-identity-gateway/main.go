package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/whereareiam/netbird-identity-gateway/internal/server"
)

var version = "dev"

func main() {
	configPath := flag.String("config", envOr("NIG_CONFIG", "config/config.yaml"), "path to the YAML configuration")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	config, err := server.LoadConfig(*configPath)
	if err != nil {
		logger.Error("loading configuration", "error", err)
		os.Exit(1)
	}

	signer, err := loadSigner(config.SigningKey)
	if err != nil {
		logger.Error("loading signing key", "error", err)
		os.Exit(1)
	}

	server, err := server.NewServer(config, signer, logger)
	if err != nil {
		logger.Error("initializing gateway", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	newHTTPServer := func(addr string, handler http.Handler) *http.Server {
		return &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       2 * time.Minute,
			MaxHeaderBytes:    8192,
		}
	}
	httpServer := newHTTPServer(config.Listen, server.Handler())
	backchannel := newHTTPServer(config.BackchannelListen, server.BackchannelHandler())
	go func() {
		if err := backchannel.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			logger.Error("backchannel stopped", "error", err)
			stop()
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = backchannel.Shutdown(shutdownContext)
		if err := httpServer.Shutdown(shutdownContext); err != nil {
			logger.Error("shutting down HTTP server", "error", err)
		}
	}()

	logger.Info("starting identity gateway", "version", version, "listen", config.Listen, "issuer", config.Issuer)
	if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		logger.Error("HTTP server stopped", "error", err)
		os.Exit(1)
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func loadSigner(config string) (*rsa.PrivateKey, error) {
	contents, err := os.ReadFile(config)
	if err != nil {
		return nil, fmt.Errorf("read signing key %q: %w", config, err)
	}
	return server.ParsePrivateKey(contents)
}
