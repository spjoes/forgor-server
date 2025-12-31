package config

import (
	"flag"
	"os"
	"strconv"
	"time"
)

type Config struct {
	BindAddr string
	DBPath   string

	RateLimitRequestsPerSecond float64
	RateLimitBurst             int

	MaxRequestBodySize int64
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	IdleTimeout        time.Duration

	LogLevel string
}

func Load() *Config {
	cfg := &Config{
		BindAddr:                   getEnvOrDefault("FORGOR_BIND_ADDR", ":8080"),
		DBPath:                     getEnvOrDefault("FORGOR_DB_PATH", "forgor.db"),
		RateLimitRequestsPerSecond: getEnvFloatOrDefault("FORGOR_RATE_LIMIT_RPS", 10.0),
		RateLimitBurst:             getEnvIntOrDefault("FORGOR_RATE_LIMIT_BURST", 50),
		MaxRequestBodySize:         int64(getEnvIntOrDefault("FORGOR_MAX_BODY_SIZE", 10*1024*1024)),
		ReadTimeout:                time.Duration(getEnvIntOrDefault("FORGOR_READ_TIMEOUT_SEC", 30)) * time.Second,
		WriteTimeout:               time.Duration(getEnvIntOrDefault("FORGOR_WRITE_TIMEOUT_SEC", 60)) * time.Second,
		IdleTimeout:                time.Duration(getEnvIntOrDefault("FORGOR_IDLE_TIMEOUT_SEC", 120)) * time.Second,
		LogLevel:                   getEnvOrDefault("FORGOR_LOG_LEVEL", "info"),
	}

	flag.StringVar(&cfg.BindAddr, "addr", cfg.BindAddr, "Bind address (host:port)")
	flag.StringVar(&cfg.DBPath, "db", cfg.DBPath, "SQLite database path")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level (debug, info, warn, error)")
	flag.Parse()

	return cfg
}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvIntOrDefault(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

func getEnvFloatOrDefault(key string, defaultVal float64) float64 {
	if val := os.Getenv(key); val != "" {
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			return f
		}
	}
	return defaultVal
}
