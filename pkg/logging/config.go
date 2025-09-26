package logging

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// LogLevel represents the logging level
type LogLevel string

const (
	LogLevelTrace LogLevel = "trace"
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
	LogLevelPanic LogLevel = "panic"
)

// LogFormat represents the logging format
type LogFormat string

const (
	LogFormatJSON    LogFormat = "json"
	LogFormatConsole LogFormat = "console"
)

// Config holds the logging configuration
type Config struct {
	Level       LogLevel  `json:"level" yaml:"level"`
	Format      LogFormat `json:"format" yaml:"format"`
	ServiceName string    `json:"service_name" yaml:"service_name"`
	Environment string    `json:"environment" yaml:"environment"`
	Version     string    `json:"version" yaml:"version"`
	Caller      bool      `json:"caller" yaml:"caller"`
	Timestamp   bool      `json:"timestamp" yaml:"timestamp"`
	PID         bool      `json:"pid" yaml:"pid"`
}

// DefaultConfig returns a default logging configuration
func DefaultConfig() *Config {
	return &Config{
		Level:       LogLevelInfo,
		Format:      LogFormatConsole,
		ServiceName: "tokensmith",
		Environment: "development",
		Version:     "1.0.0",
		Caller:      true,
		Timestamp:   true,
		PID:         false,
	}
}

// Configure sets up the global logger with the given configuration
func Configure(config *Config) zerolog.Logger {
	if config == nil {
		config = DefaultConfig()
	}

	// Set the global log level
	level, err := zerolog.ParseLevel(string(config.Level))
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// Configure time format
	zerolog.TimeFieldFormat = time.RFC3339Nano

	// Create the logger
	var logger zerolog.Logger

	switch config.Format {
	case LogFormatConsole:
		output := zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: time.RFC3339,
		}
		if !config.Timestamp {
			output.NoColor = true
		}
		logger = zerolog.New(output).With().Timestamp().Logger()
	case LogFormatJSON:
		logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
	default:
		logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
	}

	// Add common fields
	logger = logger.With().
		Str("service", config.ServiceName).
		Str("environment", config.Environment).
		Str("version", config.Version).
		Logger()

	// Add caller information if requested
	if config.Caller {
		logger = logger.With().Caller().Logger()
	}

	// Add PID if requested
	if config.PID {
		logger = logger.With().Int("pid", os.Getpid()).Logger()
	}

	// Set as global logger
	log.Logger = logger

	return logger
}

// ConfigureFromEnv configures logging from environment variables
func ConfigureFromEnv() zerolog.Logger {
	config := DefaultConfig()

	// Override with environment variables
	if level := os.Getenv("LOG_LEVEL"); level != "" {
		config.Level = LogLevel(strings.ToLower(level))
	}

	if format := os.Getenv("LOG_FORMAT"); format != "" {
		config.Format = LogFormat(strings.ToLower(format))
	}

	if serviceName := os.Getenv("SERVICE_NAME"); serviceName != "" {
		config.ServiceName = serviceName
	}

	if environment := os.Getenv("ENVIRONMENT"); environment != "" {
		config.Environment = environment
	}

	if version := os.Getenv("VERSION"); version != "" {
		config.Version = version
	}

	if caller := os.Getenv("LOG_CALLER"); caller != "" {
		config.Caller = caller == "true"
	}

	if timestamp := os.Getenv("LOG_TIMESTAMP"); timestamp != "" {
		config.Timestamp = timestamp == "true"
	}

	if pid := os.Getenv("LOG_PID"); pid != "" {
		config.PID = pid == "true"
	}

	return Configure(config)
}

// GetLogger returns a logger with the given context
func GetLogger(component string) zerolog.Logger {
	return log.Logger.With().Str("component", component).Logger()
}

// GetLoggerWithFields returns a logger with additional fields
func GetLoggerWithFields(component string, fields map[string]interface{}) zerolog.Logger {
	logger := log.Logger.With().Str("component", component)
	for key, value := range fields {
		logger = logger.Interface(key, value)
	}
	return logger.Logger()
}
