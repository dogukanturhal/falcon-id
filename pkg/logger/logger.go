// SPDX-License-Identifier: AGPL-3.0-or-later

// Package logger provides structured logging utilities.
package logger

import (
	"os"

	sharedlogger "github.com/dogukanturhal/falcon-id/internal/shared/logger"
	"go.uber.org/zap"
)

// Log is an exported constant.
var Log *zap.Logger

// InitLogger is an exported function.
func InitLogger(level string, environment string) {
	Log = sharedlogger.MustNewLogger(level, environment)
	initSecurityAuditLogger()
}

// Sync is an exported function.
func Sync() {
	if Log != nil {
		_ = Log.Sync()
	}
}

// Debug is an exported function.
func Debug(msg string, fields ...zap.Field) {
	Log.Debug(msg, fields...)
}

// Info is an exported function.
func Info(msg string, fields ...zap.Field) {
	Log.Info(msg, fields...)
}

// Warn is an exported function.
func Warn(msg string, fields ...zap.Field) {
	Log.Warn(msg, fields...)
}

// Error is an exported function.
func Error(msg string, fields ...zap.Field) {
	Log.Error(msg, fields...)
}

// Fatal is an exported function.
func Fatal(msg string, fields ...zap.Field) {
	Log.Fatal(msg, fields...)
	os.Exit(1)
}

// With is an exported function.
func With(fields ...zap.Field) *zap.Logger {
	return Log.With(fields...)
}

// SecurityAudit is a dedicated logger for security audit events.
// It includes a "log_type" field set to "security_audit" on every entry,
// making it easy to filter and route security-relevant log lines
// separately from regular application logs.
var SecurityAudit *zap.Logger

// initSecurityAuditLogger initializes the security audit sub-logger.
// Must be called after InitLogger.
func initSecurityAuditLogger() {
	if Log == nil {
		return
	}
	SecurityAudit = sharedlogger.NewSecurityAuditLogger(Log)
}
