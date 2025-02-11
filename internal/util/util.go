// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

// Package util packages various utilities.
package util

import (
	"context"
	"log/slog"
)

// log/slog does not implement trace logging by default, but is flexible.
const (
	LogLevelTrace = slog.Level(-8)
)

// TraceLog sends trace-level logging to log/slog.Logger.
func TraceLog(l *slog.Logger, msg string, args ...any) {
	l.Log(context.Background(), LogLevelTrace, msg, args...)
}
