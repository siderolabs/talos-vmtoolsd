// This file was adapted from govmomi/toolbox's channel.go and backdoor.go.
// The original copyright notice follows.

// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

// Package vmwlogger is a wrapper to plug into github.com/vmware/vmw-guestinfo/message
package vmwlogger

import (
	"fmt"
	"log/slog"

	"github.com/siderolabs/talos-vmtoolsd/internal/util"
)

// VMWareLogger is wrapper to make log/slog fit into https://pkg.go.dev/github.com/vmware/vmw-guestinfo@v0.0.0-20220317130741-510905f0efa3/message.
type VMWareLogger struct {
	logger *slog.Logger
}

// New initializes the wrapper around slog.Logger.
func New(logger *slog.Logger) *VMWareLogger {
	l := &VMWareLogger{
		logger: logger,
	}

	return l
}

// Errorf logs an error.
func (v VMWareLogger) Errorf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	v.logger.Error(msg)
}

// Debugf logs debugging (acually trace info).
// We'll send debug statements from vmw-message to slog trace level.
func (v VMWareLogger) Debugf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	util.TraceLog(v.logger, msg)
}

// Infof logs informational messages.
func (v VMWareLogger) Infof(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	v.logger.Info(msg)
}
