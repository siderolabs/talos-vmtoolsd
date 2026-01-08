// SPDX-FileCopyrightText: Copyright (c) 2025 Clément Nussbaumer, PostFinance
// SPDX-License-Identifier: Apache-2.0

// Package rpc contains the logic to issue arbitrary command to the hypervisor
package rpc

import (
	"fmt"
	"log/slog"

	"github.com/equinix-ms/go-vmw-guestrpc/pkg/nanotoolbox"
)

func ExecuteRPC(logger *slog.Logger, command string) error {
	if command == "" {
		return fmt.Errorf("RPC command cannot be empty")
	}

	logger.Debug("executing RPC command", "command", command)

	rpci, err := nanotoolbox.NewRPCI(logger.With("module", "RPCI"))
	if err != nil {
		return fmt.Errorf("failed to create RPCI: %w", err)
	}

	if err = rpci.Start(); err != nil {
		return fmt.Errorf("failed to start RPCI channel: %w", err)
	}

	defer func() {
		if err = rpci.Stop(); err != nil {
			logger.Warn("failed to close RPCI channel", "err", err)
		}
	}()

	result, ok, err := rpci.Request([]byte(command))
	if err != nil {
		logger.Warn("error while executing RPCI request", "err", err)

		return err
	}

	if len(result) > 0 {
		fmt.Println(string(result))
	}

	if !ok {
		logger.Debug("RPC request failed", "response", string(result))

		return fmt.Errorf("RPC request failed: %s", string(result))
	} else {
		logger.Debug("RPC request successful", "response", string(result))

		return nil
	}
}
