// SPDX-FileCopyrightText: Copyright (c) 2025 Clément Nussbaumer, PostFinance
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/equinix-ms/go-vmw-guestrpc/pkg/nanotoolbox"
	"github.com/spf13/cobra"
)

var rpcCmd = &cobra.Command{
	Use:   "rpc --cmd [command]",
	Short: "execute an arbitrary RPC command",
	Long:  "can be used to query the hypervisor with e.g. 'info-get guestinfo.some-metadata'",
	RunE:  rpcCommand,
}

var rpcCommandFlag string

func init() {
	rpcCmd.Flags().StringVar(&rpcCommandFlag, "cmd", "", "RPC command")
	rootCmd.AddCommand(rpcCmd)
}

func rpcCommand(_ *cobra.Command, _ []string) error {
	err := executeRPC(rpcCommandFlag)

	return err
}

func executeRPC(command string) error {
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
		return fmt.Errorf("RPC request failed: %w", err)
	}

	if !ok {
		logger.Error("RPC returned error", "response", string(result))

		return fmt.Errorf("RPC command failed: %s", string(result))
	}

	logger.Debug("RPC command successful", "response", string(result))

	if len(result) > 0 {
		fmt.Println(string(result))
	}

	return nil
}
