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
	Short: "execute an arbitraty RPC command",
	Long:  "can be used to query the hypervisor with e.g. 'info-get guestinfo.some-metadata'",
	RunE:  rpcCommand,
}

var rpcCommandFlag string

func init() {
	rpcCmd.Flags().StringVar(&rpcCommandFlag, "cmd", "", "RPC command")
	rootCmd.AddCommand(rpcCmd)
}

func rpcCommand(cmd *cobra.Command, _ []string) error {
	rpci, err := nanotoolbox.NewRPCI(logger.With("module", "RPCI"))
	if err != nil {
		return err
	}

	if err = rpci.Start(); err != nil {
		logger.Error("error starting rpci service", "err", err)
	}

	defer func() {
		if err = rpci.Stop(); err != nil {
			logger.Warn("failed to close RPCI channel", "err", err)
		}
	}()

	result, ok, err := rpci.Request([]byte(rpcCommandFlag))
	if err != nil {
		return fmt.Errorf("RPC request failed: %w", err)
	}

	if !ok {
		return fmt.Errorf("RPC request failed (!ok). response: %v", result)
	}

	if len(result) > 0 {
		fmt.Println(string(result))
	}

	return nil
}
