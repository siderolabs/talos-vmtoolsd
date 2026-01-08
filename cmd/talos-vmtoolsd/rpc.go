// SPDX-FileCopyrightText: Copyright (c) 2025 Clément Nussbaumer, PostFinance
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/siderolabs/talos-vmtoolsd/internal/rpc"
)

const (
	flagRPCCommand = "cmd"
)

var rpcCmd = &cobra.Command{
	Use:   "rpc --cmd [command]",
	Short: "execute an arbitrary RPC command",
	Long:  "can be used to query the hypervisor with e.g. 'info-get guestinfo.some-metadata'",
	Run:   rpcCommand,
}

var rpcCommandFlag string

func init() {
	rpcCmd.Flags().StringVar(&rpcCommandFlag, flagRPCCommand, "", "RPC command")
	rootCmd.AddCommand(rpcCmd)
}

func rpcCommand(_ *cobra.Command, _ []string) {
	if err := rpc.ExecuteRPC(logger, rpcCommandFlag); err != nil {
		os.Exit(1)
	}
}
