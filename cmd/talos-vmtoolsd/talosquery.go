// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"time"

	"github.com/spf13/cobra"
)

var talosqueryCmd = &cobra.Command{
	Use:   "talosquery",
	Short: "query the talos API",
	Long:  "this can be used to test the connection with talos api for development of this tool",
	Run:   talosquery,
}

func init() {
	rootCmd.AddCommand(talosqueryCmd)
}

func talosquery(_ *cobra.Command, _ []string) {
	logger.Info("hostname", "dnsname", api.Hostname())
	logger.Info("os information", "version", api.OSVersion(), "short", api.OSVersionShort())
	u := api.Uptime()
	logger.Info("uptime", "seconds", u, "duration", time.Duration(u))

	for idx, nic := range api.NetInterfaces() {
		logger.Info("interface", "idx", idx, "name", nic.Name, "mac", nic.Mac)

		for _, addr := range nic.Addrs {
			logger.Info("with address", "addr", addr)
		}
	}
}
