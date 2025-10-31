// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

// Package main is the main package invoking the tool
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/equinix-ms/go-vmw-guestrpc/pkg/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/siderolabs/talos-vmtoolsd/internal/talosconnection"
	"github.com/siderolabs/talos-vmtoolsd/internal/version"
)

const (
	flagUseMachined = "use-machined"
	flagLogLevel    = "log-level"
	flagTalosConfig = "talos-config"
	flagTalosNode   = "talos-node"
	flagRPCCmd      = "cmd"
)

var rootCmd = &cobra.Command{
	Use:                "talos-vmtoolsd",
	Short:              "toolset that glues talos to vmware hypervisors",
	Long:               "this is a tool like open-vm-tools, but for Talos Linux",
	PersistentPreRunE:  setup,
	PersistentPostRunE: cleanup,
	RunE: func(cmd *cobra.Command, args []string) error {
		if viper.IsSet(flagRPCCmd) {
			return executeRPC(viper.GetString(flagRPCCmd))
		}

		return cmd.Help()
	},
}

var errTalosSetupFailed = errors.New("error setting up Talos connection")

var (
	logger    *slog.Logger
	api       *talosconnection.TalosAPIConnection
	ctx       context.Context
	ctxCancel context.CancelFunc
)

func parseLevel(s string) (slog.Level, error) {
	// slog does not support trace level logging by default, but is flexible
	if strings.ToUpper(s) == "TRACE" {
		return util.LogLevelTrace, nil
	}

	var level slog.Level

	err := level.UnmarshalText([]byte(s))

	return level, err
}

func setup(cmd *cobra.Command, _ []string) error {
	level, err := parseLevel(viper.GetString(flagLogLevel))
	if err != nil {
		panic("error parsing log level")
	}

	logOpts := &slog.HandlerOptions{
		Level: level,
	}

	logger = slog.New(slog.NewTextHandler(os.Stdout, logOpts)).With("command", cmd.Name())

	if viper.IsSet(flagRPCCmd) || cmd.Name() == "rpc" {
		// no need to configure talos api client in that case.
		return nil
	}

	ctx = context.Background()
	ctx, ctxCancel = context.WithCancel(ctx) // nolint:fatcontext

	if !viper.GetBool(flagUseMachined) {
		// Our spec file passes the secret path and K8s host IP via env vars.
		configPath := viper.GetString(flagTalosConfig)
		if len(configPath) == 0 {
			logger.Error("a path to a Talos configuration file is required when not connecting to machined")

			return errTalosSetupFailed
		}

		talosNode := viper.GetString(flagTalosNode)
		if len(talosNode) == 0 {
			logger.Error("you need to specify a Talos node when not connecting to machined")

			return errTalosSetupFailed
		}

		// Connect to Talos apid
		var err error

		api, err = talosconnection.RemoteApidConnection(ctx, logger.With("module", "talosconnection"), configPath, talosNode)
		if err != nil {
			logger.Error("could not connect to apid", "err", err)

			return errTalosSetupFailed
		}
	} else {
		// Connect to Talos machined
		var err error

		api, err = talosconnection.MachinedConnection(ctx, logger.With("module", "talosconnection"))
		if err != nil {
			logger.Error("could not connect to machined socket", "err", err)

			return errTalosSetupFailed
		}
	}

	hello := fmt.Sprintf("%s © 2020-2025 Oliver Kuckertz, Equinix and Siderolabs", version.Name)
	logger.Info(hello, "version", version.Tag)

	return nil
}

func cleanup(_ *cobra.Command, _ []string) error {
	if api != nil {
		if err := api.Close(); err != nil {
			logger.Warn("failed to close API client during process shutdown", "err", err)

			return err
		}
	}

	return nil
}

func init() {
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(`-`, `_`))
	viper.SetEnvPrefix("vmtoolsd")

	pf := rootCmd.PersistentFlags()
	pf.Bool(flagUseMachined, false, "use machined unix socket instead of TCP")
	pf.String(flagTalosConfig, "", "path to talos config file")
	pf.String(flagTalosNode, "", "talos node to operate on")
	pf.String(flagLogLevel, "info", "log level (error, warning, info, debug, trace)")
	pf.String(flagRPCCmd, "", "RPC command for the hypvervisor")

	if err := viper.BindPFlags(pf); err != nil {
		panic(err)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}
