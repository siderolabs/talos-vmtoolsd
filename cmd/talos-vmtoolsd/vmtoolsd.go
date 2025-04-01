// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/siderolabs/talos-vmtoolsd/internal/integration"
	"github.com/siderolabs/talos-vmtoolsd/pkg/hypercall"
	"github.com/siderolabs/talos-vmtoolsd/pkg/nanotoolbox"
)

var vmtoolsdCmd = &cobra.Command{
	Use:   "vmtoolsd",
	Short: "a daemon that responds to requests from vmware",
	Long:  "this daemon listens to vmware and implements stuff like guestinfo, poweroff, etc",
	RunE:  vmtoolsd,
}

var errVMToolsdStartFailed = errors.New("error starting vmtoolsd")

func init() {
	rootCmd.AddCommand(vmtoolsdCmd)
}

func vmtoolsd(_ *cobra.Command, _ []string) error {
	// Simplify deployment to mixed vSphere and non-vSphere clusters by detecting ESXi and stopping
	// early for other platforms. Admins can avoid the overhead of this idle process by labeling
	// all ESXi/vSphere nodes and editing talos-vmtoolsd's DaemonSet to run only on those nodes.
	if !hypercall.IsVirtual() {
		// NB: We cannot simply exit(0) because DaemonSets are always restarted. TODO: or should we? Restarts get noticed, select{} won't
		logger.Error("halting because the current node is not running under ESXi. fair winds!")
		select {}
	}

	rpci, err := nanotoolbox.NewRPCI(logger.With("module", "RPCI"))
	if err != nil {
		return err
	}

	tclo, err := nanotoolbox.NewTCLO(logger.With("module", "TCLO"))
	if err != nil {
		return err
	}

	svc := nanotoolbox.NewService(logger.With("module", "nanotoolbox.service"), rpci, tclo)

	integrations := []integration.Integration{
		integration.NewPower(logger.With("integration", "power"), api, svc),
		integration.NewGuestInfo(logger.With("integration", "guestinfo"), api, svc),
		integration.NewVIX(logger.With("integration", "vix"), api, svc),
	}

	for _, i := range integrations {
		i.Register()
	}

	// The toolbox service runs and response to RPC requests in the background.
	if err := svc.Start(); err != nil {
		logger.Error("error starting service", "err", err)

		return errVMToolsdStartFailed
	}

	// Graceful shutdown on SIGINT/SIGTERM
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Debug("signal received", "signal", <-sig)
		ctxCancel()
		svc.Stop()
	}()
	svc.Wait()
	logger.Info("graceful shutdown done, fair winds!")

	return nil
}
