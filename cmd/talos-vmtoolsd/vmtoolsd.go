// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"os/signal"
	"syscall"
	"strconv"

	"github.com/equinix-ms/go-vmw-guestrpc/pkg/hypercall"
	"github.com/equinix-ms/go-vmw-guestrpc/pkg/nanotoolbox"
	"github.com/spf13/cobra"

	"github.com/siderolabs/talos-vmtoolsd/internal/integration"
	"github.com/siderolabs/talos-vmtoolsd/internal/capcheck"
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
	// SKIP_VMWARE_DETECTION allows bypassing detection, thus avoiding the CAP_SYS_RAWIO requirement.
	skipVMwareDetection, _ := strconv.ParseBool(os.Getenv("SKIP_VMWARE_DETECTION"))

	if !skipVMwareDetection {
			// CAP_SYS_RAWIO bit = 17
			if err := capcheck.CheckCapabilities(17); err != nil {
				logger.Error("halting during CAP_SYS_RAWIO check", "err" , err)
				select {}
			}
			if !hypercall.IsVMWareVM() {
				// NB: We cannot simply exit(0) because DaemonSets are always restarted. TODO: or should we? Restarts get noticed, select{} won't
				logger.Error("halting because the current node is not running under ESXi. fair winds!")
				select {}
			}
	}	else {
		logger.Info("Skipping VMware environment detection!")
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
