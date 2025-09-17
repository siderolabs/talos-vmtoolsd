// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/equinix-ms/go-vmw-guestrpc/pkg/hypercall"
	"github.com/equinix-ms/go-vmw-guestrpc/pkg/nanotoolbox"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/siderolabs/talos-vmtoolsd/internal/capcheck"
	"github.com/siderolabs/talos-vmtoolsd/internal/integration"
)

const (
	flagSkipVmwareDetection = "skip-vmware-detection"
)

var vmtoolsdCmd = &cobra.Command{
	Use:   "vmtoolsd",
	Short: "a daemon that responds to requests from vmware",
	Long:  "this daemon listens to vmware and implements stuff like guestinfo, poweroff, etc",
	RunE:  vmtoolsd,
}

var errVMToolsdStartFailed = errors.New("error starting vmtoolsd")

func init() {
	pf := vmtoolsdCmd.PersistentFlags()
	pf.Bool(flagSkipVmwareDetection, false, "skip vmware detection")

	if err := viper.BindPFlags(pf); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(vmtoolsdCmd)
}

func vmtoolsd(_ *cobra.Command, _ []string) error {
	// Simplify deployment to mixed vSphere and non-vSphere clusters by detecting ESXi and stopping
	// early for other platforms. Admins can avoid the overhead of this idle process by labeling
	// all ESXi/vSphere nodes and editing talos-vmtoolsd's DaemonSet to run only on those nodes.
	// VMTOOLSD_SKIP_VMWARE_DETECTION allows bypassing detection, thus avoiding the CAP_SYS_RAWIO requirement.
	if !viper.GetBool(flagSkipVmwareDetection) {
		hascap, err := capcheck.HasCapability(capcheck.CapSysRawio)
		if err != nil {
			logger.Error("error checking capabilities", "err", err)

			return err
		}

		if !hascap {
			logger.Error("we lack CAP_SYS_RAWIO and cannot check safely if we are running in VMWare")

			return fmt.Errorf("lacking capabilities")
		}

		isVMwareVM, err := hypercall.IsVMWareVM()
		switch {
		case errors.Is(err, hypercall.ErrSetPivilegeLevel) && api.SecureBootEnabled():
			// If secure boot is enabled, we can ignore `ErrSetPivilegeLevel` but
			// we still need to check IsVirtual()
			logger.Info("running with secure boot; ignoring privilege level error")

			isVirtual, err2 := hypercall.IsVirtual()
			switch {
			case err2 != nil:
				return err2
			case !isVirtual:
				return fmt.Errorf("we are not running in a virtual machine")
			}
		case err != nil:
			return err
		case !isVMwareVM:
			return fmt.Errorf("not running under VMWare/ESXi")
		}
	} else {
		logger.Info("skipping VMware environment detection")
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
