package main

import (
	vmtoolsd "github.com/mologie/talos-vmtoolsd"
	"github.com/mologie/talos-vmtoolsd/internal/nanotoolbox"
	"github.com/mologie/talos-vmtoolsd/internal/talosapi"
	"github.com/mologie/talos-vmtoolsd/internal/tboxcmds"
	"github.com/sirupsen/logrus"
	vmguestmsg "github.com/vmware/vmw-guestinfo/message"
	"github.com/vmware/vmw-guestinfo/vmcheck"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	l := logrus.StandardLogger()
	l.SetFormatter(&logrus.JSONFormatter{
		DisableTimestamp:  true,
		DisableHTMLEscape: true,
	})

	// Apply log level, default to "info"
	if levelStr, ok := os.LookupEnv("LOG_LEVEL"); ok {
		if level, err := logrus.ParseLevel(levelStr); err != nil {
			l.WithError(err).Fatal("error parsing log level")
		} else {
			l.SetLevel(level)
		}
	} else {
		l.SetLevel(logrus.InfoLevel)
	}

	l.Infof("talos-vmtoolsd version %v\n"+
		"Copyright 2020-2021 Oliver Kuckertz <oliver.kuckertz@mologie.de>\n"+
		"This program is free software and available under the Apache 2.0 license.",
		vmtoolsd.Version)

	// Simplify deployment to mixed vSphere and non-vSphere clusters by detecting ESXi and stopping
	// early for other platforms. Admins can avoid the overhead of this idle process by labeling
	// all ESXi/vSphere nodes and editing talos-vmtoolsd's DaemonSet to run only on those nodes.
	if !vmcheck.IsVirtualCPU() {
		// NB: We cannot simply exit(0) because DaemonSets are always restarted.
		l.Info("halting because the current node is not running under ESXi. fair winds!")
		select {}
	}

	// Our spec file passes the secret path and K8s host IP via env vars.
	configPath := os.Getenv("TALOS_CONFIG_PATH")
	if len(configPath) == 0 {
		l.Fatal("error: TALOS_CONFIG_PATH is a required path to a Talos configuration file")
	}
	k8sHost := os.Getenv("TALOS_HOST")
	if len(k8sHost) == 0 {
		l.Fatal("error: TALOS_HOST is required to point to a node's internal IP")
	}

	// Wires up VMware Toolbox commands to Talos apid.
	vmguestmsg.DefaultLogger = l.WithField("module", "vmware-guestinfo")
	rpcIn, rpcOut := nanotoolbox.NewHypervisorChannelPair()
	svc := nanotoolbox.NewService(l, rpcIn, rpcOut)
	api, err := talosapi.NewLocalClient(l, configPath, k8sHost)
	if err != nil {
		l.WithError(err).Fatal("could not connect to apid")
	}
	defer func() {
		if err := api.Close(); err != nil {
			l.WithError(err).Warn("failed to close API client during process shutdown")
		}
	}()
	tboxcmds.RegisterGuestInfoCommands(svc, api)
	tboxcmds.RegisterPowerDelegate(svc, api)
	tboxcmds.RegisterVixCommand(svc, api)

	// The toolbox service runs and response to RPC requests in the background.
	if err := svc.Start(); err != nil {
		l.WithError(err).Fatal("error starting service")
	}

	// Graceful shutdown on SIGINT/SIGTERM
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		l.Debugf("signal: %s", <-sig)
		svc.Stop()
	}()
	svc.Wait()
	l.Info("graceful shutdown done, fair winds!")
}
