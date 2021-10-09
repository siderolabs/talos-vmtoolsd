package main

import (
	tvmtoolsd "github.com/mologie/talos-vmtoolsd"
	"github.com/mologie/talos-vmtoolsd/internal/nanotoolbox"
	"github.com/mologie/talos-vmtoolsd/internal/talosapi"
	"github.com/mologie/talos-vmtoolsd/internal/tboxcmds"
	"github.com/sirupsen/logrus"
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
		tvmtoolsd.Version)

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
