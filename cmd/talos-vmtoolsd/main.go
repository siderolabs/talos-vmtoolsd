package main

import (
	tvmtoolsd "github.com/mologie/talos-vmtoolsd"
	"github.com/mologie/talos-vmtoolsd/internal/nanotoolbox"
	"github.com/mologie/talos-vmtoolsd/internal/talosapi"
	"github.com/mologie/talos-vmtoolsd/internal/tboxcmds"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	l := log.New(os.Stderr, "", log.LstdFlags)
	l.Printf("talos-vmtoolsd version %v", tvmtoolsd.Version)
	l.Println("Copyright 2020 Oliver Kuckertz <oliver.kuckertz@mologie.de>")
	l.Println("Copyright 2017 VMware, Inc.")
	l.Println("This program is free software and available under the Apache 2.0 license.")

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
	svc := nanotoolbox.NewService(nanotoolbox.NewHypervisorChannelPair())
	svc.Log = l
	api, err := talosapi.NewLocalClient(l, configPath, k8sHost)
	if err != nil {
		l.Fatalf("error: could not connect to apid: %v", err)
	}
	tboxcmds.RegisterGuestInfoCommands(svc, api)
	tboxcmds.RegisterPowerDelegate(svc, api)
	tboxcmds.RegisterVixCommand(svc, api)

	// The toolbox service runs and response to RPC requests in the background.
	if err := svc.Start(); err != nil {
		l.Fatalf("error starting service: %v", err)
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		l.Printf("[main] received signal: %s", <-sig)
		svc.Stop()
	}()
	svc.Wait()
	l.Println("[main] graceful shutdown done, fair winds!")
}
