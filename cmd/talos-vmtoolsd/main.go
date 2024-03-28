// Package main implements the main entry point for the Talos VMware Tools Daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	vmguestmsg "github.com/vmware/vmw-guestinfo/message"
	"github.com/vmware/vmw-guestinfo/vmcheck"

	"github.com/siderolabs/talos-vmtoolsd/internal/nanotoolbox"
	"github.com/siderolabs/talos-vmtoolsd/internal/talosapi"
	"github.com/siderolabs/talos-vmtoolsd/internal/tboxcmds"
	"github.com/siderolabs/talos-vmtoolsd/internal/version"
)

// Debug flags.
var (
	talosTestQuery    string
	useMachinedSocket bool
)

func main() {
	l := logrus.StandardLogger()
	l.SetFormatter(&logrus.JSONFormatter{
		DisableTimestamp:  true,
		DisableHTMLEscape: true,
	})

	flag.StringVar(&talosTestQuery, "test-apid-query", "", "query apid")
	flag.BoolVar(&useMachinedSocket, "use-machined", false, "use machined unix socket")
	flag.Parse()

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
		"Copyright 2020-2022 Oliver Kuckertz <oliver.kuckertz@mologie.de>\n"+
		"This program is free software and available under the Apache 2.0 license.",
		version.Tag)

	// Simplify deployment to mixed vSphere and non-vSphere clusters by detecting ESXi and stopping
	// early for other platforms. Admins can avoid the overhead of this idle process by labeling
	// all ESXi/vSphere nodes and editing talos-vmtoolsd's DaemonSet to run only on those nodes.
	if !vmcheck.IsVirtualCPU() {
		// NB: We cannot simply exit(0) because DaemonSets are always restarted.
		l.Info("halting because the current node is not running under ESXi. fair winds!")
		select {}
	}

	ctx, ctxCancel := context.WithCancel(context.Background())

	var (
		api *talosapi.LocalClient
		err error
	)

	if !useMachinedSocket {
		// Our spec file passes the secret path and K8s host IP via env vars.
		configPath := os.Getenv("TALOS_CONFIG_PATH")
		if len(configPath) == 0 {
			l.Fatal("error: TALOS_CONFIG_PATH is a required path to a Talos configuration file")
		}

		k8sHost := os.Getenv("TALOS_HOST")
		if len(k8sHost) == 0 {
			l.Fatal("error: TALOS_HOST is required to point to a node's internal IP")
		}

		// Connect to Talos apid
		api, err = talosapi.NewLocalClient(ctx, l, configPath, k8sHost)
		if err != nil {
			l.WithError(err).Fatal("could not connect to apid")
		}
	} else {
		// Connect to Talos machined
		api, err = talosapi.NewLocalSocketClient(ctx, l)
		if err != nil {
			l.WithError(err).Fatal("could not connect to machined socket")
		}
	}

	defer func() {
		if err := api.Close(); err != nil {
			l.WithError(err).Warn("failed to close API client during process shutdown")
		}
	}()

	// Manual test query mode for Talos apid client
	if talosTestQuery != "" {
		if err := testQuery(api, talosTestQuery); err != nil {
			l.WithField("test_query", talosTestQuery).WithError(err).Fatal("test query failed")

			os.Exit(1) //nolint:gocritic
		}

		os.Exit(0)
	}

	// Wires up VMware Toolbox commands to Talos apid.
	vmguestmsg.DefaultLogger = l.WithField("module", "vmware-guestinfo")
	rpcIn, rpcOut := nanotoolbox.NewHypervisorChannelPair()
	svc := nanotoolbox.NewService(l, rpcIn, rpcOut)
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
		ctxCancel()
		svc.Stop()
	}()
	svc.Wait()
	l.Info("graceful shutdown done, fair winds!")
}

func testQuery(api *talosapi.LocalClient, query string) error {
	w := os.Stdout

	switch query {
	case "net-interfaces":
		for idx, intf := range api.NetInterfaces() {
			for _, addr := range intf.Addrs {
				_, _ = fmt.Fprintf(w, "%d: name=%s mac=%s addr=%s\n", idx, intf.Name, intf.MAC, addr)
			}
		}

		return nil
	case "hostname":
		_, _ = fmt.Fprintln(w, api.Hostname())

		return nil
	case "os-version":
		_, _ = fmt.Fprintln(w, api.OSVersion())

		return nil
	case "os-version-short":
		_, _ = fmt.Fprintln(w, api.OSVersionShort())

		return nil
	default:
		return fmt.Errorf("unknown test query %q", query)
	}
}
