// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

// Package talosconnection represents the connection to the Talos API.
package talosconnection

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/siderolabs/talos/pkg/grpc/middleware/authz"
	talosclient "github.com/siderolabs/talos/pkg/machinery/client"
	talosconfig "github.com/siderolabs/talos/pkg/machinery/client/config"
	talosconstants "github.com/siderolabs/talos/pkg/machinery/constants"
	talosrole "github.com/siderolabs/talos/pkg/machinery/role"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// TalosAPIConnection represents the Talos API client.
type TalosAPIConnection struct {
	ctx    context.Context //nolint:containedctx
	log    *slog.Logger
	client *talosclient.Client
}

// Close closes the client.
func (c *TalosAPIConnection) Close() error {
	return c.client.Close()
}

// RemoteApidConnection is used for using a TCP/gRPC connection to apid.
func RemoteApidConnection(ctx context.Context, logger *slog.Logger, configPath string, node string) (*TalosAPIConnection, error) {
	cfg, err := talosconfig.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file %q: %w", configPath, err)
	}

	logger.Debug("setting up talos connection to apid", "configfile", configPath, "node", node)

	client, err := talosclient.New(ctx,
		talosclient.WithConfig(cfg),
		talosclient.WithEndpoints(node),
	)
	if err != nil {
		logger.Error("could not setup connection", "err", err)
	}

	conn := &TalosAPIConnection{
		ctx:    ctx,
		log:    logger,
		client: client,
	}

	return conn, nil
}

// MachinedConnection is used for using a connection to machined using local UNIX socket.
func MachinedConnection(ctx context.Context, logger *slog.Logger) (*TalosAPIConnection, error) {
	logger.Debug("setting up talos connection to machined", "socket", talosconstants.MachineSocketPath)

	md := metadata.Pairs()
	authz.SetMetadata(md, talosrole.MakeSet(talosrole.Admin))
	adminCtx := metadata.NewOutgoingContext(ctx, md)

	client, err := talosclient.New(adminCtx,
		talosclient.WithUnixSocket(talosconstants.MachineSocketPath),
		talosclient.WithGRPCDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	if err != nil {
		logger.Error("could not setup connection", "err", err)
	}

	conn := &TalosAPIConnection{
		ctx:    adminCtx,
		log:    logger,
		client: client,
	}

	return conn, nil
}
