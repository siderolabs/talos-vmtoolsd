// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/base64"
	"log/slog"

	"github.com/equinix-ms/go-vmw-guestrpc/pkg/nanotoolbox"
	"github.com/vmware/govmomi/toolbox/vix"

	"github.com/siderolabs/talos-vmtoolsd/internal/talosconnection"
	"github.com/siderolabs/talos-vmtoolsd/internal/version"
	"github.com/siderolabs/talos-vmtoolsd/pkg/vixserver"
)

const (
	vixCommand = "Vix_1_Relayed_Command"
)

const (
	vixToolsFeatureSupportGetHandleState = 1
)

const (
	vixGuestOfFamilyLinux = 1
)

// VIX represents the VIX integration.
type VIX struct {
	talos     *talosconnection.TalosAPIConnection
	logger    *slog.Logger
	service   *nanotoolbox.Service
	vixserver *vixserver.VIXCommandServer
}

// NewVIX constructs the VIX integration.
func NewVIX(logger *slog.Logger, talos *talosconnection.TalosAPIConnection, service *nanotoolbox.Service) *VIX {
	vs := vixserver.New(logger.With("module", "vixserver"), talos)

	logger.Debug("initializing")

	vi := &VIX{
		logger:    logger,
		talos:     talos,
		service:   service,
		vixserver: vs,
	}

	return vi
}

func (v *VIX) handleVIXCommand(data []byte) ([]byte, error) {
	res, err := v.vixserver.Dispatch(data)
	if err != nil {
		v.logger.Error("error dispatching VIX command", "err", err)
	}

	return res, err
}

// Register registers the VIX integration into the service.
func (v *VIX) Register() {
	v.logger.Debug("registering")
	v.service.RegisterCommandHandler(vixCommand, v.handleVIXCommand)
	v.vixserver.RegisterCommand(vixToolsFeatureSupportGetHandleState, v.getToolState)
}

func (v *VIX) getToolState(_ vix.CommandRequestHeader, _ []byte) ([]byte, error) {
	osVersion := v.talos.OSVersion()
	osVersionShort := v.talos.OSVersionShort()
	hostname := v.talos.Hostname()

	v.logger.Debug("sending tool state", "version", osVersion, "short", osVersionShort, "hostname", hostname)

	props := vix.PropertyList{
		vix.NewStringProperty(vix.PropertyGuestOsVersion, osVersion),
		vix.NewStringProperty(vix.PropertyGuestOsVersionShort, osVersionShort),
		vix.NewStringProperty(vix.PropertyGuestToolsProductNam, version.Name),
		vix.NewStringProperty(vix.PropertyGuestToolsVersion, version.Tag),
		vix.NewStringProperty(vix.PropertyGuestName, hostname),
		vix.NewInt32Property(vix.PropertyGuestToolsAPIOptions, vixToolsFeatureSupportGetHandleState),
		vix.NewInt32Property(vix.PropertyGuestOsFamily, vixGuestOfFamilyLinux),
	}

	bin, err := props.MarshalBinary()
	if err != nil {
		v.logger.Warn("error encoding vix props to binary", "err", err)

		return nil, err
	}

	encoder := base64.StdEncoding
	res := make([]byte, encoder.EncodedLen(len(bin)))
	encoder.Encode(res, bin)

	return res, nil
}
