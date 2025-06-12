// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"fmt"
	"log/slog"

	"github.com/equinix-ms/go-vmw-guestrpc/pkg/nanotoolbox"

	"github.com/siderolabs/talos-vmtoolsd/internal/talosconnection"
)

// Power represents the power integration (shutdown/reboot/etc.)
type Power struct {
	talos   *talosconnection.TalosAPIConnection
	logger  *slog.Logger
	service *nanotoolbox.Service
}

type powerState int

// vmware/guestrpc/powerops.h.
const (
	_ powerState = iota
	pwrHaltID
	pwrRebootID
	pwrPowerOnID
	pwrResumeID
	pwrSuspendID
)

var pwrStates = map[powerState]string{
	pwrHaltID:    "OS_Halt",
	pwrRebootID:  "OS_Reboot",
	pwrPowerOnID: "OS_PowerOn",
	pwrResumeID:  "OS_Resume",
	pwrSuspendID: "OS_Suspend",
}

func (p powerState) Name() string {
	return pwrStates[p]
}

// powerHandler is the type of the function that handles power operations.
type powerHandler func() error

// no-op power operation.
func noop() error {
	return nil
}

// NewPower creates a new power integration.
func NewPower(logger *slog.Logger, talos *talosconnection.TalosAPIConnection, service *nanotoolbox.Service) *Power {
	logger.Debug("initializing")

	p := &Power{
		logger:  logger,
		talos:   talos,
		service: service,
	}

	return p
}

// template function that "creates" a power operation. It basically wraps powerFn.
func (p *Power) makePowerHandler(ps powerState, powerFn powerHandler) (string, nanotoolbox.CommandHandler) {
	return ps.Name(), func([]byte) ([]byte, error) {
		l := p.logger.With("power_op", ps.Name())
		l.Debug("handling power operation")

		rc := nanotoolbox.RpciOK

		if err := powerFn(); err != nil {
			l.Error("error handling power operation", "err", err)

			rc = nanotoolbox.RpciERR
		}

		msg := fmt.Sprintf("tools.os.statechange.status %s%d\x00", rc, int(ps))
		if _, err := p.service.Request([]byte(msg)); err != nil {
			return nil, fmt.Errorf("error sending %q: %w", msg, err)
		}

		return nil, nil
	}
}

// Register registers the power integration into the service.
func (p *Power) Register() {
	p.logger.Debug("registering")
	p.service.AddCapability("tools.capability.statechange")
	p.service.AddCapability("tools.capability.softpowerop_retry")
	p.service.RegisterCommandHandler(p.makePowerHandler(pwrHaltID, p.talos.Shutdown))
	p.service.RegisterCommandHandler(p.makePowerHandler(pwrRebootID, p.talos.Reboot))
	p.service.RegisterCommandHandler(p.makePowerHandler(pwrPowerOnID, noop))
	p.service.RegisterCommandHandler(p.makePowerHandler(pwrSuspendID, noop))
	p.service.RegisterCommandHandler(p.makePowerHandler(pwrResumeID, noop))
}
