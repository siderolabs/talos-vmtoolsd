// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package nanotoolbox

import (
	"log/slog"

	"github.com/siderolabs/talos-vmtoolsd/pkg/hypercall"
)

// TCLO represents a "TCLO" communication interface with the hypervisor.
type TCLO struct {
	channel *hypercall.Channel
	logger  *slog.Logger
}

// TCLOCallBack is a callback function.
type TCLOCallBack func(command string) (reply string, err error)

// NewTCLO creates a new TCLO interface.
func NewTCLO(log *slog.Logger) (*TCLO, error) {
	log.Debug("starting TCLO")

	channel, err := hypercall.NewChannel(hypercall.TCLOProto, log.With("module", "hypercall.Channel"))
	if err != nil {
		return nil, err
	}

	return &TCLO{
		channel: channel,
		logger:  log,
	}, nil
}

// Start starts the TCLO.
func (t *TCLO) Start() error {
	return nil
}

// Stop stops the TCLO.
func (t *TCLO) Stop() error {
	t.logger.Debug("closing TCLO")

	return t.channel.Close()
}

// Send sends data over TCLO.
func (t *TCLO) Send(data []byte) error {
	return t.channel.Send(data)
}

// Receive receives data over TCLO.
func (t *TCLO) Receive() ([]byte, error) {
	return t.channel.Receive()
}
