// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package nanotoolbox

import (
	"bytes"
	"fmt"
	"log/slog"

	"github.com/siderolabs/talos-vmtoolsd/pkg/hypercall"
)

// RPCI models a RPCI communication interface.
type RPCI struct {
	channel *hypercall.Channel
	logger  *slog.Logger
}

var (
	// RpciOK is the return code for a successful RPCI request.
	RpciOK = []byte{'1', ' '}
	// RpciERR is the return code for a failed RPCI request.
	RpciERR = []byte{'0', ' '}
)

// NewRPCI creates a new RPCI instance.
func NewRPCI(log *slog.Logger) (*RPCI, error) {
	log.Debug("starting RPCI")

	channel, err := hypercall.NewChannel(hypercall.RPCIProto, log.With("module", "hypercall.Channel"))
	if err != nil {
		return nil, err
	}

	return &RPCI{
		channel: channel,
		logger:  log,
	}, nil
}

// Request sends an RPC command to the vmx and checks the return code for success or error.
func (r *RPCI) Request(request []byte) ([]byte, error) {
	if r.channel == nil {
		return nil, fmt.Errorf("no channel available for request %q", request)
	}

	if err := r.channel.Send(request); err != nil {
		return nil, err
	}

	reply, err := r.channel.Receive()
	if err != nil {
		return nil, err
	}

	if bytes.HasPrefix(reply, RpciOK) {
		return reply[2:], nil
	}

	return nil, fmt.Errorf("failed request %q: %q", request, reply)
}

// Start starts the RPCI, but this is effectively no-op, as RPCI is only used for initiating communications (it does not listen/wait).
func (r *RPCI) Start() error {
	return nil
}

// Stop closes the RPCI.
func (r *RPCI) Stop() error {
	r.logger.Debug("closing RPCI")

	return r.channel.Close()
}

// Send sends data over RPCI.
func (r *RPCI) Send(data []byte) error {
	return r.channel.Send(data)
}

// Receive receives data over RPCI.
func (r *RPCI) Receive() ([]byte, error) {
	return r.channel.Receive()
}
