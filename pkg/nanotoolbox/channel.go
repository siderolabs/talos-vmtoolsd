// This file was adapted from govmomi/toolbox's channel.go and backdoor.go.
// The original copyright notice follows.

// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

// Package nanotoolbox provides a minimal set of tools for communicating with the vmx.
package nanotoolbox

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"

	"github.com/vmware/vmw-guestinfo/message"
	"github.com/vmware/vmw-guestinfo/vmcheck"
)

const (
	rpciProtocol uint32 = 0x49435052
	tcloProtocol uint32 = 0x4f4c4354
)

// ErrNotVirtualWorld is returned when the current process is not running in a virtual world.
var ErrNotVirtualWorld = errors.New("not in a virtual world")

// Channel abstracts the guest<->vmx RPC transport.
type Channel interface {
	Start() error
	Stop() error
	Send([]byte) error
	Receive() ([]byte, error)
}

var (
	// RpciOK is the return code for a successful RPCI request.
	RpciOK = []byte{'1', ' '}
	// RpciERR is the return code for a failed RPCI request.
	RpciERR = []byte{'0', ' '}
)

// ChannelOut extends Channel to provide RPCI protocol helpers.
type ChannelOut struct {
	Channel
}

// Request sends an RPC command to the vmx and checks the return code for success or error.
func (c *ChannelOut) Request(request []byte) ([]byte, error) {
	if c.Channel == nil {
		return nil, fmt.Errorf("no channel available for request %q", request)
	}

	if err := c.Send(request); err != nil {
		return nil, err
	}

	reply, err := c.Receive()
	if err != nil {
		return nil, err
	}

	if bytes.HasPrefix(reply, RpciOK) {
		return reply[2:], nil
	}

	return nil, fmt.Errorf("failed request %q: %q", request, reply)
}

type hypervisorChannel struct { //nolint:govet
	protocol uint32
	logger   *slog.Logger

	*message.Channel
}

func (b *hypervisorChannel) Start() error {
	b.logger.Debug("starting")

	if !vmcheck.IsVirtualCPU() {
		return ErrNotVirtualWorld
	}

	channel, err := message.NewChannel(b.protocol)
	if err != nil {
		return err
	}

	b.Channel = channel

	return nil
}

func (b *hypervisorChannel) Stop() error {
	b.logger.Debug("stopping")

	if b.Channel == nil {
		return nil
	}

	err := b.Channel.Close()

	b.Channel = nil

	return err
}

// NewHypervisorChannelPair returns a pair of channels for communicating with the vmx.
func NewHypervisorChannelPair(logger *slog.Logger) (Channel, Channel) {
	in := &hypervisorChannel{
		protocol: tcloProtocol,
		logger:   logger.With("dir", "in"),
	}
	out := &hypervisorChannel{
		protocol: rpciProtocol,
		logger:   logger.With("dir", "out"),
	}

	return in, out
}
