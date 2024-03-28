// This file was adapted from govmomi/toolbox's channel.go and backdoor.go.
// The original copyright notice follows.

/*
Copyright (c) 2017 VMware, Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package nanotoolbox provides a minimal set of tools for communicating with the vmx.
package nanotoolbox

import (
	"bytes"
	"errors"
	"fmt"

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

	*message.Channel
}

func (b *hypervisorChannel) Start() error {
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
	if b.Channel == nil {
		return nil
	}

	err := b.Channel.Close()

	b.Channel = nil

	return err
}

// NewHypervisorChannelPair returns a pair of channels for communicating with the vmx.
func NewHypervisorChannelPair() (Channel, Channel) {
	in := &hypervisorChannel{protocol: tcloProtocol}
	out := &hypervisorChannel{protocol: rpciProtocol}

	return in, out
}
