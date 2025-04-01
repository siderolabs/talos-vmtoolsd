// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package hypercall

import (
	"errors"
	"log/slog"
)

type protocol uint32

const (
	// RPCIProto is the protocol number of RPCI (the ASCII characters of 'RPCI').
	RPCIProto protocol = 0x49435052 // RPCI in ASCII
	// TCLOProto is the protocol number of TCLO (the ASCII characters of 'TCLO').
	TCLOProto protocol = 0x4f4c4354 // TCLO in ASCII
)

// Channel models a channel with the hypervisor.
type Channel struct {
	logger   *slog.Logger
	cookie   uint64
	protocol protocol
	id       uint16
}

// Code returns the protocol code.
func (p protocol) Code() uint32 {
	return uint32(p)
}

// String returns the protocol name.
func (p protocol) String() string {
	switch p {
	case RPCIProto:
		return "RPCI"
	case TCLOProto:
		return "TCLO"
	}

	return "UNKNOWN"
}

// NewChannel returns a new channel with given protocol.
func NewChannel(protocol protocol, log *slog.Logger) (*Channel, error) {
	log.Debug("opening channel")

	ch, cookie, err := cmdMsgOpenChannel(protocol)
	if err != nil {
		log.Error("error opening channel", "ch", ch, "cookie", cookie)

		return nil, err
	}

	return &Channel{
		id:       ch,
		cookie:   cookie,
		protocol: protocol,
		logger:   log.With("channel_id", ch, "protocol", protocol.String()),
	}, nil
}

// Close closes the channel gracefully.
func (c *Channel) Close() error {
	c.logger.Debug("closing channel")

	return cmdMsgCloseChannel(c.id, c.cookie)
}

// Send sends data over the channel.
func (c *Channel) Send(data []byte) error {
	c.logger.Debug("send data over channel", "data", string(data))
	c.logger.Debug("sending size", "size", len(data))

	highBW, err := cmdMsgSendSize(c.id, uint32(len(data)), c.cookie)
	if err != nil {
		c.logger.Error("error sending size", "err", err)

		return err
	}

	if len(data) == 0 {
		c.logger.Debug("zero length data, bailing")

		return nil
	}

	for {
		var err error

		c.logger.Debug("sending payload", "data", data)

		if highBW {
			err = cmdMsgSendHighBW(c.id, c.cookie, data)
		} else {
			err = cmdMsgSendLowBW(c.id, c.cookie, data)
		}

		if err == nil {
			return nil
		}

		if errors.Is(err, ErrCheckpoint) {
			c.logger.Debug("error received, bailing out", "err", err)

			return err
		}

		// otherwise, we are checkpointed, retry.
		c.logger.Debug("checkpoint received, retrying")
	}
}

// Receive receives data over the channel.
func (c *Channel) Receive() ([]byte, error) {
	c.logger.Debug("receive data over channel")
	size, highBW, err := cmdMsgReceiveSize(c.id, c.cookie)
	c.logger.Debug("received size", "size", size, "err", err)

	if errors.Is(err, ErrNoDataToReceive) {
		return nil, nil
	}

	if err != nil {
		c.logger.Error("error receiving size", "err", err)

		return nil, err
	}

	var data []byte
	if highBW {
		data, err = cmdMsgReceiveHighBW(c.id, c.cookie, size)
	} else {
		data, err = cmdMsgReceiveLowBW(c.id, c.cookie, size)
	}

	c.logger.Debug("received payload", "data", data, "err", err)

	if err != nil {
		c.logger.Debug("replying with failure")

		if replyErr := cmdMsgReply(c.id, c.cookie, messageTypeReceivePayload, uint16(flagFail)); replyErr != nil {
			c.logger.Warn("error replying with failure", "err", replyErr)
		}

		return nil, err
	}

	c.logger.Debug("replying with success")

	if replyErr := cmdMsgReply(c.id, c.cookie, messageTypeReceiveStatus, uint16(flagSuccess)); replyErr != nil {
		c.logger.Warn("error replying with failure", "err", replyErr)
	}

	return data, nil
}
