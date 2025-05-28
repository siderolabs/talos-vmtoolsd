// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package hypercall

// this file contains the low-level commands to interface with the hypervisor

import (
	"bytes"
	"errors"
	"fmt"
	"unsafe"
)

const (
	noVersion uint32 = 0xffffffff
)

const (
	commandHighBandwidthMessage uint16 = 0x00
	commandGetMHz               uint16 = 0x01
	commandGetVersion           uint16 = 0x0a
	commandMessage              uint16 = 0x1e
)

const (
	messageTypeOpen           uint16 = 0x0000
	messageTypeSendSize       uint16 = 0x0001
	messageTypeSendPayload    uint16 = 0x0002 // only used for low-bandwidth
	messageTypeReceiveSize    uint16 = 0x0003
	messageTypeReceivePayload uint16 = 0x0004
	messageTypeReceiveStatus  uint16 = 0x0005
	messageTypeClose          uint16 = 0x0006
)

const (
	flagFail          uint32 = 0x00000000
	flagSuccess       uint32 = 0x00000001
	flagDoReceive     uint32 = 0x00000002
	flagCheckpoint    uint32 = 0x00000010
	flagHighBandwidth uint32 = 0x00000080
	flagCookie        uint32 = 0x80000000
)

var (
	magicMismatchStr = fmt.Sprintf("returned magic does not match, expected 0x%08x", vxMagic)
	// ErrMagicMismatch indicates that the magic received does not match.
	ErrMagicMismatch = errors.New(magicMismatchStr)

	// ErrOpeningChannel is returned when opening a channel went wrong.
	ErrOpeningChannel = errors.New("error opening channel")

	// ErrClosingChannel is returned when closing a channel went wrong.
	ErrClosingChannel = errors.New("error closing channel")

	// ErrSendingSize is for indicating sending payload size went wrong.
	ErrSendingSize = errors.New("error sending size")

	// ErrHighBWExpected is not really an error, but to flag payload is sent/received using high bandwidth.
	ErrHighBWExpected = errors.New("high bandwidth expected")

	// ErrCheckpoint is to signal that a checkpoint occurred, whatever that may be.
	ErrCheckpoint = errors.New("a checkpoint occurred")

	// ErrReceivingSize means that we did not receive the payload size properly.
	ErrReceivingSize = errors.New("error receiving size")

	// ErrNoDataToReceive is returned when there is no data to received.
	ErrNoDataToReceive = errors.New("no data to receive")

	// ErrExpectedSendSize tells that we expected a message of type sendsize.
	ErrExpectedSendSize = errors.New("message of type MESSAGE_TYPE_SENDSIZE expected")

	// ErrUnableToReply is returned when we were unable to reply to a message.
	ErrUnableToReply = errors.New("unable to reply to a message")

	// ErrSendPayload is returned when we were unable to send the payload.
	ErrSendPayload = errors.New("error sending payload")

	// ErrReceivePayload is returned when we were unable to receive the payload.
	ErrReceivePayload = errors.New("error receiving payload")

	// ErrPayloadExpected means that we expected payload, but did not get it.
	ErrPayloadExpected = errors.New("payload expected")
)

func joinCookie(c1, c2 uint32) uint64 {
	return uint64(c1)<<32 | uint64(c2)
}

func splitCookie(c uint64) (uint32, uint32) {
	return uint32(c >> 32), uint32(c & 0xffffffff)
}

func bitIsSet(v uint16, mask uint32) bool {
	return (uint32(v) & mask) == mask
}

// GetVersion fetches version of the hypervisor. Returns the version and product type.
func GetVersion() (uint32, uint32, error) {
	f := StackFrame{}
	f.CX.AsUInt32().Low = commandGetVersion
	f.LowBWInOut()

	version := f.AX.AsUInt32().Word()
	product := f.CX.AsUInt32().Word()
	magic := f.BX.AsUInt32().Word()

	if magic != vxMagic {
		return version, product, ErrMagicMismatch
	}

	return version, product, nil
}

// IsVirtual tells you if you are running virtual or not. Beware that the backdoor might involve a privileged instruction, causing a SEGFAULT on non-ESXI.
func IsVirtual() bool {
	version, _, err := GetVersion()
	if err != nil {
		return false
	}

	if version == noVersion {
		return false
	}

	return true
}

// GetProcessorMHz returns the speed of the CPU clock.
func GetProcessorMHz() uint32 {
	f := StackFrame{}
	f.CX.AsUInt32().Low = commandGetMHz

	f.LowBWInOut()

	return f.AX.AsUInt32().Word()
}

// cmdMsgOpenChannel opens a communication channel in the given protocol. The "give me cookie" flag is always set, because we want a cookie.
func cmdMsgOpenChannel(protocol protocol) (uint16, uint64, error) {
	f := StackFrame{}
	f.BX.AsUInt32().SetWord(protocol.Code() | flagCookie)

	f.CX.AsUInt32().Low = commandMessage
	f.CX.AsUInt32().High = messageTypeOpen

	f.LowBWInOut()

	status := f.CX.AsUInt32().High
	channel := f.DX.AsUInt32().High
	c1 := f.SI.AsUInt32().Word()
	c2 := f.DI.AsUInt32().Word()

	cookie := joinCookie(c1, c2)

	if !bitIsSet(status, flagSuccess) {
		return 0, 0, ErrOpeningChannel
	}

	return channel, cookie, nil
}

// cmdMsgCloseChannel closes a communication channel in the given protocol.
func cmdMsgCloseChannel(channel uint16, cookie uint64) error {
	c1, c2 := splitCookie(cookie)

	f := StackFrame{}
	f.CX.AsUInt32().High = messageTypeClose
	f.CX.AsUInt32().Low = commandMessage
	f.DX.AsUInt32().High = channel
	f.SI.AsUInt32().SetWord(c1)
	f.DI.AsUInt32().SetWord(c2)
	f.LowBWInOut()

	status := f.CX.AsUInt32().High

	if !bitIsSet(status, flagSuccess) {
		return ErrClosingChannel
	}

	return nil
}

// cmdMsgReply sends a reply to a received message.
func cmdMsgReply(channel uint16, cookie uint64, messageType uint16, setStatus uint16) error {
	c1, c2 := splitCookie(cookie)

	f := StackFrame{}
	f.BX.AsUInt32().Low = setStatus
	f.CX.AsUInt32().High = messageType
	f.CX.AsUInt32().Low = commandMessage
	f.DX.AsUInt32().High = channel
	f.SI.AsUInt32().SetWord(c1)
	f.DI.AsUInt32().SetWord(c2)

	f.LowBWInOut()

	status := f.CX.AsUInt32().High

	if !bitIsSet(status, flagSuccess) {
		return ErrUnableToReply
	}

	return nil
}

// cmdMsgSendSize sends the size of a message over an already opened
// communication channel. Returns the "high bandwidth" flag.
func cmdMsgSendSize(channel uint16, size uint32, cookie uint64) (bool, error) {
	c1, c2 := splitCookie(cookie)

	f := StackFrame{}
	f.BX.AsUInt32().SetWord(size)

	f.CX.AsUInt32().High = messageTypeSendSize
	f.CX.AsUInt32().Low = commandMessage
	f.DX.AsUInt32().High = channel

	f.SI.AsUInt32().SetWord(c1)
	f.DI.AsUInt32().SetWord(c2)

	f.LowBWInOut()

	status := f.CX.AsUInt32().High

	if !bitIsSet(status, flagSuccess) {
		return false, ErrSendingSize
	}

	return bitIsSet(status, flagHighBandwidth), nil
}

// cmdMsgSendLowBW sends the message payload in the low bandwidth way.
func cmdMsgSendLowBW(channel uint16, cookie uint64, data []byte) error {
	c1, c2 := splitCookie(cookie)

	f := StackFrame{}
	f.BX.AsUInt32().SetWord(uint32(len(data)))

	f.CX.AsUInt32().High = messageTypeSendPayload
	f.DX.AsUInt32().High = channel

	f.SI.AsUInt32().SetWord(c1)
	f.DI.AsUInt32().SetWord(c2)

	buf := bytes.NewBuffer(data)

	for {
		chunk := buf.Next(4)

		if len(chunk) == 0 {
			break
		}

		word := uint32(0)
		for i, b := range chunk {
			word |= uint32(b << byte(i*8))
		}

		f.BX.AsUInt32().SetWord(word)
		f.LowBWInOut()

		status := f.CX.AsUInt32().High

		if !bitIsSet(status, flagSuccess) {
			return ErrSendPayload
		}
	}

	return nil
}

// cmdMsgSendHighBW sends the message payload in the high bandwidth way.
func cmdMsgSendHighBW(channel uint16, cookie uint64, data []byte) error {
	c1, c2 := splitCookie(cookie)

	f := StackFrame{}
	f.BX.AsUInt32().Low = commandHighBandwidthMessage
	f.BX.AsUInt32().High = uint16(flagSuccess)

	f.CX.AsUInt32().SetWord(uint32(len(data)))

	f.DX.AsUInt32().High = channel

	f.SI.SetPointer(unsafe.Pointer(&data[0]))
	f.DI.AsUInt32().SetWord(c2)
	f.BP.AsUInt32().SetWord(c1)

	f.HighBWOut()

	status := f.BX.AsUInt32().High

	if !bitIsSet(status, flagSuccess) {
		return ErrSendPayload
	}

	if bitIsSet(status, flagCheckpoint) {
		return ErrCheckpoint
	}

	return nil
}

// cmdMsgReceiveSize checks if there is a message to receive, and retrieves its
// size and if the payload is going to be retrieved over "high bandwidth".
func cmdMsgReceiveSize(channel uint16, cookie uint64) (uint32, bool, error) {
	c1, c2 := splitCookie(cookie)

	f := StackFrame{}
	f.CX.AsUInt32().High = messageTypeReceiveSize
	f.CX.AsUInt32().Low = commandMessage
	f.DX.AsUInt32().High = channel

	f.SI.AsUInt32().SetWord(c1)
	f.DI.AsUInt32().SetWord(c2)

	f.LowBWInOut()

	status := f.CX.AsUInt32().High
	typ := f.DX.AsUInt32().High
	size := f.BX.AsUInt32().Word()

	if !bitIsSet(status, flagSuccess) {
		return 0, false, ErrReceivingSize
	}

	if !bitIsSet(status, flagDoReceive) {
		return 0, false, ErrNoDataToReceive
	}

	if typ != messageTypeSendSize {
		return 0, false, ErrExpectedSendSize
	}

	return size, bitIsSet(status, flagHighBandwidth), nil
}

// cmdMsgReceiveLowBW sends the message payload in the low bandwidth way.
func cmdMsgReceiveLowBW(channel uint16, cookie uint64, size uint32) ([]byte, error) {
	c1, c2 := splitCookie(cookie)

	f := StackFrame{}

	f.DX.AsUInt32().High = channel

	f.SI.AsUInt32().SetWord(c1)
	f.DI.AsUInt32().SetWord(c2)

	buf := new(bytes.Buffer)

	for {
		want := int(min(4, size-uint32(buf.Len())))

		if want <= 0 {
			break
		}

		f.BX.AsUInt32().Low = uint16(flagSuccess)
		f.CX.AsUInt32().High = messageTypeReceivePayload

		f.LowBWInOut()

		status := f.CX.AsUInt32().High

		if !bitIsSet(status, flagCheckpoint) {
			return nil, ErrCheckpoint
		}

		if !bitIsSet(status, flagSuccess) {
			return nil, ErrReceivePayload
		}

		word := f.BX.AsUInt32().Value()

		for range want {
			buf.WriteByte(uint8(word & 0xff))
			word >>= 8
		}
	}

	return buf.Bytes(), nil
}

// cmdMsgReceiveHighBW receives the message payload over the high bandwidth channel.
func cmdMsgReceiveHighBW(channel uint16, cookie uint64, size uint32) ([]byte, error) {
	c1, c2 := splitCookie(cookie)

	data := make([]byte, size)

	f := StackFrame{}

	f.BX.AsUInt32().Low = commandHighBandwidthMessage
	f.BX.AsUInt32().High = uint16(flagSuccess)

	f.CX.AsUInt32().SetWord(uint32(len(data)))

	f.DX.AsUInt32().High = channel

	f.SI.AsUInt32().SetWord(c1)
	f.DI.SetPointer(unsafe.Pointer(&data[0]))
	f.BP.AsUInt32().SetWord(c2)

	f.HighBWIn()

	status := f.BX.AsUInt32().High

	if !bitIsSet(status, flagSuccess) {
		return nil, ErrReceivePayload
	}

	return data, nil
}
