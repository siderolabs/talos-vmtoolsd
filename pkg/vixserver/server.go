// This file was adapted from govmomi/toolbox's command.go.
// The original copyright notice follows.

// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

// Package vixserver is a "VIX Command Server", it dispatches so called vix commands. It was adapted from govmomi's command.go.
package vixserver

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"

	"github.com/vmware/govmomi/toolbox/vix"

	"github.com/siderolabs/talos-vmtoolsd/internal/talosconnection"
)

type vixCommandHandler func(vix.CommandRequestHeader, []byte) ([]byte, error)

// VIXCommandServer is the command server itself.
type VIXCommandServer struct {
	logger   *slog.Logger
	talos    *talosconnection.TalosAPIConnection
	registry map[uint32]vixCommandHandler
}

// New constructs a fresh command server.
func New(logger *slog.Logger, talos *talosconnection.TalosAPIConnection) *VIXCommandServer {
	v := &VIXCommandServer{
		logger:   logger,
		talos:    talos,
		registry: make(map[uint32]vixCommandHandler),
	}

	return v
}

// createVIXCommandResult is a convinience function that builds a VIX command result.
// it is adapted from govmomi's commandResult().
func createVIXCommandResult(header vix.CommandRequestHeader, rc int, err error, response []byte) []byte {
	// All Foundry tools commands return results that start with a foundry error
	// and a guest-OS-specific error (e.g. errno)
	errno := 0

	if err != nil {
		response = []byte(err.Error())
	}

	buf := bytes.NewBufferString(fmt.Sprintf("%d %d ", rc, errno))

	if header.CommonFlags&vix.CommandGuestReturnsBinary != 0 {
		// '#' delimits end of ascii and the start of the binary data (see ToolsDaemonTcloReceiveVixCommand)
		_ = buf.WriteByte('#')
	}

	_, _ = buf.Write(response)

	if header.CommonFlags&vix.CommandGuestReturnsBinary == 0 {
		// this is not binary data, so it should be a NULL terminated string (see ToolsDaemonTcloReceiveVixCommand)
		_ = buf.WriteByte(0)
	}

	return buf.Bytes()
}

// Dispatch dispatches a VIX command from toolbox. It is copied verbatim from govmomi.
func (v *VIXCommandServer) Dispatch(data []byte) ([]byte, error) {
	// See ToolsDaemonTcloGetQuotedString
	if data[0] == '"' {
		data = data[1:]
	}

	name := ""

	ix := bytes.IndexByte(data, '"')
	if ix > 0 {
		name = string(data[:ix])
		data = data[ix+1:]
	}

	if data[0] == 0 {
		data = data[1:]
	}

	l := v.logger.With("command_name", name)

	var header vix.CommandRequestHeader

	buf := bytes.NewBuffer(data)

	err := binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		l.Error("decoding command failed", "err", err)

		return nil, err
	}

	if header.Magic != vix.CommandMagicWord {
		l.Error("invalid magic header for command", "magic", header.Magic)

		return createVIXCommandResult(header, vix.InvalidMessageHeader, nil, nil), nil
	}

	handler, ok := v.registry[header.OpCode]
	if !ok {
		l.Debug("unhandled command") // debug level, as ESX issues way more commands than we care for

		return createVIXCommandResult(header, vix.UnrecognizedCommandInGuest, nil, nil), nil
	}

	rc := vix.OK

	response, err := handler(header, buf.Bytes())
	if err != nil {
		l.Error("command handler failed", "err", err)
		rc = vix.ErrorCode(err)
	}

	return createVIXCommandResult(header, rc, err, response), nil
}

// RegisterCommand registers a VIX command.
func (v *VIXCommandServer) RegisterCommand(command uint32, handler vixCommandHandler) {
	v.logger.Info("registering vix command", "command", command)
	v.registry[command] = handler
}
