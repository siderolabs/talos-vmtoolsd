// This file was adapted from govmomi/toolbox's command.go.
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

// Package tboxcmds provides a set of commands for the vmx.
package tboxcmds

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/vmware/govmomi/toolbox/vix"

	"github.com/siderolabs/talos-vmtoolsd/internal/nanotoolbox"
	"github.com/siderolabs/talos-vmtoolsd/internal/version"
)

const (
	// VixToolsFeatureSupportGetHandleState defines the VixToolsFeatureSupportGetHandleState feature.
	VixToolsFeatureSupportGetHandleState = 1
	// VixGuestOfFamilyLinux defines the VixGuestOfFamilyLinux family.
	VixGuestOfFamilyLinux = 1
)

// VixCommandHandler is a function that handles a Vix command.
type VixCommandHandler func(vix.CommandRequestHeader, []byte) ([]byte, error)

// VixDelegate is the interface that must be implemented by the delegate.
type VixDelegate interface {
	OSVersion() string
	OSVersionShort() string
	Hostname() string
}

// VixCommandServer provides a set of commands for the vmx.
type VixCommandServer struct {
	log      logrus.FieldLogger
	out      *nanotoolbox.ChannelOut
	delegate VixDelegate
	handlers map[uint32]VixCommandHandler
}

// RegisterVixCommand registers the Vix command.
func RegisterVixCommand(svc *nanotoolbox.Service, delegate VixDelegate) {
	svr := &VixCommandServer{
		log:      svc.Log.WithField("command", "vix"),
		out:      svc.Out,
		delegate: delegate,
	}
	svr.handlers = map[uint32]VixCommandHandler{vix.CommandGetToolsState: svr.GetToolsState}
	svc.RegisterCommandHandler("Vix_1_Relayed_Command", svr.Dispatch)
}

func commandResult(header vix.CommandRequestHeader, rc int, err error, response []byte) []byte {
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

// Dispatch dispatches the Vix command.
func (c *VixCommandServer) Dispatch(data []byte) ([]byte, error) {
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

	l := c.log.WithField("command_name", name)

	var header vix.CommandRequestHeader

	buf := bytes.NewBuffer(data)

	err := binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		l.WithError(err).Print("decoding command failed")

		return nil, err
	}

	if header.Magic != vix.CommandMagicWord {
		l.Print("invalid magic header for command")

		return commandResult(header, vix.InvalidMessageHeader, nil, nil), nil
	}

	handler, ok := c.handlers[header.OpCode]
	if !ok {
		l.Warn("unhandled command")

		return commandResult(header, vix.UnrecognizedCommandInGuest, nil, nil), nil
	}

	rc := vix.OK

	response, err := handler(header, buf.Bytes())
	if err != nil {
		l.WithError(err).Error("command handler failed")
		rc = vix.ErrorCode(err)
	}

	return commandResult(header, rc, err, response), nil
}

// RegisterHandler registers the Vix command handler.
func (c *VixCommandServer) RegisterHandler(op uint32, handler VixCommandHandler) {
	c.handlers[op] = handler
}

// GetToolsState returns the tools state.
func (c *VixCommandServer) GetToolsState(_ vix.CommandRequestHeader, _ []byte) ([]byte, error) {
	osVersion := c.delegate.OSVersion()
	versionShort := c.delegate.OSVersionShort()
	hostname := c.delegate.Hostname()
	c.log.Debugf("sending tools state version=%q versionShort=%q hostname=%q",
		osVersion, versionShort, hostname)

	props := vix.PropertyList{
		vix.NewStringProperty(vix.PropertyGuestOsVersion, osVersion),
		vix.NewStringProperty(vix.PropertyGuestOsVersionShort, versionShort),
		vix.NewStringProperty(vix.PropertyGuestToolsProductNam, "Talos Tools"),
		vix.NewStringProperty(vix.PropertyGuestToolsVersion, version.Version),
		vix.NewStringProperty(vix.PropertyGuestName, hostname),
		vix.NewInt32Property(vix.PropertyGuestToolsAPIOptions, VixToolsFeatureSupportGetHandleState),
		vix.NewInt32Property(vix.PropertyGuestOsFamily, VixGuestOfFamilyLinux),
	}
	src, _ := props.MarshalBinary() //nolint:errcheck
	enc := base64.StdEncoding
	buf := make([]byte, enc.EncodedLen(len(src)))
	enc.Encode(buf, src)

	return buf, nil
}
