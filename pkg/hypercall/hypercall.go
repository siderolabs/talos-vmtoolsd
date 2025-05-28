// SPDX-FileCopyrightText: Copyright (c) 2020 Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package hypercall

import "fmt"

const (
	portLowBW  = uint16(0x5658)
	portHighBW = uint16(0x5659)
	vxMagic    = uint32(0x564D5868)
)

// the definition of Stackframe is arch specific, so these are in _amd64.go, _i386.go and _arm64.go

// String converts the stackframe to string, useful for debugging.
func (s *StackFrame) String() string {
	return fmt.Sprintf("ax=%8x bx=%8x cx=%8x dx=%8x si=%8x di=%8x bp=%x", s.AX.Value(), s.BX.Value(), s.CX.Value(), s.DX.Value(), s.SI.Value(), s.DI.Value(), s.BP.Value())
}

// LowBWInOut implements the "low-bandwidth" (ie, single word stackframe) interface with the hypervisor.
// It sends and receives a single stackframe.
func (s *StackFrame) LowBWInOut() {
	s.DX.AsUInt32().Low = portLowBW
	s.AX.AsUInt32().SetValue(vxMagic)

	retax, retbx, retcx, retdx, retsi, retdi, retbp := bdoorLBInOut(
		s.AX.Value(),
		s.BX.Value(),
		s.CX.Value(),
		s.DX.Value(),
		s.SI.Value(),
		s.DI.Value(),
		s.BP.Value(),
	)

	s.AX.SetValue(retax)
	s.BX.SetValue(retbx)
	s.CX.SetValue(retcx)
	s.DX.SetValue(retdx)
	s.SI.SetValue(retsi)
	s.DI.SetValue(retdi)
	s.BP.SetValue(retbp)
}

// HighBWOut implements the "high-bandwidth" (ie, repeat sending a word) interface with the hypervisor.
func (s *StackFrame) HighBWOut() {
	s.DX.AsUInt32().Low = portHighBW
	s.AX.AsUInt32().SetValue(vxMagic)

	retax, retbx, retcx, retdx, retsi, retdi, retbp := bdoorHBOut(
		s.AX.Value(),
		s.BX.Value(),
		s.CX.Value(),
		s.DX.Value(),
		s.SI.Value(),
		s.DI.Value(),
		s.BP.Value(),
	)

	s.AX.SetValue(retax)
	s.BX.SetValue(retbx)
	s.CX.SetValue(retcx)
	s.DX.SetValue(retdx)
	s.SI.SetValue(retsi)
	s.DI.SetValue(retdi)
	s.BP.SetValue(retbp)
}

// HighBWIn implements the "high-bandwidth" (ie, repeat receiving a word) interface with the hypervisor.
func (s *StackFrame) HighBWIn() {
	s.DX.AsUInt32().Low = portHighBW
	s.AX.AsUInt32().SetValue(vxMagic)
	retax, retbx, retcx, retdx, retsi, retdi, retbp := bdoorHBIn(
		s.AX.Value(),
		s.BX.Value(),
		s.CX.Value(),
		s.DX.Value(),
		s.SI.Value(),
		s.DI.Value(),
		s.BP.Value(),
	)

	s.AX.SetValue(retax)
	s.BX.SetValue(retbx)
	s.CX.SetValue(retcx)
	s.DX.SetValue(retdx)
	s.SI.SetValue(retsi)
	s.DI.SetValue(retdi)
	s.BP.SetValue(retbp)
}
