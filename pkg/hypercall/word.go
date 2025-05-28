// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

// This file was copied from (archived) https://github.com/vmware-archive/vmw-guestinfo/

package hypercall

import "unsafe"

// UInt32 is an unsigned 32-bit word/integer.
type UInt32 struct {
	High uint16
	Low  uint16
}

// Word returns the uint32 as a single word.
func (u *UInt32) Word() uint32 {
	return uint32(u.High)<<16 + uint32(u.Low)
}

// SetWord sets value using a single word.
func (u *UInt32) SetWord(w uint32) {
	u.High = uint16(w >> 16)
	u.Low = uint16(w)
}

// AsUInt32 represents the uint32 as an uint32.
func (u *UInt32) AsUInt32() *UInt32 {
	return u
}

// Value returns the value of the uint32.
func (u *UInt32) Value() uint32 {
	return u.Word()
}

// SetValue sets the value of the uint32.
func (u *UInt32) SetValue(val uint32) {
	u.SetWord(val)
}

// SetPointer sets the value of the uint32 using a pointer.
func (u *UInt32) SetPointer(p unsafe.Pointer) {
	u.SetWord(uint32(uintptr(p)))
}

// UInt64 is used to model a 64-bit word/integer.
type UInt64 struct {
	High UInt32
	Low  UInt32
}

// Quad represents the uint64 as a quad.
func (u *UInt64) Quad() uint64 {
	return uint64(u.High.Word())<<32 + uint64(u.Low.Word())
}

// SetQuad sets the uint64 using a quad.
func (u *UInt64) SetQuad(w uint64) {
	u.High.SetWord(uint32(w >> 32))
	u.Low.SetWord(uint32(w))
}

// AsUInt32 represents the uint64 as a uint32 using the lower word.
func (u *UInt64) AsUInt32() *UInt32 {
	return &u.Low
}

// Value returns the value (a quad).
func (u *UInt64) Value() uint64 {
	return u.Quad()
}

// SetValue sets the value using a quad.
func (u *UInt64) SetValue(val uint64) {
	u.SetQuad(val)
}

// SetPointer sets the value using a pointer.
func (u *UInt64) SetPointer(p unsafe.Pointer) {
	u.SetQuad(uint64(uintptr(p)))
}
