// SPDX-FileCopyrightText: Copyright (c) 2020 Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package hypercall

// StackFrame models the set of registers to be sent/received.
type StackFrame struct {
	AX, BX, CX, DX, SI, DI, BP UInt64
}

func bdoorLBInOut(ax, bx, cx, dx, si, di, bp uint64) (retax, retbx, retcx, retdx, retsi, retdi, retbp uint64)
func bdoorHBOut(ax, bx, cx, dx, si, di, bp uint64) (retax, retbx, retcx, retdx, retsi, retdi, retbp uint64)
func bdoorHBIn(ax, bx, cx, dx, si, di, bp uint64) (retax, retbx, retcx, retdx, retsi, retdi, retbp uint64)
