// SPDX-FileCopyrightText: Copyright (c) 2020 Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

// +build gc

#include "textflag.h"

// func bdoor_lb_inout(ax uint64, bx uint64, cx uint64, dx uint64, si uint64, di uint64, bp uint64) (retax uint64, retbx uint64, retcx uint64, retdx uint64, retsi uint64, retdi uint64, retbp uint64)
TEXT ·bdoorLBInOut(SB), NOSPLIT|WRAPPER, $0-112
	MOVQ ax+0(FP), AX
	MOVQ bx+8(FP), BX
	MOVQ cx+16(FP), CX
	MOVQ dx+24(FP), DX
	MOVQ si+32(FP), SI
	MOVQ di+40(FP), DI
	MOVQ bp+48(FP), BP

	// IN to DX from AX
	INL
	MOVQ AX, retax+56(FP)
	MOVQ BX, retbx+64(FP)
	MOVQ CX, retcx+72(FP)
	MOVQ DX, retdx+80(FP)
	MOVQ SI, retsi+88(FP)
	MOVQ DI, retdi+96(FP)
	MOVQ BP, retbp+104(FP)
	RET

// func bdoor_hb_out(ax uint64, bx uint64, cx uint64, dx uint64, si uint64, di uint64, bp uint64) (retax uint64, retbx uint64, retcx uint64, retdx uint64, retsi uint64, retdi uint64, retbp uint64)
TEXT ·bdoorHBOut(SB), NOSPLIT|WRAPPER, $0-112
	MOVQ ax+0(FP), AX
	MOVQ bx+8(FP), BX
	MOVQ cx+16(FP), CX
	MOVQ dx+24(FP), DX
	MOVQ si+32(FP), SI
	MOVQ di+40(FP), DI
	MOVQ bp+48(FP), BP
	CLD
	REP
	OUTSB
	MOVQ AX, retax+56(FP)
	MOVQ BX, retbx+64(FP)
	MOVQ CX, retcx+72(FP)
	MOVQ DX, retdx+80(FP)
	MOVQ SI, retsi+88(FP)
	MOVQ DI, retdi+96(FP)
	MOVQ BP, retbp+104(FP)
	RET

// func bdoor_hb_in(ax uint64, bx uint64, cx uint64, dx uint64, si uint64, di uint64, bp uint64) (retax uint64, retbx uint64, retcx uint64, retdx uint64, retsi uint64, retdi uint64, retbp uint64)
TEXT ·bdoorHBIn(SB), NOSPLIT|WRAPPER, $0-112
	MOVQ ax+0(FP), AX
	MOVQ bx+8(FP), BX
	MOVQ cx+16(FP), CX
	MOVQ dx+24(FP), DX
	MOVQ si+32(FP), SI
	MOVQ di+40(FP), DI
	MOVQ bp+48(FP), BP
	CLD
	REP
	INSB
	MOVQ AX, retax+56(FP)
	MOVQ BX, retbx+64(FP)
	MOVQ CX, retcx+72(FP)
	MOVQ DX, retdx+80(FP)
	MOVQ SI, retsi+88(FP)
	MOVQ DI, retdi+96(FP)
	MOVQ BP, retbp+104(FP)
	RET
