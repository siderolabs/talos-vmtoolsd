// SPDX-FileCopyrightText: Copyright (c) 2020 Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

// +build gc

#include "textflag.h"

// func bdoorLBInOut(ax uint64, bx uint64, cx uint64, dx uint64, si uint64, di uint64, bp uint64) (retax uint64, retbx uint64, retcx uint64, retdx uint64, retsi uint64, retdi uint64, retbp uint64)
TEXT ·bdoorLBInOut(SB), NOSPLIT|WRAPPER, $0-56
	MOVL ax+0(FP), AX
	MOVL bx+4(FP), BX
	MOVL cx+8(FP), CX
	MOVL dx+12(FP), DX
	MOVL si+16(FP), SI
	MOVL di+20(FP), DI
	MOVL bp+24(FP), BP

	// IN to DX from AX
	INL
	MOVL AX, retax+28(FP)
	MOVL BX, retbx+32(FP)
	MOVL CX, retcx+36(FP)
	MOVL DX, retdx+40(FP)
	MOVL SI, retsi+44(FP)
	MOVL DI, retdi+48(FP)
	MOVL BP, retbp+52(FP)
	RET

// func bdoorHBOut(ax uint64, bx uint64, cx uint64, dx uint64, si uint64, di uint64, bp uint64) (retax uint64, retbx uint64, retcx uint64, retdx uint64, retsi uint64, retdi uint64, retbp uint64)
TEXT ·bdoorHBOut(SB), NOSPLIT|WRAPPER, $0-56
	MOVL ax+0(FP), AX
	MOVL bx+4(FP), BX
	MOVL cx+8(FP), CX
	MOVL dx+12(FP), DX
	MOVL si+16(FP), SI
	MOVL di+20(FP), DI
	MOVL bp+24(FP), BP
	CLD
	REP
	OUTSB
	MOVL AX, retax+28(FP)
	MOVL BX, retbx+32(FP)
	MOVL CX, retcx+36(FP)
	MOVL DX, retdx+40(FP)
	MOVL SI, retsi+44(FP)
	MOVL DI, retdi+48(FP)
	MOVL BP, retbp+52(FP)
	RET

// func bdoorHBIn(ax uint64, bx uint64, cx uint64, dx uint64, si uint64, di uint64, bp uint64) (retax uint64, retbx uint64, retcx uint64, retdx uint64, retsi uint64, retdi uint64, retbp uint64)
TEXT ·bdoor_hb_in(SB), NOSPLIT|WRAPPER, $0-56
	MOVL ax+0(FP), AX
	MOVL bx+4(FP), BX
	MOVL cx+8(FP), CX
	MOVL dx+12(FP), DX
	MOVL si+16(FP), SI
	MOVL di+20(FP), DI
	MOVL bp+24(FP), BP
	CLD
	REP
	INSB
	MOVL AX, retax+28(FP)
	MOVL BX, retbx+32(FP)
	MOVL CX, retcx+36(FP)
	MOVL DX, retdx+40(FP)
	MOVL SI, retsi+44(FP)
	MOVL DI, retdi+48(FP)
	MOVL BP, retbp+52(FP)
	RET
