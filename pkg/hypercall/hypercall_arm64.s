// SPDX-FileCopyrightText: Copyright (c) 2020 Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

// +build gc

// this is liberally borrowed from open-vm-tools, specifically:
// - lib/backdoor/backdoorGcc64_arm64.c - the actual assembly code
// - lib/include/backdoor_def.h        - (where the ARM64 x86-style I/O is described)
// 
// also learned a lot from https://blog.felixge.de/go-arm64-function-call-assembly/
// and reference at https://pkg.go.dev/cmd/internal/obj/arm64
// and https://developer.arm.com/documentation/102374/0102/Loads-and-stores---addressing

//#define X86_IO_MAGIC          0x86
//#define X86_IO_W7_SIZE_SHIFT  0
//#define X86_IO_W7_SIZE_MASK   (0x3 << X86_IO_W7_SIZE_SHIFT)
//#define X86_IO_W7_DIR         (1 << 2)
//#define X86_IO_W7_WITH        (1 << 3)
//#define X86_IO_W7_STR         (1 << 4)
//#define X86_IO_W7_DF          (1 << 5)
//#define X86_IO_W7_IMM_SHIFT   5
//#define X86_IO_W7_IMM_MASK    (0xff << X86_IO_W7_IMM_SHIFT)

#include "textflag.h"

// value of R7:
// [63..32] should be "(X86_IO_W7_WITH | X86_IO_W7_DIR | 2 << X86_IO_W7_SIZE_SHIFT)", which is 0x0e
// [31..0] should be X86_IO_MAGIC, which is 0x86
// func bdoor_lb_inout(ax uint32, bx uint32, cx uint32, dx uint32, si uint32, di uint32, bp uint32) (retax uint32, retbx uint32, retcx uint32, retdx uint32, retsi uint32, retdi uint32, retbp uint32)
TEXT ·bdoorLBInOut(SB), NOSPLIT|WRAPPER, $0-112
	//                              de-templated inline asm from open-vm-tools
	LDP  dibp+40(FP), (R5, R6)   // ldp x5, x6, [myBp, 8 * 5]
	LDP  dxsi+24(FP), (R3, R4)   // ldp x3, x4, [myBp, 8 * 3]
	LDP  bxcx+8(FP), (R1, R2)    // ldp x1, x2, [myBp, 8 * 1]
	MOVD  ax+0(FP), R0           // ldr x0,     [myBp]
	MOVD $0x0e, R7               // mov x7, (X86_IO_W7_WITH | X86_IO_W7_DIR | 2 << X86_IO_W7_SIZE_SHIFT)
	MOVK $(0x86 << 32), R7       // movk x7, X86_IO_MAGIC, lsl #32
	MRS  MDCCSR_EL0, ZR          // mrs xzr, mdccsr_el0
	STP  (R5, R6), r_dibp+96(FP) // stp x5, x6, [myBp, 8 * 5] 
	STP  (R3, R4), r_dxsi+80(FP) // stp x3, x4, [myBp, 8 * 3]
	STP  (R1, R2), r_bxcx+64(FP) // stp x1, x2, [myBp, 8 * 1]
	MOVD  R0, r_ax+48(FP)        // str x0,     [myBp]        <- our memory layout is different, we continue at FP+48, as in golang returns are just after the args
	RET                          // original code has no RET, probably has to do with memory layout as well

// value of R7:
// [63..32] should be "(X86_IO_W7_STR | X86_IO_W7_WITH)", which is 0x18
// [31..0] should be X86_IO_MAGIC, which is 0x86
// func bdoor_hb_out(ax uint64, bx uint64, cx uint64, dx uint64, si uint64, di uint64, bp uint64) (retax uint64, retbx uint64, retcx uint64, retdx uint64, retsi uint64, retdi uint64, retbp uint64)
TEXT ·bdoorHBOut(SB), NOSPLIT|WRAPPER, $0-112
    // for explanation of assembly code, see ·bdoor_lb_inout above, but note the difference in R7 loading
	LDP  dibp+40(FP), (R5, R6)
	LDP  dxsi+24(FP), (R3, R4)
	LDP  bxcx+8(FP), (R1, R2)
	MOVD  ax+0(FP), R0
	MOVD $0x18, R7
	MOVK $(0x86 << 32), R7
	MRS  MDCCSR_EL0, ZR
	STP  (R5, R6), r_dibp+96(FP)
	STP  (R3, R4), r_dxsi+80(FP)
	STP  (R1, R2), r_bxcx+64(FP)
	MOVD  R0, r_ax+48(FP)
	RET

// value of R7:
// [63..32] should be "(X86_IO_W7_STR | X86_IO_W7_WITH | X86_IO_W7_DIR)", which is 0x1c
// [31..0] should be X86_IO_MAGIC, which is 0x86
// func bdoor_hb_in(ax uint64, bx uint64, cx uint64, dx uint64, si uint64, di uint64, bp uint64) (retax uint64, retbx uint64, retcx uint64, retdx uint64, retsi uint64, retdi uint64, retbp uint64)
TEXT ·bdoorHBIn(SB), NOSPLIT|WRAPPER, $0-112
    // for explanation of assembly code, see ·bdoor_lb_inout above, but note the difference in R7 loading
	LDP  dibp+40(FP), (R5, R6)
	LDP  dxsi+24(FP), (R3, R4)
	LDP  bxcx+8(FP), (R1, R2)
	MOVD  ax+0(FP), R0
	MOVD $0x1c, R7
	MOVK $(0x86 << 32), R7
	MRS  MDCCSR_EL0, ZR
	STP  (R5, R6), r_dibp+96(FP)
	STP  (R3, R4), r_dxsi+80(FP)
	STP  (R1, R2), r_bxcx+64(FP)
	MOVD  R0, r_ax+48(FP)
	RET
