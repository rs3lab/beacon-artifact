#pragma once

/**************************** ALU ***************************/

#define BPF_NEG64_REG(DST)             \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_OP(BPF_NEG),    \
        .dst_reg = DST,                 \
        .src_reg = 0,                 \
        .off   = 0,                 \
        .imm   = 0 })

#define BPF_NEG32_REG(DST)             \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_OP(BPF_NEG),    \
        .dst_reg = DST,                 \
        .src_reg = 0,                 \
        .off   = 0,                 \
        .imm   = 0 })

#define BPF_ENDBE_REG(DST, IMM)             \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_TO_BE | BPF_END,    \
        .dst_reg = DST,                 \
        .src_reg = 0,                 \
        .off   = 0,                 \
        .imm   = IMM }) // imm = 16, 32, 64

#define BPF_ENDLE_REG(DST, IMM)             \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_TO_LE | BPF_END,    \
        .dst_reg = DST,                 \
        .src_reg = 0,                 \
        .off   = 0,                 \
        .imm   = IMM }) // imm = 16, 32, 64

#define BPF_ENDSWAP_REG(DST, IMM)             \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_TO_LE | BPF_END,    \
        .dst_reg = DST,                 \
        .src_reg = 0,                 \
        .off   = 0,                 \
        .imm   = IMM }) // imm = 16, 32, 64
/**************************** Load/Store ***************************/

/*
 * insn[0].src_reg:  BPF_PSEUDO_MAP_[FD|IDX]
 * insn[0].imm:      map fd or fd_idx
 * insn[1].imm:      0
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of map
 * verifier type:    CONST_PTR_TO_MAP
*/
#define BPF_PSEUDO_MAP_IDX  5
#define BPF_LD_FDIDX(DST, MAP_FDIDX)             \
    BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_IDX, MAP_FDIDX)


/* insn[0].src_reg:  BPF_PSEUDO_MAP_[IDX_]VALUE
 * insn[0].imm:      map fd or fd_idx
 * insn[1].imm:      offset into value
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of map[0]+offset
 * verifier type:    PTR_TO_MAP_VALUE
 */
#define BPF_PSEUDO_MAP_VALUE        2
#define BPF_PLATFORM_VAR            3
#define BPF_PSEUDO_MAP_IDX_VALUE    6
#define BPF_LD_FD_MAPVALUE(DST, FD, OFF)             \
    BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_VALUE, (((__u64)OFF<<32 | FD)))
#define BPF_LD_FDIDX_MAPVALUE(DST, FDIDX, OFF)             \
    BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_IDX_VALUE, ((__u64)OFF<<32 | FDIDX))

// NOT IMPLEMENTED FOR NOW
#define BPF_LD_PLAT_VAR(DST, VAR_IMM)             \
    BPF_LD_IMM64_RAW(DST, BPF_PLATFORM_VAR, VAR_IMM)

/* insn[0].src_reg:  BPF_PSEUDO_BTF_ID
 * insn[0].imm:      kernel btd id of VAR
 * insn[1].imm:      0
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of the kernel variable
 * verifier type:    PTR_TO_BTF_ID or PTR_TO_MEM, depending on whether the var
 *                   is struct/union.
 */
#define BTF_FD_IDX 0

/* insn[0].src_reg:  BPF_PSEUDO_FUNC
 * insn[0].imm:      insn offset to the func
 * insn[1].imm:      0
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of the function
 * verifier type:    PTR_TO_FUNC.
 since the second instruction is not used at all. Define it with one instruction.
 */
#define BPF_PSEUDO_FUNC     4
#define BPF_LD_PSEUDO_FUNC(DST, OFF) \
        BPF_RAW_INSN(BPF_LD | BPF_IMM | BPF_DW, DST, BPF_PSEUDO_FUNC, 0, OFF)

// Packet data at a variable offset (BPF_IND)
#define BPF_LD_IND(SIZE, IMM)                   \
    ((struct bpf_insn) {                    \
        .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_IND, \
        .dst_reg = 0,                   \
        .src_reg = 0,                   \
        .off   = 0,                 \
        .imm   = IMM })

/*
// The packet length (BPF_LEN)
#define BPF_LD_LEN(SIZE, IMM)                   \
    ((struct bpf_insn) {                    \
        .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_LEN, \
        .dst_reg = 0,                   \
        .src_reg = 0,                   \
        .off   = 0,                 \
        .imm   = IMM })
// Loading the IP header length
#define BPF_LD_MSH(SIZE, IMM)                   \
    ((struct bpf_insn) {                    \
        .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_MSH, \
        .dst_reg = 0,                   \
        .src_reg = 0,                   \
        .off   = 0,                 \
        .imm   = IMM })
*/


/**************************** JMP ***************************/

#define BPF_JA_INSN(OFF) BPF_RAW_INSN(BPF_JMP | BPF_JA, 0, 0, OFF, 0)
#define BPF_JA32_INSN(OFF) BPF_RAW_INSN(BPF_JMP32 | BPF_JA, 0, 0, 0, OFF)

/**************************** Call ***************************/

/* when bpf_call->src_reg == BPF_PSEUDO_CALL, bpf_call->imm == pc-relative
 * offset to another bpf function
 */
#define BPF_PSEUDO_CALL     1
#define BPF_CALL_PSEUDO_FUNC(PCOFF)                   \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP | BPF_CALL,            \
        .dst_reg = 0,                   \
        .src_reg = BPF_PSEUDO_CALL,         \
        .off   = 0,                 \
        .imm   = PCOFF })


/* when bpf_call->src_reg == BPF_PSEUDO_KFUNC_CALL,
 * bpf_call->imm == btf_id of a BTF_KIND_FUNC in the running kernel
 */
#define BPF_PSEUDO_KFUNC_CALL   2
// TAO TODO

#define BPF_HELPER_CALL(HELPER) BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, HELPER)
/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* eBPF instruction mini library */
#ifndef __BPF_INSN_H
#define __BPF_INSN_H

struct bpf_insn;

/* ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */

#define BPF_ALU64_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_ALU32_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */

#define BPF_ALU64_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_ALU32_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP((__u8)OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* signed ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */

#define BPF_ALUS64_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 1,					\
		.imm   = 0 })

#define BPF_ALUS32_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 1,					\
		.imm   = 0 })

/* signed ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */

#define BPF_ALUS64_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 1,					\
		.imm   = IMM })

#define BPF_ALUS32_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP((__u8)OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 1,					\
		.imm   = IMM })

/* Short form of mov, dst_reg = src_reg */

#define BPF_MOV64_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_MOV32_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* Short form of mov, dst_reg = imm32 */

#define BPF_MOV64_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_MOV32_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Short form of signed mov, dst_reg = src_reg */

#define BPF_MOVS64_REG(DST, SRC, OFF)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 }) // off = 8/16/32

#define BPF_MOVS32_REG(DST, SRC, OFF)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 }) // off = 8/16


/* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */
#define BPF_LD_IMM64(DST, IMM)					\
	BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_DW | BPF_IMM,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = (__u32) (IMM) }),			\
	((struct bpf_insn) {					\
		.code  = 0, /* zero is reserved opcode */	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((__u64) (IMM)) >> 32 })

#ifndef BPF_PSEUDO_MAP_FD
# define BPF_PSEUDO_MAP_FD	1
#endif

/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */
#define BPF_LD_MAP_FD(DST, MAP_FD)				\
	BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)


/* Direct packet access, R0 = *(uint *) (skb->data + imm32) */

#define BPF_LD_ABS(SIZE, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Memory load, dst_reg = *(uint *) (src_reg + off16) */

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

#define BPF_LDX_MEMSX(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEMSX,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })
/* Memory store, *(uint *) (dst_reg + off16) = src_reg */

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/*
 * Atomic operations:
 *
 *   BPF_ADD                  *(uint *) (dst_reg + off16) += src_reg
 *   BPF_AND                  *(uint *) (dst_reg + off16) &= src_reg
 *   BPF_OR                   *(uint *) (dst_reg + off16) |= src_reg
 *   BPF_XOR                  *(uint *) (dst_reg + off16) ^= src_reg
 *   BPF_ADD | BPF_FETCH      src_reg = atomic_fetch_add(dst_reg + off16, src_reg);
 *   BPF_AND | BPF_FETCH      src_reg = atomic_fetch_and(dst_reg + off16, src_reg);
 *   BPF_OR | BPF_FETCH       src_reg = atomic_fetch_or(dst_reg + off16, src_reg);
 *   BPF_XOR | BPF_FETCH      src_reg = atomic_fetch_xor(dst_reg + off16, src_reg);
 *   BPF_XCHG                 src_reg = atomic_xchg(dst_reg + off16, src_reg)
 *   BPF_CMPXCHG              r0 = atomic_cmpxchg(dst_reg + off16, r0, src_reg)
 */

#define BPF_ATOMIC_OP(SIZE, OP, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_ATOMIC,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = OP })

/* Legacy alias */
#define BPF_STX_XADD(SIZE, DST, SRC, OFF) BPF_ATOMIC_OP(SIZE, BPF_ADD, DST, SRC, OFF)

/* Memory store, *(uint *) (dst_reg + off16) = imm32 */

#define BPF_ST_MEM(SIZE, DST, OFF, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Conditional jumps against registers, if (dst_reg 'op' src_reg) goto pc + off16 */

#define BPF_JMP_REG(OP, DST, SRC, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Like BPF_JMP_REG, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_REG(OP, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_JMP32 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */

#define BPF_JMP_IMM(OP, DST, IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Like BPF_JMP_IMM, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_IMM(OP, DST, IMM, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_JMP32 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Raw code statement block */

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)			\
	((struct bpf_insn) {					\
		.code  = CODE,					\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Program exit */

#define BPF_EXIT_INSN()						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_EXIT,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = 0 })

#endif

