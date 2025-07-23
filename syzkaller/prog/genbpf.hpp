#pragma once
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "../include/linux/bpf.h"
#include <bpf/btf.h>
#include <unistd.h>
#include <cstdint>

#include <iostream>
#include <fstream>
#include <atomic>
#include <map>

#include "../syz-manager/shared-header.hpp"

#include "bpf_complete_insn.h"
#include "bpf-info/progtypes.h"
#include "bpf-info/helper_dataflow.h"
#include "bpf-info/progtype_helpers.h"

#define CHECKERMODE

#define RARE_CHANCE 20

// When we are looking for a map, number of tries we do so
#define MAP_TRY_TO_FIND 100

#define NINSNS 6
#define MININSNS 5
#define NINSNSALL (NINSNS + 3)
#define BBMAX (NINSNSALL * 2)
#define PROGSTATES 40
#define SMAX 

#define Bit64 0b00
#define Bit32 0b01
#define Bit64Value 0b10
#define Bit32Value 0b11

#define U32_MAX		((uint32_t)~0U)
#define U32_MIN		((uint32_t)0)
#define S32_MAX		((int32_t)(U32_MAX >> 1))
#define S32_MIN		((int32_t)(-S32_MAX - 1))
#define U64_MAX		((uint64_t)~0ULL)
#define S64_MAX		((int64_t)(U64_MAX >> 1))
#define S64_MIN		((int64_t)(-S64_MAX - 1))

enum operations{
    ALUOP,
    LSOP,
    CALLOP,
    JMPOP
};

struct tnum {
	__u64 value;
	__u64 mask;
};

struct regState {
	int type;
    // __s32 off;
    // struct tnum var_off;
	// __s64 smin_value; /* minimum possible (s64)value */
	// __s64 smax_value; /* maximum possible (s64)value */
	// __u64 umin_value; /* minimum possible (u64)value */
	// __u64 umax_value; /* maximum possible (u64)value */
	// __s32 s32_min_value; /* minimum possible (s32)value */
	// __s32 s32_max_value; /* maximum possible (s32)value */
	// __u32 u32_min_value; /* minimum possible (u32)value */
	// __u32 u32_max_value; /* maximum possible (u32)value */
};

#define MAX_RET_LEN 6

const static struct {
    int type;
    const char *str;
} retTypeEnum[MAX_RET_LEN] = {
    {SCALAR_VALUE, "INTEGER"},
    //{PTR_TO_BTF_ID, "PTR_TO_BTF_ID"},
    {PTR_TO_MEM, "PTR_TO_MEM"},
    {NOT_INIT, "VOID"},
    {PTR_TO_SOCKET, "PTR_TO_SOCKET"},
    {PTR_TO_SOCK_COMMON, "PTR_TO_SOCK_COMMON"},
    //{PTR_TO_BTF_ID, "PTR_TO_BTF_ID"},
    {PTR_TO_MAP_VALUE, "PTR_TO_MAP_VALUE"}
};

const int NO_OF_PROGTYPE = (sizeof(progTypes) / sizeof(const char *)) + 1;
bool progtype_allows_helpers;

//char logbuf[1024 * 1024];
char licenseString[] = "Dual BSD/GPL";

#define MAX_PSEUDO_FUNCS 0
// set the number of blocks
#define MAX_PROG_BLOCKS 5
#define MAX_CFG_VERTS (MAX_PSEUDO_FUNCS + MAX_PROG_BLOCKS)
#define UNSET_EDGE 0
#define SET_EDGE 1

// Number of pseudo functions
int pseudoFuncs;
bool isFuncUsed[MAX_PSEUDO_FUNCS];

// https://www.kernel.org/doc/html/next/bpf/btf.html §3.3

int func_type_id[MAX_PSEUDO_FUNCS+1];

//struct bpf_insn progBytecode[MAX_CFG_VERTS][BBMAX];
int cfg[MAX_PROG_BLOCKS][MAX_PROG_BLOCKS];

using namespace std;
std::atomic<int> solve_id{0};
std::atomic<int> solve_cnt{0};
#define MAX_THRDS 4096

struct thrd_arg {
	union bpf_attr *prog_attr;
	struct interm_state *itm_states;
	int runtime_res;
};

pthread_t oracle_thrds[MAX_THRDS];
struct thrd_arg thrd_args[MAX_THRDS];

inline void swap(int *a, int *b) {if (*a != *b) {*a ^= *b; *b ^= *a; *a ^= *b;}}
void shuffle(int *arr, int num);
bool isLeaf(int cfgMat[][MAX_PROG_BLOCKS], int idx);
bool isConditional(int cfgMat[][MAX_PROG_BLOCKS], int idx);
inline void initCFG() { memset(cfg, UNSET_EDGE, sizeof(int) * MAX_PROG_BLOCKS * MAX_PROG_BLOCKS); }
int genCFG(int cfgMat[][MAX_PROG_BLOCKS], int vert);

void findIncoming(int idx, int *res);
void findOutgoing(int idx, int *stack, int &stack_cnt);

inline int getFirstChild(int idx) { for (int i = 0; i < MAX_PROG_BLOCKS; i++) { if (cfg[idx][i]) return i; } return -1; }
inline int getChildIndex(int idx, int *visited) { for (int i = 0; i < MAX_PROG_BLOCKS; i++) { if (visited[i] == idx) { return i; } } return -1; }
inline bool isVisited(int *visited, int idx) { for(int i = 0; i < MAX_PROG_BLOCKS; i++) { if (visited[i] == idx) return true; } return false; }
struct regState *genInputState(int bbIdx, struct regState *regStates);
void genBasicBlock(struct regState *regStates, struct bpf_insn progBytecode[][BBMAX], int maxMaps, int idx, bool isEnd, int *visited, int verts);
void rearrangeProg(struct bpf_insn progBytecode[][BBMAX], int cfgMat[][MAX_PROG_BLOCKS], int verts, int maxMaps);
void makePseudoFuncs(struct btf *btf, struct bpf_insn progBytecode[][BBMAX], int verts, int pseudoNum, int maxMaps);

int findReg(const struct regState *regStates, bool wantPtr, int state, bool allowSP);

void genALUOP(struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int max_cnt, bool isPseudoFunc = false);
void genLSOP(struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int maxMaps, int max_cnt, bool isPseudoFunc = false);
void genCallOP(struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int max_cnt, int maxMaps, int posIdx, int verts, bool isPseudoFunc = false, int pseudoNum = MAX_PSEUDO_FUNCS);
void genJA(struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int off, bool force = false);
void genCondJMP(struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int off, int dst, int src, int bit, bool force = false);

__u8 aluops[] = {
    BPF_ADD,
    BPF_SUB,
    BPF_MUL,
    BPF_DIV,
    BPF_OR,
    BPF_AND,
    BPF_LSH,
    BPF_RSH,
    // BPF_NEG,
    BPF_MOD,
    BPF_XOR,
    BPF_ARSH
    // BPF_TO_LE | BPF_END,
    // BPF_TO_BE | BPF_END,
};

__u8 aluSops[] = {
    BPF_DIV,
    BPF_MOD
};

__u8 jmpops[] = {
    // BPF_JA,
    BPF_JEQ,
    BPF_JGT,
    BPF_JGE,
    BPF_JSET,
    BPF_JNE,
    BPF_JLT,
    BPF_JLE,
    BPF_JSGT,
    BPF_JSGE,
    BPF_JSLT,
    BPF_JSLE,
};

#define REG_FAIL (__u8) -1

__u8 regs[__MAX_BPF_REG] = {
    BPF_REG_0,
    BPF_REG_1,
    BPF_REG_2,
    BPF_REG_3,
    BPF_REG_4,
    BPF_REG_5,
    BPF_REG_6,
    BPF_REG_7,
    BPF_REG_8,
    BPF_REG_9,
    BPF_REG_10,
};

__u8 writable_regs[] = {
    BPF_REG_0,
    BPF_REG_2,
    BPF_REG_3,
    BPF_REG_4,
    BPF_REG_5,
    BPF_REG_6,
    BPF_REG_7,
    BPF_REG_8,
    BPF_REG_9,
};

#define one_writable_reg (writable_regs[rand() % sizeof(writable_regs)])

__u8 SIZE[] = {
    BPF_W,
    BPF_H,
    BPF_B,
    BPF_DW,
};

__u8 ATOMIC_SIZE[] = {
    BPF_W,
    BPF_DW,
};

#define get_atomic_size (ATOMIC_SIZE[rand() % sizeof(ATOMIC_SIZE)])

#define BPF_FETCH	0x01
#define BPF_XCHG	(0xe0 | BPF_FETCH)
#define BPF_CMPXCHG	(0xf0 | BPF_FETCH)
#define BPF_ATOMIC	0xc0

__u8 atomicOps[] = {
    BPF_ADD,
    BPF_AND,
    BPF_OR,
    BPF_XOR,
    BPF_ADD | BPF_FETCH,
    BPF_AND | BPF_FETCH,
    BPF_OR | BPF_FETCH,
    BPF_XOR | BPF_FETCH,
    BPF_XCHG,
    BPF_CMPXCHG,
};

__u8 ENDIMMs[] = {
    16,
    32,
    64
};

struct regState regStates[sizeof(regs)];
struct regState *progStates[PROGSTATES * sizeof(regStates)];
struct regState basicBlockStates[MAX_PROG_BLOCKS][sizeof(regs)];
struct regState protoStates[MAX_PSEUDO_FUNCS][sizeof(regs)];
int populationBB[MAX_PROG_BLOCKS];
int populationPseudo[MAX_PSEUDO_FUNCS];

const char *funcNames[5] = { "func1", "func2", "func3", "func4", "func5" };

#define stateTransit(dst, src) (dst.type = src.type)

int progType;

static void printInsn(const char *insn, u_int8_t op, u_int8_t dst, u_int8_t src, int32_t imm, short int off) {
#ifdef DEBUG
    fprintf(stderr, "%s_%d(dst %d, src %d, imm %d, off %d)\n", insn, op, dst, src, imm, off);
#endif
}

#define DEUBG_LOC(label) ({ \
    fprintf(stderr, "%s DEBUG Location: %s: %d\n", label, __FILE__, __LINE__); \
})

static void PrintLogbuf(char *bpfAttrArg){
	union bpf_attr *bpfAttr = (union bpf_attr *)bpfAttrArg;
	fprintf(stderr, "log_buf:%s\n", (char *)bpfAttr->log_buf);
}

bool updateByteCode(struct bpf_insn *bpfBytecode, int *cnt, struct bpf_insn insn,
                        bool force, int lineno, int max_cnt = NINSNS) {
    int limit = (force ? max_cnt + 3 : max_cnt);
    if (*cnt < limit) {
        bpfBytecode[*cnt] = insn;
        *cnt += 1;
        progStates[*cnt] = regStates;
        fprintf(stderr, "updateBytecode at: %d\n", lineno);
        return true;
    }
    return false;
}

void print_full_code(struct bpf_insn** progBytecode){
    fprintf(stderr, "print full code\n");
    for (int i = 0; i < MAX_CFG_VERTS; i++)
    {
        for (int j = 0; j < BBMAX; j++)
        {
            fprintf(stderr,"%02x ", progBytecode[i][j].code);
        }
        fprintf(stderr, "\n");
    }
}

bool BPF_ATOMIC_OP_Constrait(int size, u_int8_t op, u_int8_t dst, u_int8_t src, short int off) {
    
    if (size != BPF_DW && size != BPF_W) return false;
    return true;
}

void printProg(int ind);

// Later, when PseudoFuncs are done
// bool regStackFrames[12] = {0};

#define MAX_INDEP_ARGS 5
#define MAX_DEP_ARGS 8

const char *indep_args_enum[MAX_INDEP_ARGS] = {
    "SCALAR_VALUE",
    "PTR_TO_STACK",
    "PTR_TO_CTX",
    "ARG_ANYTHING",
    "ARG_PTR_TO_STACK_OR_NULL"
};

const char *dep_args_enum[MAX_DEP_ARGS] = {
    "PTR_TO_MEM",
    "PTR_TO_SOCKET",
    "PTR_TO_SOCK_COMMON",
    "PTR_TO_BTF_ID",
    "PTR_TO_MAP_VALUE",
    "ARG_PTR_TO_BTF_ID_OR_NULL",
    "ARG_PTR_TO_MEM_OR_NULL",
    "ARG_PTR_TO_MAP_VALUE_OR_NULL"
};

#define PTR_TO_MEM_LOC 320
#define PTR_TO_SOCKET 328
#define PTR_TO_SOCK_COMMON 336
#define PTR_TO_BTF_ID 344
#define PTR_TO_MAP_VALUE 352

int spilledRegs[5] = {NOT_INIT};
bool stackHasDeps[5] = {false, false, false, false, false, };
bool callerSpillRegs(regState *regStates, bpf_insn *bpfByteCode, int *cnt, int max_cnt);
bool callerPopRegs(regState *regStates, bpf_insn *bpfByteCode, int *cnt, int max_cnt);
bool fillArg(regState *regStates, bpf_insn *bpfByteCode, int *cnt, int max_cnt, char reg, const char *type, int maxMaps, proto_addr helper_func);
bool canFulfilArgs(int funcIdx, regState *regStates, bpf_insn *bpfByteCode, int *cnt, int max_cnt, int maxMaps);
bool initStack(int ind, int size);

char genProgFlags(bpf_attr *progAttr);
