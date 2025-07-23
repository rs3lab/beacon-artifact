#pragma once
#define BPF_BASE_TYPE_MASK	255
#define PTR_MAYBE_NULL 256

inline int base_type(int type)
{
	return type & BPF_BASE_TYPE_MASK;
}

/* ALU instruction constraits:
    1. Initialized
    2. Registers are all scalar value
    3. The number of shift bit should be less than 32/64
    4. Frame pointer is read only
*/

int findAnyPtrReg(const regState* regStates)
{
    int res;
    unsigned int checkedRegs = 0;
    while (checkedRegs <= 0x7ff) {
        res = randRange(BPF_REG_0, BPF_REG_10);
        if (regStates[res].type != NOT_INIT && regStates[res].type != SCALAR_VALUE && regStates[res].type != CONST_PTR_TO_MAP)
            break;
        checkedRegs |= (1 << res);
    }

    if (checkedRegs > 0x7ff) {
        fprintf(stderr, "reg type: stack\n");
        return BPF_REG_10;
    }
    else {
        fprintf(stderr, "reg %d type: %d\n", res, regStates[res].type);
        return res;
    }
}

int findAnyWritableReg(const regState* regStates)
{
    int res;
    unsigned int checkedRegs = 0;
    while (checkedRegs <= 0x7ff) {
        res = randRange(BPF_REG_0, BPF_REG_10);
        if (regStates[res].type != NOT_INIT)
            break;
        checkedRegs |= (1 << res);
    }

    if (checkedRegs > 0x7ff) {
        fprintf(stderr, "reg type: stack\n");
        return BPF_REG_10;
    } else {
        fprintf(stderr, "reg %d type: %d\n", res, regStates[res].type);
        return res;
    }
}

int findAnyInitReg(const regState* regStates)
{
    int res;
    unsigned int checkedRegs = 0;
    while (checkedRegs <= 0x7ff) {
        res = randRange(BPF_REG_0, BPF_REG_10);
        if (regStates[res].type != NOT_INIT)
            break;
        checkedRegs |= (1 << res);
    }

    if (checkedRegs > 0x7ff) {
        fprintf(stderr, "reg type: stack\n");
        return BPF_REG_10;
    } else {
        fprintf(stderr, "reg %d type: %d\n", res, regStates[res].type);
        return res;
    }
}

int findReg(const regState* regStates, bool wantPtr, int state = NOT_INIT, bool allowSP = false)
{
    // fprintf(stderr, "finding a reg\n");
    int res;
    int checkedRegs = 0;
    while ((checkedRegs < 0x3ff) || (allowSP && checkedRegs < 0x7ff)) {
        res = (allowSP ? randRange(BPF_REG_0, BPF_REG_10) : randRange(BPF_REG_0, BPF_REG_9));
        if (state) {
            if (regStates[res].type == state)
                break;
        } else if ((wantPtr && regStates[res].type != NOT_INIT && regStates[res].type != SCALAR_VALUE) || (!wantPtr && regStates[res].type == SCALAR_VALUE))
            break;
        checkedRegs |= (1 << res);
    }

    //fprintf(stderr, "reg %d state %d wantPtr %d checkedRegs %x\n", res, regStates[res].type, wantPtr, checkedRegs);
    if ((!allowSP && checkedRegs > 0x3fe) || checkedRegs > 0x7fe)
        return -1;

    if (state || !state && (randRange(0, 10) < 8))
        return res;
    else {
        // fprintf(stderr, "syke\n");
        return -1;
    }
}

bool initRegScalar(u_int8_t reg, u_int8_t regBit, struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int64_t value, int max_cnt = NINSNS, bool force = false) {
    
    // Constraint 4: R10 is read-only.
    if (reg == BPF_REG_10 || reg == BPF_REG_1) return false;

    // The reg has already been initilized
    if (regStates[reg].type == SCALAR_VALUE &&
        regBit != Bit32Value && regBit != Bit64Value && !force) {
        return true;
    }

	// Randomly select one initialized register.
    int bitVect = 0, srcReg;

    while (bitVect < 0x3ff) {
        // Omit BPF_REG_10
        srcReg = regs[rand() % (sizeof(regs) - 1)];
        if (regStates[srcReg].type == SCALAR_VALUE) break;
        bitVect |= (1 << srcReg);
    }

    if (bitVect == 0x3ff) srcReg = -1;

    // REG_10 is not scalar, so I don't bother including it

    //fprintf(stderr, "This is initRegScalatr\n");

    struct bpf_insn insn;
    int32_t imm32;
    int64_t imm64;
    switch (regBit) {
        case Bit32:
            if (rand() % 100 < 90 && srcReg != -1) {
                insn = BPF_MOV32_REG(reg, srcReg);
                printInsn("BPF_MOV32_REG", 0, reg, srcReg, 0, 0);
            } else {
                imm32 = randNum32();
                insn = BPF_MOV32_IMM(reg, imm32);
                printInsn("BPF_MOV32_IMM", 0, reg, 0, imm32, 0);
            }
            break;
        case Bit64:
            if (rand() % 100 < 90 && srcReg != -1) {
                insn = BPF_MOV64_REG(reg, srcReg);
                printInsn("BPF_MOV64_REG", 0, reg, srcReg, 0, 0);
            } else {
                imm64 = randNum64();
                insn = BPF_MOV64_IMM(reg, imm64);
                printInsn("BPF_MOV64_IMM", 0, reg, 0, imm64, 0);
            }
            break;
        case Bit32Value:
            insn = BPF_MOV32_IMM(reg, value);
            printInsn("BPF_MOV32_IMM", 0, reg, 0, value, 0);
            break;
        case Bit64Value:
            insn = BPF_MOV64_IMM(reg, value);
            printInsn("BPF_MOV64_IMM", 0, reg, 0, value, 0);
            break;
    }

    bool ret = updateByteCode(bpfBytecode, cnt, insn, force, __LINE__, max_cnt);
    if (ret) regStates[reg].type = SCALAR_VALUE;
    else return false;

    return true;
}

bool commonALUCons(struct bpf_insn *insn, struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int max_cnt = NINSNS) {

    u_int8_t bit = 0;
    int opcode = BPF_OP(insn->code);

    switch (insn->code) {
        // NEG dst = ~dst
        case BPF_ALU | BPF_NEG:
            if (BPF_SRC(insn->code) != BPF_K) return false;
            if (insn->src_reg != BPF_REG_0) return false;
            if (insn->dst_reg == BPF_REG_10) return false;
            if (insn->off) return false;
            if (insn->imm) return false;
            if(!initRegScalar(insn->dst_reg, Bit32, regStates, bpfBytecode, cnt, 0, max_cnt, false)) return false;
            break;  
        case BPF_ALU | BPF_END | BPF_TO_BE:
        case BPF_ALU | BPF_END | BPF_TO_LE:
        case BPF_ALU64 | BPF_END | BPF_TO_LE: // swap
            if (insn->src_reg != BPF_REG_0) return false;
            if (insn->off) return false;
            if (insn->imm != 16 && insn->imm != 32 && insn->imm != 64) return false;
            if (insn->dst_reg == BPF_REG_10) return false;
            if(!initRegScalar(insn->dst_reg, Bit32, regStates, bpfBytecode, cnt, 0, max_cnt, false)) return false;
            break;
        case BPF_ALU64 | BPF_NEG:
            if (BPF_SRC(insn->code) != BPF_K) return false;
            if (insn->src_reg != BPF_REG_0) return false;
            if (insn->dst_reg == BPF_REG_10) return false;
            if (insn->off) return false;
            if (insn->imm) return false;
            if(!initRegScalar(insn->dst_reg, Bit64, regStates, bpfBytecode, cnt, 0, max_cnt, false)) return false;
            break;
        case BPF_ALU64 | BPF_END | BPF_TO_BE:
            return false;
        // Shift
        case BPF_ALU | BPF_ARSH | BPF_X:
        case BPF_ALU | BPF_LSH | BPF_X:
        case BPF_ALU | BPF_RSH | BPF_X:
            if (insn->off || insn->imm) return false;
            if (insn->dst_reg == BPF_REG_10) return false;
            if(!initRegScalar(insn->dst_reg, Bit32, regStates, bpfBytecode, cnt, 0, max_cnt, false)) return false;
            // Constraint 3: shifted bits <= 32/64
            // If this is already init, we might get errors as that value might not be between 0 to 31
            if(!initRegScalar(insn->src_reg, Bit32Value, regStates, bpfBytecode, cnt, randRange(0, 31), max_cnt, false)) return false;
            break;
        case BPF_ALU | BPF_ARSH | BPF_K:
        case BPF_ALU | BPF_LSH | BPF_K:
        case BPF_ALU | BPF_RSH | BPF_K:
            if (insn->src_reg != BPF_REG_0) return false;
            if (insn->off) return false;
            if (insn->dst_reg == BPF_REG_10) return false;
            if(!initRegScalar(insn->dst_reg, Bit32, regStates, bpfBytecode, cnt, 0, max_cnt, false)) return false;
            // Constraint 3: shifted bits <= 32/64
            insn->imm = randRange(0, 31);
            break;
        case BPF_ALU64 | BPF_ARSH | BPF_X:
        case BPF_ALU64 | BPF_LSH | BPF_X:
        case BPF_ALU64 | BPF_RSH | BPF_X:
            if (insn->off || insn->imm) return false;
            if (insn->dst_reg == BPF_REG_10) return false;
            if(!initRegScalar(insn->dst_reg, Bit64, regStates, bpfBytecode, cnt, 0, max_cnt, false)) return false;
            // Constraint 3: shifted bits <= 32/64
            if(!initRegScalar(insn->src_reg, Bit64Value, regStates, bpfBytecode, cnt, randRange(0, 63), max_cnt, false)) return false;
            break;
        case BPF_ALU64 | BPF_ARSH | BPF_K:
        case BPF_ALU64 | BPF_LSH | BPF_K:
        case BPF_ALU64 | BPF_RSH | BPF_K:
            if (insn->src_reg != BPF_REG_0) return false;
            if (insn->off) return false;
            if (insn->dst_reg == BPF_REG_10) return false;
            if(!initRegScalar(insn->dst_reg, Bit64, regStates, bpfBytecode, cnt, 0, max_cnt, false)) return false;
            // Constraint 3: shifted bits <= 32/64
            insn->imm = randRange(0, 63);
            break;
        // Mov
        case BPF_ALU64 | BPF_MOV | BPF_X:
        case BPF_ALU | BPF_MOV | BPF_X:
            if ((insn->off!=0 && insn->off!=8 && insn->off!=16 && insn->off!=32) || insn->imm) return false;
            if (insn->dst_reg == BPF_REG_10) return false;
            if (BPF_CLASS(insn->code) == BPF_ALU && regStates[insn->src_reg].type != SCALAR_VALUE) return false;
            // R10 has already been initialized with stack ptr.
            if (insn->src_reg != BPF_REG_10) {
                bit = insn->code & BPF_ALU64 ? Bit64 : Bit32;
                if(!initRegScalar(insn->src_reg, bit, regStates, bpfBytecode, cnt, 0, max_cnt, false)) return false;
            }
            regStates[insn->dst_reg].type = regStates[insn->src_reg].type;
            break;
        case BPF_ALU64 | BPF_MOV | BPF_K:
        case BPF_ALU | BPF_MOV | BPF_K:
            if (insn->src_reg != BPF_REG_0 || (insn->off!=0 && insn->off!=8 && insn->off!=16 && insn->off!=32)) return false;
            // Constraint 4: r10 is read-only.
            if (insn->dst_reg == BPF_REG_10) return false;
            regStates[insn->dst_reg].type = SCALAR_VALUE;
            break;
        // Others
        default:
            bit = insn->code & BPF_ALU64 ? Bit64 : Bit32;
            if (insn->dst_reg == BPF_REG_10) return false;
            if (insn->code & BPF_X) {
                if (insn->src_reg != BPF_REG_0 || insn->off) {
                    if (insn->src_reg != BPF_REG_0 || !(insn->off == 1 && (BPF_OP(insn->code)==BPF_DIV || BPF_OP(insn->code)==BPF_MOD))){
                        return false;
                    }
                }
                if ((opcode == BPF_MOD || opcode == BPF_DIV) && !insn->imm) return false;
                // Registers
                if(!initRegScalar(insn->src_reg, bit, regStates, bpfBytecode, cnt, 0, max_cnt, false)) return false;
                if(!initRegScalar(insn->dst_reg, bit, regStates, bpfBytecode, cnt, 0, max_cnt, false)) return false;
            } else if ((insn->code & BPF_X) == 0) {
                if (insn->src_reg != BPF_REG_0) return false;
                if (insn->off) {
                    if (!(insn->off == 1 && (BPF_OP(insn->code)==BPF_DIV || BPF_OP(insn->code)==BPF_MOD))){
                        return false;
                    }
                }
                if(!initRegScalar(insn->dst_reg, bit, regStates, bpfBytecode, cnt, 0, max_cnt, false)) return false;
            }
            break;
    }

    return true;
}


/* JMP instruction constraits:
    1. Initialized registers as any types.
    2. Offset: unsolved "unreachable insn" due to JA instruction.
*/

bool CommonInit(u_int8_t reg, u_int8_t regBit, struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int max_cnt = NINSNS) {
    
    if (reg == BPF_REG_10) return false;

    if (regStates[reg].type != NOT_INIT) return true;

    struct bpf_insn insn;
    int32_t imm32;
    int64_t imm64;
    u_int8_t srcReg;

    // Randomly select one initialized register.
    int i = 0;
    while(true){
        if (regStates[i].type != NOT_INIT && (rand() % 100 > 50)){
            srcReg = i;
            break;
        }
        i = (i + 1) % sizeof(regs);
    }

    // fprintf(stderr, "We came into CommonInit\n");

    switch((rand() % 2 << 2) | regBit) {
        // Reg
        case Bit32:
            insn = BPF_MOV32_REG(reg, srcReg);
            regStates[reg].type = regStates[srcReg].type;
            break;
        case Bit64:
            insn = BPF_MOV64_REG(reg, srcReg);
            regStates[reg].type = regStates[srcReg].type;
            break;
        // Immediate
        case 1<<2 | Bit32:
            imm32 = randNum32();
            insn = BPF_MOV32_IMM(reg, imm32);
            regStates[reg].type = SCALAR_VALUE;
            break;
        case 1<<2 | Bit64:
            imm64 = randNum64();
            insn = BPF_MOV64_IMM(reg, imm64);
            regStates[reg].type = SCALAR_VALUE;
            break;
    }

    return updateByteCode(bpfBytecode, cnt, insn, false, __LINE__, max_cnt);
}

inline bool type_may_be_null(uint32_t type)
{
	return type & PTR_MAYBE_NULL;
}

bool reg_type_not_null(int type)
{
	if (type_may_be_null(type))
		return false;

	type = base_type(type);
	return type == PTR_TO_SOCKET ||
		type == PTR_TO_TCP_SOCK ||
		type == PTR_TO_MAP_VALUE ||
		type == PTR_TO_MAP_KEY ||
		type == PTR_TO_SOCK_COMMON ||
		type == PTR_TO_MEM;
}

inline bool checkJA(struct bpf_insn *insn) {
    return (BPF_SRC(insn->code) == BPF_K && (insn->imm == 0 || insn->off == 0) && insn->src_reg == BPF_REG_0 && insn->dst_reg == BPF_REG_0 && (BPF_CLASS(insn->code) == BPF_JMP || BPF_CLASS(insn->code) == BPF_JMP32));
}

bool checkExit(struct bpf_insn *insn, struct regState *regStates, u_int8_t bit, int *cnt, struct bpf_insn *bpfBytecode, int max_cnt = NINSNS) {
    if (!checkJA(insn)) return false;
    // TODO {pragyansh.chaturvedi} Once call is implemented, need to check if we are exiting from program or callback
    // TODO {pragyansh.chaturvedi} Once prog_types are implemented, need to extend the constraints
    // We need R0 to be a scalar, so just initing it that way for now
    if (!initRegScalar(BPF_REG_0, bit, regStates, bpfBytecode, cnt, 0, max_cnt, false)) return false;
    return true;
}

bool checkExitJMP(struct bpf_insn *insn, struct regState *regStates, u_int8_t bit, int *cnt, struct bpf_insn *bpfBytecode) {
    if (!checkJA(insn)) return false;
    // TODO {pragyansh.chaturvedi} Once call is implemented, need to check if we are exiting from program or callback
    // TODO {pragyansh.chaturvedi} Once prog_types are implemented, need to extend the constraints
    // We need R0 to be a scalar, so just initing it that way for now
    if (regStates[BPF_REG_0].type != SCALAR_VALUE) return false;
    return true;
}

bool checkCall(struct bpf_insn *insn) {
    return false;
}

int calcPredX(struct bpf_insn *insn, struct regState *regStates) {
    return 0;
}

int calcPredK(struct bpf_insn *insn, struct regState *regStates) {
    if (regStates[insn->dst_reg].type != SCALAR_VALUE) {
        if (!reg_type_not_null(regStates[insn->dst_reg].type) || insn->imm)
			return -1;
        
        switch (BPF_OP(insn->code)) {
            case BPF_JEQ:
                return 0;
            case BPF_JNE:
                return 1;
            default:
                return -1; 
        }
    } else if (BPF_CLASS(insn->code) == BPF_JMP32) {
        return -1;
    } else {
        return -1;
    }

    return 0;
}

bool commonJMPCons(struct bpf_insn *insn, struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int max_cnt = NINSNS) {

    int pred;
    u_int8_t bit = insn->code & BPF_JMP ? Bit64 : Bit32;

    if (insn->code == BPF_JA) return checkJA(insn);
    if (insn->code == BPF_CALL) return checkCall(insn);
    if (insn->code == BPF_EXIT) return checkExit(insn, regStates, bit, cnt, bpfBytecode, max_cnt);

    // return false;

    switch (BPF_SRC(insn->code)) {
        case BPF_X:
            if (insn->imm != 0) return false;
            if (!initRegScalar(insn->src_reg, bit, regStates, bpfBytecode, cnt, 0, max_cnt)) return false;
            if (!CommonInit(insn->dst_reg, bit, regStates, bpfBytecode, cnt, max_cnt)) return false;
            break;
        case BPF_K:
            if (insn->src_reg != BPF_REG_0) return false;
            if (!CommonInit(insn->dst_reg, bit, regStates, bpfBytecode, cnt, max_cnt)) return false;
            break;
        default:
            return false;
    }
    
    // insn->off = randRange(-*cnt, (NINSNS-*cnt-2));

    return true;
}

bool initRegPtr(u_int8_t reg, struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int max_cnt = NINSNS) {
    
    if (reg == BPF_REG_10) return true;
    if (regStates[reg].type != NOT_INIT && regStates[reg].type != SCALAR_VALUE) return true;

    // Randomly select one initialized ptr register.
    int i = 0, loopTimes = 0;
    struct bpf_insn insn;
    // fprintf(stderr, "we are in initReg[Pytrr]\n");

    int bitVect = 0, srcReg;
    while (bitVect < 0x7ff) {
        srcReg = regs[rand() % (sizeof(regs))];
        if ((regStates[srcReg].type != SCALAR_VALUE) && (regStates[srcReg].type != NOT_INIT)) break;
        bitVect |= (1 << srcReg);
    }
    if (bitVect == 0x7ff) return false;

    insn = BPF_MOV64_REG(reg, srcReg);
    printInsn("BPF_MOV64_REG", 0, reg, srcReg, 0, 0);
    bool ret = updateByteCode(bpfBytecode, cnt, insn, false, __LINE__, max_cnt);
    if (ret) regStates[reg].type = regStates[srcReg].type; 
    return ret;
}

void initReg(struct regState *regStates, u_int8_t reg, struct bpf_insn *bpfBytecode, int *cnt, int max_cnt) {

    if (rand() % 2 == 0)
        initRegPtr(reg, regStates, bpfBytecode, cnt, max_cnt);
    else
        initRegScalar(reg, Bit64, regStates, bpfBytecode, cnt, 0, max_cnt, false);
}

// Load/Store instruction constraits:

inline bool isValidReg(int regno) {
    return regno < MAX_BPF_REG;	
}

bool isValidAtomicOp(struct bpf_insn *insn) {
    switch(insn->imm) {
        case BPF_ADD:
	    case BPF_ADD | BPF_FETCH:
	    case BPF_AND:
	    case BPF_AND | BPF_FETCH:
	    case BPF_OR:
	    case BPF_OR | BPF_FETCH:
	    case BPF_XOR:
	    case BPF_XOR | BPF_FETCH:
	    case BPF_XCHG:
	    case BPF_CMPXCHG:
            return true;
        default:
            return false;
    }
}

bool isValidLdImmSrc(struct bpf_insn *insn) {
    switch(insn->src_reg) {
        case BPF_PSEUDO_MAP_VALUE:
        case BPF_PSEUDO_MAP_IDX_VALUE:
        case BPF_PSEUDO_MAP_FD:
        case BPF_PSEUDO_MAP_IDX:
            return true;
        default:
            return false;
    }
}

bool checkStAtomicType(int type) {
    switch (type) {
        case PTR_TO_CTX:
        case PTR_TO_PACKET:
        case PTR_TO_PACKET_META:
        case PTR_TO_FLOW_KEYS:
        case PTR_TO_SOCKET:
        case PTR_TO_SOCK_COMMON:
        case PTR_TO_TCP_SOCK:
        case PTR_TO_XDP_SOCK:
            return false;
        default:
            return true;
    }
}

uint8_t bpf_size_to_bytes(unsigned char size) {
    switch (size) {
        case BPF_B:
            return 1;
        case BPF_H:
            return 2;
        case BPF_W:
            return 4;
        case BPF_DW:
            return 8;
        default:
            return 0;
    }
}


int get_off(struct regState *regstate, int size) {
    int real_size = bpf_size_to_bytes(size);
    int off = 0;
    switch (regstate->type) {
        case NOT_INIT:
            return 0;
        case SCALAR_VALUE:
            return 0;
        case PTR_TO_STACK:
            off = randRange(-512, -1);
            off -= (off % real_size);
            return off;
        default:
            // TODO
            off = randRange(0, 512);
            off += (off % real_size);
            return off;
    };
}

inline bool stackOffCheck(regState *regStates, unsigned char reg, signed short off, uint8_t size) {
    return (regStates[reg].type == PTR_TO_STACK && off < 0 && off > -512 && (!size || ((off + size -1) > -512 && (off + size -1) < 0 && !(off % size))));
}

inline void clobberScratchRegs(regState *regStates) {
    for (int i = 1; i < 6; i++) regStates[i].type = NOT_INIT;
}

bool commonLSCons(struct bpf_insn *insn, struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int max_cnt = NINSNS) {

    switch(insn->code & ~BPF_SIZE(0xffffffff)) {
        // case BPF_ST_MEM: BPF_ST | BPF_SIZE(SIZE) | BPF_MEM
        // *(size *) (dst + offset) = imm32
        case BPF_ST | BPF_MEM:
            if (insn->src_reg != BPF_REG_0) return false;                                                   /* Constraint 1 */
            if (regStates[insn->dst_reg].type == SCALAR_VALUE) return false;                                /* Constraint 5 */
            if (!stackOffCheck(regStates, insn->dst_reg, insn->off, bpf_size_to_bytes(BPF_SIZE(insn->code)))) return false;                          /* Constraint 4 */
            if (!initRegPtr(insn->dst_reg, regStates, bpfBytecode, cnt, max_cnt)) return false;                      /* Constraint 2 */
            break;
        //case BPF_STX_MEM: BPF_STX | BPF_SIZE(SIZE) | BPF_MEM
        // *(size *) (dst + offset) = src
        case BPF_STX | BPF_MEM:
            if (insn->imm != 0) return false;                                                              /* Constraint 1 */
            if (!(isValidReg(insn->src_reg) && isValidReg(insn->dst_reg))) return false;                    /* Constraint 2.1 */
            if (!initRegPtr(insn->dst_reg, regStates, bpfBytecode, cnt, max_cnt)) return false;                      /* Constraint 2.2 */
            DEUBG_LOC("initRegScalar");
            // if (!initRegScalar(insn->src_reg, Bit64, regStates, bpfBytecode, cnt, 0, max_cnt)) return false;    /* Constraint 2.3 */
            break;
        //case BPF_ATOMIC_OP: BPF_STX | BPF_SIZE(SIZE) | BPF_ATOMIC
        // *(u32 *)(dst + offset) += src
        case BPF_STX | BPF_ATOMIC:
            if (BPF_SIZE(insn->code) != BPF_W && BPF_SIZE(insn->code) != BPF_DW) return false;              /* Constraint 3.1 */
            if (!isValidAtomicOp(insn)) return false;                                                       /* Constraint 3.2 */
            if (insn->dst_reg == BPF_REG_10) return false;
            if (insn->imm == BPF_CMPXCHG && regStates[BPF_REG_0].type == PTR_TO_MAP_VALUE) return false;    /* Constraint 3.4 */
            if (regStates[insn->src_reg].type == PTR_TO_MAP_VALUE) return false;                            /* Constraint 3.5 */
            if (!checkStAtomicType(regStates[insn->dst_reg].type)) return false;                            /* Constraint 3.6 */
            if (!stackOffCheck(regStates, insn->src_reg, insn->off, bpf_size_to_bytes(BPF_SIZE(insn->code)))) return false;                          /* Constraint 3.8 */
            if (!stackOffCheck(regStates, insn->dst_reg, insn->off, bpf_size_to_bytes(BPF_SIZE(insn->code)))) return false;                          /* Constraint 3.8 */
            // fprintf(stderr, "atomic init\n");
            if (!initRegPtr(insn->dst_reg, regStates, bpfBytecode, cnt, max_cnt)) return false;                      /* Constraint 3.3 */
            if (!CommonInit(insn->src_reg, Bit64, regStates, bpfBytecode, cnt, max_cnt)) return false;               /* Constraint 3.3 */

            regStates[insn->src_reg].type = SCALAR_VALUE;
            if (insn->imm == BPF_CMPXCHG) {
                // regStates[insn->src_reg].type = PTR_TO_STACK;
                // regStates[insn->dst_reg].type = PTR_TO_STACK;
                regStates[BPF_REG_0].type = SCALAR_VALUE;
            } else {
                regStates[insn->src_reg].type = SCALAR_VALUE;
            }

            break;
        // case BPF_LDX_MEM: BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM
        // dst = *(size *) (src + offset)
        case BPF_LDX | BPF_MEMSX:
        case BPF_LDX | BPF_MEM:
            if (!(isValidReg(insn->src_reg) && isValidReg(insn->dst_reg))) return false;                    /* Constraint 1 */
            if (insn->dst_reg == BPF_REG_10) return false;                                                  /* Constraint 3 */
            if (regStates[insn->src_reg].type == SCALAR_VALUE) return false;                                /* Constraint 4 */
            if (!stackOffCheck(regStates, insn->src_reg, insn->off, bpf_size_to_bytes(BPF_SIZE(insn->code)))) return false;                          /* Constraint 9 */
            // fprintf(stderr, "init LDXMEM\n");
            if (!initRegPtr(insn->src_reg, regStates, bpfBytecode, cnt, max_cnt)) return false;                      /* Constraint 2, 4 */
            regStates[insn->dst_reg].type = SCALAR_VALUE;
            break;
        // case BPF_LD_IMM64: BPF_LD | BPF_DW | BPF_IMM + src = 0
        // case BPF_LD_MAP_FD: BPF_LD | BPF_DW | BPF_IMM + src = BPF_PSEUDO_MAP_FD
        // case BPF_LD_FD_MAPVALUE: BPF_LD | BPF_DW | BPF_IMM + src = BPF_PSEUDO_MAP_VALUE
        // case BPF_LD_PSEUDO_FUNC: BPF_LD | BPF_DW | BPF_IMM + src = BPF_PSEUDO_FUNC
        case BPF_LD | BPF_IMM:
            // fprintf(stderr, "con0 %x\n", BPF_SIZE(insn->code));
            if (BPF_SIZE(insn->code) != BPF_DW) return false;                                               /* Constraint 2.1 */
            // fprintf(stderr, "con1\n");
            if (insn->off != 0) return false;                                                               /* Constraint 2.2 */
            // fprintf(stderr, "con2\n");
            if (insn->dst_reg == BPF_REG_10) return false;                                                  /* Constraint 2.3 */
            // fprintf(stderr, "con3\n");
            if (insn->src_reg == BPF_PSEUDO_BTF_ID) {                                                       /* Constraint 2.4 */
                struct regState dst = regStates[insn->dst_reg];
                if (base_type(dst.type) != PTR_TO_MEM && base_type(dst.type) != PTR_TO_BTF_ID)
                    return false;
            }
            if (!isValidLdImmSrc(insn)) return false;                                                       /* Constraint 2.5 */
            // fprintf(stderr, "con4\n");
            break;
        // case BPF_LD_ABS: BPF_LD | BPF_SIZE(SIZE) | BPF_ABS
        // case BPF_LD_IND: BPF_LD | BPF_SIZE(SIZE) | BPF_IND
        // R0 = *(uint *) (skb->data + imm32)
        case BPF_LD | BPF_ABS:
            if (insn->dst_reg != BPF_REG_0) return false;                                                   /* Constraint 3.1 */
            if (insn->off != 0) return false;                                                               /* Constraint 3.2 */
            if (BPF_SIZE(insn->code) == BPF_DW) return false;                                               /* Constraint 3.3 */
            if (regStates[BPF_REG_6].type != PTR_TO_CTX) return false;                                      /* Constraint 3.4 */
            if (insn->src_reg != BPF_REG_0) return false;                                                   /* Constraint 4 */
            regStates[BPF_REG_0].type = SCALAR_VALUE;
            clobberScratchRegs(regStates);
            break;
        case BPF_LD | BPF_IND:
            if (insn->dst_reg != BPF_REG_0) return false;                                                   /* Constraint 3.1 */
            if (insn->off != 0) return false;                                                               /* Constraint 3.2 */    
            if (BPF_SIZE(insn->code) == BPF_DW) return false;                                               /* Constraint 3.3 */
            if (regStates[BPF_REG_6].type != PTR_TO_CTX) return false;                                      /* Constraint 3.4 */
            // fprintf(stderr, "init LDIND\n");
            if(!initRegPtr(insn->src_reg, regStates, bpfBytecode, cnt, max_cnt)) return false;                       /* Constraint 5 */
            regStates[BPF_REG_0].type = SCALAR_VALUE;
            clobberScratchRegs(regStates);
            break;
    }

    // fprintf(stderr, "it's valid\n");
    return true;
}


