#include <sstream>
#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <iostream>
#include <chrono>
#include <cstdint>
#include <map>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <cstring>
#include <mutex>
#include <atomic>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <linux/bpf.h>

#include "verifybpfprog.hpp"

#include "../prog/bpf_complete_insn.h"
#include "../prog/bpf_insn.h"

/*
    Find the first instruction that use the reg as a src operand instead of dst operand
*/


void nonExitInsn2Dafny(struct bpf_insn *insn, std::vector<int>& stacked_branches, bool *regs_taint) {

    int src = insn->src_reg;
    int dst = insn->dst_reg;
    uint8_t op = BPF_OP(insn->code);

    switch (BPF_CLASS(insn->code)) {

		case BPF_ALU:
			// op32 = true;
		case BPF_ALU64:

			switch (op) {
				case BPF_NEG:
					// Neg32, Neg64
                    if (regs_taint[dst]) {
                        std::cerr << "BPF_NEG requires on reg " << dst << std::endl;
                        // regs_taint[dst] = true;
                    }
					break;

				case BPF_END:
					// Bv2be16, Bv2be32, Bv2be64, Bv2le16, Bv2le32, Bv2le64, Bv2swap16, Bv2swap32, Bvswap64
					if (regs_taint[dst]) {
                        std::cerr << "BPF_NEG requires on reg " << dst << std::endl;
                        // regs_taint[dst] = true;
                    }
					break;

				case BPF_MOV:
					// Mov32_REG, Mov32_IMM, Mov32SX8, Mov32SX16, Mov64_REG, Mov64_IMM, Mov64SX8, Mov64SX16, Mov64SX32
					if (regs_taint[src]) {
                        std::cerr << "BPF_NEG requires on reg " << src << std::endl;
                        regs_taint[dst] = true;
                    } else {
                        regs_taint[dst] = false;
                    }
					break;

				case BPF_ADD:	
					// Add32_REG, Add32_IMM, Add64_REG, Add64_IMM
				case BPF_SUB:
					// Sub32_REG, Sub32_IMM, Sub64_REG, Sub64_IMM
				case BPF_MUL:
					// Mul32_REG, Mul32_IMM, Mul64_REG, Mul64_IMM
				case BPF_OR:
					// Bvor32_REG, Bvor32_IMM, Bvor64_REG, Bvor64_IMM
				case BPF_AND:
					// Bvand32_REG, Bvand32_IMM, Bvand64_REG, Bvand64_IMM
				case BPF_XOR:
					// Bvxor32_REG, Bvxor32_IMM, Bvxor64_REG, Bvxor64_IMM
				case BPF_LSH:
					// Bvshl32_REG, Bvshl32_IMM, Bvshl64_REG, Bvxor64_REG
				case BPF_RSH:
					// Bvlshr32_REG, Bvlshr32_IMM, Bvlshr64_REG, Bvlshr64_IMM
				case BPF_ARSH:
					// Bvashr32_REG, Bvashr32_IMM, Bvashr64_REG, Bvashr64_IMM
					//
                case BPF_DIV:
					// Div32_REG, Div32_IMM, SDiv32_REG, SDiv32_IMM, Div64_REG, Div64_IMM, SDiv64_REG, SDiv64_IMM
				case BPF_MOD:
					// Mod32_REG, Mod32_IMM, SMod32_REG, SMod32_IMM, Mod64_REG, Mod64_IMM, SMod64_REG, SMod64_IMM
                    if (regs_taint[src]) {
                        std::cerr << "ALU requires on reg " << src << std::endl;
                        regs_taint[dst] = true;
                    }
                    
                    if (regs_taint[dst]) {
                        std::cerr << "ALU requires on reg " << dst << std::endl;
                        regs_taint[dst] = true;
                    }
                    
                    if (!regs_taint[src] && !regs_taint[dst]) {
                        regs_taint[dst] = false;
                    }
					break;
				default:
					std::cerr << "Unable to translate this ALU instruction: " << std::endl;
					break;
			}
			break;

		case BPF_LDX:

            if (regs_taint[src]) {
                std::cerr << "BPF_LDX requires on reg " << src << std::endl;
                regs_taint[dst] = true;
            }
            
            if (regs_taint[dst]) {
                std::cerr << "BPF_LDX requires on reg " << dst << std::endl;
                regs_taint[dst] = true;
            }
            
            if (!regs_taint[src] && !regs_taint[dst]) {
                regs_taint[dst] = false;
            }
            break;

		case BPF_ST:

            if (regs_taint[dst]) {
                std::cerr << "BPF_ST requires on reg " << dst << std::endl;
            }
			break;

		case BPF_STX:
            if (regs_taint[src]) {
                std::cerr << "BPF_STX requires on reg " << src << std::endl;
                regs_taint[dst] = true;
            }
            
            if (regs_taint[dst]) {
                std::cerr << "BPF_STX requires on reg " << dst << std::endl;
                regs_taint[dst] = true;
            }
            
			break;

		case BPF_JMP:
		case BPF_JMP32:
			switch (BPF_OP(insn->code)) {
				
				case BPF_CALL:
					std::cerr << "Unable to translate this BPF_CALL instruction: " << int(insn->imm) << std::endl;
					break;
				// Conditional and unconditional jumps
				case BPF_JA:
					// Unconditional goto: directly translate the code here
					break;

// Define
#define ISNEQ64REGELSE 0x40000000
#define GENERATE_BRANCH(INSN, JMPNAME)                                 			\
    if (BPF_SRC(INSN->code) == BPF_X && regs_taint[INSN->src_reg]) {    \
        std::cerr << "BPF_NEG requires on reg " << INSN->src_reg << std::endl;                            \
            \
    }                                                                           \
    if (INSN->dst_reg) {                                    \
        std::cerr << "BPF_NEG requires on reg " << INSN->dst_reg << std::endl;                            \
        \
    }
// END

				case BPF_JEQ:
					GENERATE_BRANCH(insn, "JEQ");
					break;
				
				case BPF_JSET:
					GENERATE_BRANCH(insn, "JSET");
					break;

				case BPF_JNE:
					GENERATE_BRANCH(insn, "JNE");
					break;


				case BPF_JGT:
					GENERATE_BRANCH(insn, "JGT");
					break;

				case BPF_JGE:
					GENERATE_BRANCH(insn, "JGE");
					break;

				case BPF_JSGT:
					GENERATE_BRANCH(insn, "JSGT");
					break;

				case BPF_JSGE:
					GENERATE_BRANCH(insn, "JSGE");
					break;

				case BPF_JLT:
					GENERATE_BRANCH(insn, "JLT");
					break;

				case BPF_JLE:
					GENERATE_BRANCH(insn, "JLE");
					break;

				case BPF_JSLT:
					GENERATE_BRANCH(insn, "JSLT");
					break;

				case BPF_JSLE:
					GENERATE_BRANCH(insn, "JSLE");
					break;

				default:
					std::cerr << "Unable to translate this conditional jump instruction: " << std::endl;
					break;
			}
		
			break;
		
		default:
			std::cerr << "Unable to translate this unknown instruction: " << std::endl;
			break;
	}
}



int main(void) {
    
    struct bpf_insn insns[] = {
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_6, offsetof(struct __sk_buff, mark)),
        BPF_LD_MAP_FD(BPF_REG_1, 0),
        BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),
        BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
        BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),
        BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),
        BPF_MOV64_REG(BPF_REG_1, BPF_REG_7),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 4),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_spin_lock),
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0, 1),
        BPF_JMP_IMM(BPF_JA, 0, 0, 1),
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_8),
        BPF_MOV64_REG(BPF_REG_1, BPF_REG_7),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 4),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_spin_unlock),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };

    std::vector<int> stacked_branches;
    int insn_idx = 0;
    bool regs_taint[10] = {false};

    for (int i = 0; i < 10; i++) {
        regs_taint[i] = true;
    }

    while (true) {

		if (insn_idx >= sizeof(insns)/sizeof(struct bpf_insn)) {
			return 0;
		}

        struct bpf_insn *insn = &(insns[insn_idx]);

        // BPF_EXIT
		if (insn->code == (BPF_JMP | BPF_EXIT)) {
			
			if (stacked_branches.size() == 0) {
				break;
			} else {
				int stacked_point = stacked_branches.back();
				stacked_branches.pop_back();
				insn_idx = stacked_point;
			}
		}		
		// Other instructions
		else {
			nonExitInsn2Dafny(insn, stacked_branches, regs_taint);
			//
			if (insn->code == (BPF_JMP32 | BPF_JA)) {
				insn_idx += insn->imm + 1;
			} else if (insn->code == (BPF_JMP | BPF_JA)) {
				insn_idx += insn->off + 1;
			} else {
				insn_idx ++;
			}
		}
    }
}