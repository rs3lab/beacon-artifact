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
#include <regex>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <linux/bpf.h>

#include "shared-header.hpp"

#include "../prog/bpf_complete_insn.h"

#include "trancimport.hpp"
#include "ebpf2dafny.hpp"
#include "linux-btfs.hpp"

/*
	TODO:
		- Translate progtype and create maps:
			- this.allow_ptr_leak == true;
			- this.bypass_spec_v1 == true;
			- this.priv == true;

		- translate map: writable
*/

int nonExitInsn2Dafny(struct bpf_insn *insn, int insn_idx, std::stringstream & trans_dafny,
				std::vector<int>& stacked_branches, bool *used_regs) {

	int ls_size = BPF_SIZE(insn->code);
	bool isSigned = false;
	bool op32 = false,
		is_reg = BPF_SRC(insn->code);

	uint8_t op = BPF_OP(insn->code),
			op_idx = op >> 4;

	std::string size_str;
	size_t index = 0;

	std::string indents(floor_division(stacked_branches.size(), 2) + 1, '\t');

	switch (BPF_CLASS(insn->code)) {

		case BPF_ALU:
			op32 = true;
		case BPF_ALU64:

			switch (op) {
				case BPF_NEG:
					used_regs[insn->dst_reg] = true;
					// Neg32, Neg64
					trans_dafny << indents << (op32 ? "s.Neg32(s.r" : "s.Neg64(s.r") << int(insn->dst_reg)
								<< ", s.r" << int(insn->src_reg) << ");" << annotate(insn_idx) << "\n"; //std::string(int(
					break;

				case BPF_END:
					// Bv2be16, Bv2be32, Bv2be64, Bv2le16, Bv2le32, Bv2le64, Bv2swap16, Bv2swap32, Bvswap64
					used_regs[insn->dst_reg] = true;
					trans_dafny << indents << "s.Bv2";
					switch (BPF_SRC(insn->code)) {
						case BPF_TO_BE: trans_dafny << "be"; break;
						// swap and converting to little endian has the same BPF_SRC, but swap is BPF_ALU64 while little endian is BPF_ALU
						case BPF_TO_LE: trans_dafny << (op32 ? "le" : "swap"); break;
					}
					trans_dafny << insn->imm << "(s.r" << int(insn->dst_reg)
								<< ", s.r" << int(insn->src_reg) << ");" << annotate(insn_idx) << "\n";
					break;

				case BPF_MOV:
					// Mov32_REG, Mov32_IMM, Mov32SX8, Mov32SX16, Mov64_REG, Mov64_IMM, Mov64SX8, Mov64SX16, Mov64SX32
					if (is_reg) used_regs[insn->src_reg] = true;

					trans_dafny << indents << "s.Mov"
								<< (op32 ? "32" : "64");
					if (insn->off == 0) trans_dafny << (is_reg ? "_REG" : "_IMM");
					else trans_dafny << "SX" << int(insn->off);
					// dst
					trans_dafny << "(s.r" << int(insn->dst_reg) << ", "
								<< (is_reg ? ("s.r" + std::to_string(insn->src_reg)) : std::to_string(insn->imm))
								<< ");" << annotate(insn_idx) << "\n";
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
					used_regs[insn->dst_reg] = true;
					if (is_reg) used_regs[insn->src_reg] = true;
					trans_dafny << indents << "s." << op2dafnyop[op_idx]
								<< (op32 ? "32" : "64")
								<< (is_reg ? "_REG" : "_IMM")
								<< "(s.r" << int(insn->dst_reg) << ", "
								<< (is_reg ? ("s.r" + std::to_string(insn->src_reg)) : std::to_string(insn->imm))
								<< ");" << annotate(insn_idx) << "\n";
					break;

				case BPF_DIV:
					// Div32_REG, Div32_IMM, SDiv32_REG, SDiv32_IMM, Div64_REG, Div64_IMM, SDiv64_REG, SDiv64_IMM
				case BPF_MOD:
					// Mod32_REG, Mod32_IMM, SMod32_REG, SMod32_IMM, Mod64_REG, Mod64_IMM, SMod64_REG, SMod64_IMM
					used_regs[insn->dst_reg] = true;
					if (is_reg) used_regs[insn->src_reg] = true;
					trans_dafny << indents << (insn->off == 1 ? "s.S" : "s.")
								<< op2dafnyop[op_idx]
								<< (op32 ? "32":"64")
								<< (is_reg ? "_REG":"_IMM")
								<< "(s.r" << int(insn->dst_reg) << ", "
								<< (is_reg ? ("s.r" + std::to_string(insn->src_reg)) : std::to_string(insn->imm))
								<< ");" << annotate(insn_idx) << "\n";
					break;
				default:
					std::cerr << "Unable to translate this ALU instruction: " << std::endl;
					return -1;
			}
			break;

		case BPF_LD:

			if (insn->code == (BPF_LD | BPF_DW | BPF_IMM)) {

				// Load 64-bit immediate
				// BPF_LD_IMM64(DST, IMM)
				if (insn->src_reg == 0) {
					// trans_dafny << indents << "// " << ((uint32_t)insn->imm) << " " << ((uint32_t)((insn+1)->imm)) << "\n";
					trans_dafny << indents << "s.Load_Imm64(s.r"
								<< int(insn->dst_reg) << ", "
								<< (int64_t)(((uint64_t)((uint32_t)insn->imm)) + (((uint64_t)((uint32_t)((insn+1)->imm))) << 32))
								<< ");" << annotate(insn_idx) << "\n";
				}

				// Load map pointer
				// BPF_LD_MAP_FD(DST, MAP_FD)
				else if (insn->src_reg == BPF_PSEUDO_MAP_FD) {
					trans_dafny << indents << "s.Load_MAPFD(s.r"
								<< int(insn->dst_reg) << ", "
								<< (int64_t)(((uint64_t)((uint32_t)insn->imm)) + (((uint64_t)((uint32_t)((insn+1)->imm))) << 32))
								<< ");" << annotate(insn_idx) << "\n";
				}

				//
				else if (insn->src_reg == BPF_PSEUDO_MAP_IDX) {
					trans_dafny << indents << "s.Load_MAPFDIDX(s.r"
								<< int(insn->dst_reg) << ", "
								<< (int64_t)(((uint64_t)((uint32_t)insn->imm)) + (((uint64_t)((uint32_t)((insn+1)->imm))) << 32))
								<< ");" << annotate(insn_idx) << "\n";
				}
				
				else if (insn->src_reg == BPF_PSEUDO_MAP_VALUE) {
					trans_dafny << indents << "s.Load_MAPVALUE_BYFD(s.r"
								<< int(insn->dst_reg) << ", "
								<< int(insn->imm) << ", "
								<< int((insn+1)->imm)
								<< ");" << annotate(insn_idx) << "\n";
				}
				
				else if (insn->src_reg == BPF_PSEUDO_MAP_IDX_VALUE) {
					trans_dafny << indents << "s.Load_MAPVALUE_BYFDIDX(s.r"
								<< int(insn->dst_reg) << ", "
								<< int(insn->imm) << ", "
								<< int((insn+1)->imm)
								<< ");" << annotate(insn_idx) << "\n";
				}

				// Load function pointer
				// BPF_RAW_INSN(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_2, BPF_PSEUDO_FUNC, 0, 6) <= BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)
				else if (insn->src_reg == BPF_PSEUDO_FUNC) {
					trans_dafny << indents << "s.Load_PSEUDOFUNC(s.r"
								<< int(insn->dst_reg) << ", " << int(insn->imm)
								<< ");" << annotate(insn_idx) << "\n";
				} 
				else {
					std::cerr << "Cannot find the corresponding spec for insn with (BPF_LD | BPF_DW | BPF_IMM) code" << std::endl;
					return -1;
				}
			} else {
				std::cerr << "Cannot find the corresponding spec for insn with BPF_LD code" << std::endl;
				return -1;
			}
			break;

		case BPF_LDX:

			used_regs[insn->src_reg] = true;

			// (dst:RegState, src:RegState, off:int64, size:int64, signExt:bool)
			// Load_MAPFD(dst:RegState, src:RegState, mapFd:int64) 
			// Load_SOCK(dst:RegState, src:RegState, off:int64, size:int64, sock_type: REGTYPE)
			isSigned = (BPF_MODE(insn->code) == BPF_MEMSX);

			if (insn->src_reg == BPF_REG_10) {
				trans_dafny << " s.Load_STACKMEM(s.r" << int(insn->dst_reg)
							<< ", s.r" << int(insn->src_reg) << ", "
							<< int(insn->off) << ", "
							<< sizeMarco2num[ls_size] << ", "
							<< (isSigned ? "true" : "false")
							<< ");" << annotate(insn_idx) << "\n";
			} else {
				for (const auto& pair : memTypes2Opname) {
					// std::cout << pair.first << " => " << pair.second << std::endl;
					trans_dafny << indents << (index == 0 ? "if " : "} else if ")
								<< "s.r" << int(insn->src_reg) << ".regType == " << pair.first << " { "
								<< " s.Load_" << pair.second
								<< "(s.r" << int(insn->dst_reg)
								<< ", s.r" << int(insn->src_reg) << ", "
								<< int(insn->off) << ", "
								<< sizeMarco2num[ls_size] << ", ";

					if (pair.second == "SOCK") {
						trans_dafny << pair.first;
					} else {
						trans_dafny << (isSigned ? "true" : "false");
					}
					
					trans_dafny << ");" << annotate(insn_idx) << "\n";
					index ++;
				}
				trans_dafny << indents << "} else { assert false; }" << annotate(insn_idx) << "\n";
			}
			break;

		case BPF_ST:
			
			used_regs[insn->dst_reg] = true;

			// Express an immediate with a RegState structure, whose regNo is Rn
			trans_dafny << "immReg.regVal := " << int(insn->imm) << "; "
						<< "immReg.regType := SCALAR;\n";

			if (insn->dst_reg == BPF_REG_10) {
				trans_dafny << " s.Store_STACKMEM(s.r" << int(insn->dst_reg)
							<< ", immReg, "
							<< insn->off << ", "
							<< sizeMarco2num[ls_size]
							<< ");" << annotate(insn_idx) << "\n";
			} else {
				for (const auto& pair : memTypes2Opname) {
				// for (size_t i = 0; i < sizeof(memTypes) / sizeof(memTypes[0]); ++i) {
					trans_dafny << indents << (index == 0 ? "if " : "} else if ")
								<< "s.r" << int(insn->dst_reg) << ".regType == " << pair.first << " { "
								<< " s.Store_" << pair.second
								<< "(s.r" << int(insn->dst_reg)
								<< ", immReg, "
								<< insn->off << ", "
								<< sizeMarco2num[ls_size]
								<< ");" << annotate(insn_idx) << "\n";
					index ++;
				}
				trans_dafny << indents << "} else { assert false; }" << annotate(insn_idx) << "\n";
			}
			break;

		case BPF_STX:

			used_regs[insn->dst_reg] = true;
			used_regs[insn->src_reg] = true;

			// (dst:RegState, src:RegState, off:int64, size:int64, isFetch: bool)
			if (insn->dst_reg == BPF_REG_10) {
				trans_dafny << ((BPF_MODE(insn->code) == BPF_ATOMIC) ? " s.AtomicLS_STACKMEM" : "s.Store_STACKMEM")
							<< "(s.r" << int(insn->dst_reg)
							<< ", s.r" << int(insn->src_reg) << ", "
							<< insn->off << ", "
							<< sizeMarco2num[ls_size];
				
				if (BPF_MODE(insn->code) == BPF_ATOMIC) {
						trans_dafny << ", " << ((insn->imm & BPF_FETCH) ? "true" : "false");
				}
				trans_dafny << ");" << annotate(insn_idx) << "\n";
			} else {
				for (const auto& pair : memTypes2Opname) {
					trans_dafny << indents << (index == 0 ? "if " : "} else if ")
								<< "s.r" << int(insn->dst_reg) << ".regType == " << pair.first << " { "
								// check if it's atomic load/store or general store
								<< ((BPF_MODE(insn->code) == BPF_ATOMIC) ? " s.AtomicLS_" : "s.Store_") << pair.second
								<< "(s.r" << int(insn->dst_reg)
								<< ", s.r" << int(insn->src_reg) << ", "
								<< insn->off << ", "
								<< sizeMarco2num[ls_size];
					
					// isFetch for AtomicLS
					if (BPF_MODE(insn->code) == BPF_ATOMIC) {
						trans_dafny << ", " << ((insn->imm & BPF_FETCH) ? "true" : "false");
					}
					trans_dafny << ");" << annotate(insn_idx) << "\n";

					index ++;
				}
				trans_dafny << "\t} else { assert false; }" << annotate(insn_idx) << "\n";
			}
			break;

		case BPF_JMP:
		case BPF_JMP32:
			switch (BPF_OP(insn->code)) {
				
				case BPF_CALL:

					used_regs[BPF_REG_1] = true;
					used_regs[BPF_REG_2] = true;
					used_regs[BPF_REG_3] = true;
					used_regs[BPF_REG_4] = true;
					used_regs[BPF_REG_5] = true;

					if (insn->src_reg == BPF_PSEUDO_CALL) {
						// pseudo_call: imm is the offset to the pseudo
						trans_dafny << indents << "s.pseudo_local_call(anybv8);" << annotate(insn_idx) << "\n";
						// Inline pseudo calls
						//
					} else if (insn->src_reg == BPF_PSEUDO_KFUNC_CALL) {
						// kfunc_call: insn->imm is the BTF id of kfunc
						if (btfid_2_name.find(insn->imm) != btfid_2_name.end()) {
							trans_dafny << indents << "s." << btfid_2_name[insn->imm]
										<< "();" << annotate(insn_idx) << "\n";
						} else {
							std::cerr << "Kfunc ID is not in our list: " << int(insn->imm) << std::endl;
							return -1;
						}
					} else {
						// helper call
						if (insn->imm < 0 || insn->imm >= sizeof(helper_names) / sizeof(helper_names[0])) {
							std::cerr << "Wrong helper call number: " << int(insn->imm) << std::endl;
							return -1;
						}
						trans_dafny << indents << "s." << helper_names[insn->imm]
									<< "();" << annotate(insn_idx) << "\n";
					}
					break;

					/*
						get_cgroup_classid
						get_prandom_u32
						jiffies64
						kptr_xchg
						ktime_get_ns
						loop
						map_delete_elem
						map_lookup_elem
						perf_event_output
						probe_read_kernel
						ringbuf_reserve
						ringbuf_submit
						skb_vlan_push
						this_cpu_ptr
						xdp_adjust_head
					*/

				// Conditional and unconditional jumps
				case BPF_JA:
					// Unconditional goto: directly translate the code here
					break;

// Define
#define bitmask 0x70000000
#define ISNEQ64REGELSE 0x40000000
#define BRANCH 0x20000000
#define UNROLL_CALL 0x10000000

#define GENERATE_BRANCH(INSN, JMPNAME)                                 			\
    trans_dafny << indents << "if (!";											\
	size_str = ((BPF_CLASS(INSN->code) == BPF_JMP32) ? "32" : "64");			\
	if (BPF_SRC(INSN->code) == BPF_X) {											\
		trans_dafny << "s." << (JMPNAME) << size_str << "_REG(" << "s.r" << int(INSN->dst_reg) << ", s.r" << int(INSN->src_reg);	\
		used_regs[INSN->dst_reg] = true;												\
		used_regs[INSN->src_reg] = true;												\
	} else {																	\
		trans_dafny << "s." << (JMPNAME) << size_str << "_IMM(" << "s.r" << int(INSN->dst_reg) << ", "<< int(INSN->imm);			\
		used_regs[INSN->dst_reg] = true;												\
	}																			\
	trans_dafny << ")) {" << annotate(insn_idx) << "\n";													\
	stacked_branches.push_back(-1);												\
	if (!strcmp(JMPNAME, "JNE") && BPF_SRC(INSN->code) == BPF_X && (BPF_CLASS(INSN->code) == BPF_JMP) && INSN->dst_reg != INSN->src_reg) {	\
		stacked_branches.push_back((insn_idx + INSN->off + 1) | ISNEQ64REGELSE | BRANCH);					\
	} else {																						\
		stacked_branches.push_back((insn_idx + INSN->off + 1) | BRANCH);										\
	}
// END


// Define
// Note: why use "if (!)" => when condition is not satisified, execute the fall-through branch
#define GENERATE_BRANCH_LGJMP(INSN, JMPNAME)                              		\
	trans_dafny << indents << "if (!";											\
	size_str = ((BPF_CLASS(INSN->code) == BPF_JMP32) ? "32" : "64");			\
	if (BPF_SRC(INSN->code) == BPF_X) {											\
		trans_dafny << "s.LGJMP" << size_str << "_REG(" << "s.r" << int(INSN->dst_reg) << ", s.r" << int(INSN->src_reg);	\
		used_regs[INSN->dst_reg] = true;												\
		used_regs[INSN->src_reg] = true;												\
	} else {																	\
		trans_dafny << "s.LGJMP" << size_str << "_IMM(" << "s.r" << int(INSN->dst_reg) << ", "<< int(INSN->imm);			\
		used_regs[INSN->dst_reg] = true;												\
	}																			\
	trans_dafny << ", " << (JMPNAME) << ")) {" << annotate(insn_idx) << "\n";	\
	stacked_branches.push_back(-1);												\
	stacked_branches.push_back((insn_idx + INSN->off + 1) | BRANCH);
// END

				case BPF_JEQ:
					GENERATE_BRANCH(insn, "JEQ");
					if (BPF_CLASS(insn->code) == BPF_JMP && BPF_SRC(insn->code) == BPF_X && insn->dst_reg != insn->src_reg) {
						// "assume {:axiom} (Ptr_or_NULL(dst.regType) && NonNULLPtr(src.regType)) ==> dst.regType != NULL;\n";
						trans_dafny << "assume {:axiom} (Ptr_or_NULL(" << "s.r" << int(insn->dst_reg)
									<< ".regType) && NonNULLPtr(" << "s.r" << int(insn->src_reg) << ".regType)) ==> "
									<< "s.r" << int(insn->dst_reg) << ".regType != NULL;\n";
    					// trans_dafny << "assume {:axiom} (NonNULLPtr(dst.regType) && Ptr_or_NULL(src.regType)) ==> src.regType != NULL;\n";
						trans_dafny << "assume {:axiom} (Ptr_or_NULL(" << "s.r" << int(insn->src_reg)
									<< ".regType) && NonNULLPtr(" << "s.r" << int(insn->dst_reg) << ".regType)) ==> "
									<< "s.r" << int(insn->src_reg) << ".regType != NULL;\n";
					}
					break;
				
				case BPF_JSET:
					GENERATE_BRANCH(insn, "JSET");
					break;

				case BPF_JNE:
					GENERATE_BRANCH(insn, "JNE");
					break;


				case BPF_JGT:
					GENERATE_BRANCH_LGJMP(insn, "JGT");
					break;

				case BPF_JGE:
					GENERATE_BRANCH_LGJMP(insn, "JGE");
					break;

				case BPF_JSGT:
					GENERATE_BRANCH_LGJMP(insn, "JSGT");
					break;

				case BPF_JSGE:
					GENERATE_BRANCH_LGJMP(insn, "JSGE");
					break;

				case BPF_JLT:
					GENERATE_BRANCH_LGJMP(insn, "JLT");
					break;

				case BPF_JLE:
					GENERATE_BRANCH_LGJMP(insn, "JLE");
					break;

				case BPF_JSLT:
					GENERATE_BRANCH_LGJMP(insn, "JSLT");
					break;

				case BPF_JSLE:
					GENERATE_BRANCH_LGJMP(insn, "JSLE");
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

	return 0;
}

int insns2Dafny(union bpf_attr *prog_attr, std::stringstream & trans_dafny, bool *used_regs,
		struct verify_range *range, uint64_t *total_paths, uint64_t *duration) {

	int insn_idx = 0, trans_cnt = 0;
	std::vector<int> stacked_branches;
	bool insn_idx_unchanged = false, has_if = false;

	// Only verify a short sequence before the failed insn
	if (range) insn_idx = range->start;

	if (prog_attr->insn_cnt < 1)
		return 0;

	auto start = std::chrono::high_resolution_clock::now();

	trans_dafny << "\t" << "var immReg := new RegState(Rn);\n";
	trans_dafny << "\t" << "var anybv8 := AnyBv8();\n";

	while (true) {

		if (trans_cnt > 1000)
			break;

		if (insn_idx == -1) {
			if (stacked_branches.size() > 0) {
				int stacked_point = stacked_branches.back();
				stacked_branches.pop_back();
				if (stacked_point == -1) {
					std::string indents((stacked_branches.size()/2) + 1, '\t');
					trans_dafny << indents << "}\n";
				} else {
					std::string indents((stacked_branches.size()/2) + 1, '\t');
					trans_dafny << indents << "} else {\n";
					insn_idx = stacked_point & (~bitmask);
				}	
				continue;
			} else {
				break;
			}
		}

		if (insn_idx >= prog_attr->insn_cnt) {
			// trans_dafny << "\nERROR: traverse out of the instruction range.";
			return insn_idx;
		}

		// Only verify a short sequence before the failed insn
		if (range && insn_idx > range->end) {
			trans_dafny << "// size of stack_branches: " << int(stacked_branches.size()) << "\n";
			std::string end_brackets (floor_division(stacked_branches.size(), 2), '}');
			trans_dafny << "\t" << end_brackets << "\n";
			*total_paths += 1;
			break;
		}

		trans_cnt ++;
		struct bpf_insn *insn = &(((struct bpf_insn *)prog_attr->insns)[insn_idx]);
		
		// BPF_EXIT
		if (insn->code == (BPF_JMP | BPF_EXIT)) {
			
			*total_paths += 1;

			used_regs[BPF_REG_0] = true;
			if (stacked_branches.size() == 0) {
				if (!has_if)
					trans_dafny << "\t" << "s.EXIT(); // 1 " << annotate(insn_idx) << "\n";
				break;
				// continue;
			} else {
				int stacked_point = stacked_branches.back();
				stacked_branches.pop_back();
				// trans_dafny << "// stacked_branches pop out: " << int(stacked_branches.size()) << std::endl;
				//
				
				if (stacked_point == -1) {
				
					std::string indents((stacked_branches.size()/2) + 2, '\t');

					if (!insn_idx_unchanged)
						trans_dafny << indents << "s.EXIT(); // 2 " << annotate(insn_idx) << "\n";
					
					// the last bracket of one "if {} else {}"
					trans_dafny << indents << "}\n";
					insn_idx_unchanged = true;
					insn_idx = -1;
					// Cannot break here, we have pop out all remaining brackets from the stacked_branches
				
				// Finish the if branch
				} else if (stacked_point & BRANCH) {

					has_if = true;
					std::string indents((stacked_branches.size()/2) + 1, '\t');

					trans_dafny << indents << "s.EXIT(); // 3 " << annotate(insn_idx) << "\n";
					trans_dafny << indents << "} else {\n";
					if (stacked_point & ISNEQ64REGELSE) {
						std::string indents2((stacked_branches.size()/2) + 1, '\t');
						// "assume {:axiom} (Ptr_or_NULL(dst.regType) && NonNULLPtr(src.regType)) ==> dst.regType != NULL;\n";
						trans_dafny << indents2 
									<< "assume {:axiom} (Ptr_or_NULL(" << "s.r" << int(insn->dst_reg)
									<< ".regType) && NonNULLPtr(" << "s.r" << int(insn->src_reg) << ".regType)) ==> "
									<< "s.r" << int(insn->dst_reg) << ".regType != NULL;\n";
    					// trans_dafny << "assume {:axiom} (NonNULLPtr(dst.regType) && Ptr_or_NULL(src.regType)) ==> src.regType != NULL;\n";
						trans_dafny << indents2 
									<< "assume {:axiom} (Ptr_or_NULL(" << "s.r" << int(insn->src_reg)
									<< ".regType) && NonNULLPtr(" << "s.r" << int(insn->dst_reg) << ".regType)) ==> "
									<< "s.r" << int(insn->src_reg) << ".regType != NULL;\n";
						insn_idx = stacked_point & (~bitmask);
					} else {
						insn_idx = stacked_point & (~bitmask);
					}
				
					insn_idx_unchanged = false;

				// Return from PSEUDO_CALL
				} else if (stacked_point & UNROLL_CALL) {

					std::string indents((stacked_branches.size()/2) + 2, '\t');
					trans_dafny << indents << "s.EXIT(); // 4 " << annotate(insn_idx) << "\n";
					trans_dafny << indents << "}\n";
					insn_idx = stacked_point & (~bitmask);

					insn_idx_unchanged = false;
				}
			}
		}		
		// Other instructions
		else {
			// class == BPF_JMP || class == BPF_JMP32
			// opcode == BPF_CALL
			int ret = nonExitInsn2Dafny(insn, insn_idx, trans_dafny, stacked_branches, used_regs);
			if (ret == -1) return ret;
			//
			// Load 64-bit imm and map-fd using two insns.
			if (insn->code == (BPF_LD | BPF_DW | BPF_IMM) && (
					insn->src_reg == 0 || // LD_IMM64
					insn->src_reg == BPF_PSEUDO_MAP_FD || insn->src_reg == BPF_PSEUDO_MAP_IDX ||
					insn->src_reg == BPF_PSEUDO_MAP_VALUE || insn->src_reg == BPF_PSEUDO_MAP_IDX_VALUE)
				)
			{
				insn_idx += 2;
			} else if (insn->code == (BPF_JMP | BPF_CALL) && insn->src_reg == BPF_PSEUDO_CALL) {
				// save the caller's next insn
				stacked_branches.push_back((insn_idx + 1) | UNROLL_CALL);
				insn_idx += insn->imm + 1;
			} else if (insn->code == (BPF_JMP32 | BPF_JA)) {
				insn_idx += insn->imm + 1;
			} else if (insn->code == (BPF_JMP | BPF_JA)) {
				insn_idx += insn->off + 1;
			} else {
				insn_idx ++;
			}

			insn_idx_unchanged = false;
		}
	}

	auto end = std::chrono::high_resolution_clock::now();
	*duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

	return trans_cnt;
}

// std::string execute_cmd(std::string final_dafny, union bpf_attr* progAttr, int runtime_res, int trans_cnt) {

std::string execute_cmd(std::string final_dafny, uint64_t *duration) {

	// write dafny code into the file /tmp/ebpf.dfy
	uint64_t currentValue = globalCounter.fetch_add(1);
	std::string fn_name = "/tmp/ebpf" + std::to_string(currentValue) + ".dfy";
	std::ofstream file(fn_name, std::ios::out);
	if (file.is_open()) {
        file << final_dafny << std::endl;
        file.close();
    } else {
        std::cerr << "Unable to open the file." << std::endl;
        exit(0);
    }
	file.close();

	auto start = std::chrono::high_resolution_clock::now();

    // FILE* pipe = popen("/home/tlyu/ebpf-fuzzing/dafny-ebpf/dafny/dafny verify --cores 50 /tmp/ebpf.dfy", "r");
	std::string cmd = "/usr/bin/dotnet ./dafny-tool/Dafny.dll \
						verify --verification-time-limit 300 --cores 3 " + fn_name;
	FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        std::cerr << "Failed to execute command" << std::endl;
    	exit(0);
	}
	
    std::string output;
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        output += buffer;
    }
    int status = pclose(pipe);
    
	auto end = std::chrono::high_resolution_clock::now();
	*duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    // solving time, failed/passed, instruction numbers
	
	std::remove(fn_name.c_str());

	return output;
}

std::string bpf_types_2_dafny_types(uint64_t bpftype) {

	switch (bpftype & BPF_BASE_TYPE_MASK) {
		case NOT_INIT: return "";
		
		case SCALAR_VALUE: return "SCALAR";
		
		case PTR_TO_STACK: return "STACKMEM";
		
		case PTR_TO_CTX: return "CTXMEM";
		
		case CONST_PTR_TO_MAP: return "MAP_PTR";
		
		case PTR_TO_MAP_VALUE: return "PTR_TO_MAP_VALUE";
		
		case PTR_TO_MAP_KEY: return "PTR_TO_MAP_KEY";
		
		case PTR_TO_PACKET_META: return "PTR_TO_PACKET_META";
		
		case PTR_TO_PACKET: return "PTR_TO_PACKET";
		
		case PTR_TO_PACKET_END: return "PTR_TO_PACKET_END";
		
		case PTR_TO_FLOW_KEYS: return "PTR_TO_FLOW_KEYS";

		case PTR_TO_SOCKET: return "PTR_TO_SOCKET";

		case PTR_TO_SOCK_COMMON: return "PTR_TO_SOCK_COMMON";

		case PTR_TO_TCP_SOCK: return "PTR_TO_TCP_SOCK";
		
		case PTR_TO_XDP_SOCK: return "PTR_TO_XDP_SOCK";
		
		case PTR_TO_TP_BUFFER: return "PTR_TO_TP_BUFFER";
		
		case PTR_TO_ARENA: return "PTR_TO_ARENA";
		
		default:
			std::cerr << "Meet unexpected types when converting kernel types to dafny types";
			return "";
	}
}

void trans_reg_val(struct reg_smt_state *reg_state, std::string var, std::stringstream & trans_dafny) {

	// uint64_t mask, uint64_t value, uint32_t off
	/*
	// assume (!mask) & var == value
	trans_dafny << "\t" << "assume {:axiom} (!" << "0x" << std::setfill('0') << std::setw(16) << std::hex << mask << ") & " << var
					<< " == 0x" << std::setfill('0') << std::setw(16) << std::hex << value << ";\n";
	// var := var + off
	trans_dafny << "\t" << var << " := " << var << " + "
				<< "0x" << std::setfill('0') << std::setw(16) << std::hex << off << ";\n";
	*/

	// assume (!mask) & var == value
	trans_dafny << "\t" << "assume {:axiom} (!" << uint64_t(reg_state->mask) << ") & " << var
					<< " == " << uint64_t(reg_state->value) << ";\n";
	// var := var + off
	trans_dafny << "\t" << var << " := " << var << " + "
				<< uint32_t(reg_state->off) << ";\n";
}

void itm_state_2_dafny(struct interm_state *itm_state, std::stringstream & trans_dafny, bool *used_regs) {

	// std::stringstream state_init_buf, assert_buf;
	struct reg_smt_state *reg_states = itm_state->reg_states;
	bool used_reg_with_stack_ptr = false;

	// ------ memId and spin_lock info ------ //
	trans_dafny << "\t" << "s.spin_lock_meta.isLocked := " << (itm_state->is_spin_locked ? "true" : "false") << ";\n";
	if (itm_state->is_spin_locked) {
		trans_dafny << "\t" << "s.spin_lock_meta.memId := " << int(itm_state->spin_lock_id) << ";\n";
		// spin_lock.ptrType: TODO: ensure memIds are unique and thus we don't have to know the ptr type of the spin_lock
	}

	// R0 - R9
	// R10 needs to be initialized as well, because of the stack ID.
	for (int i=0; i<11; i++) {

		if (used_regs[i] == false) continue;

		if (reg_states[i].type == PTR_TO_STACK)
			used_reg_with_stack_ptr = true;

		// Type
		std::string this_reg_type = bpf_types_2_dafny_types(reg_states[i].type);
		if (this_reg_type != "") {

			// Add NULL if it is
			if (reg_states[i].type & PTR_MAYBE_NULL) {
				trans_dafny << "\t" << "s.r" << int(i) << ".regType := AnyRegtype();\n";
				trans_dafny << "\t" << "assume {:axiom} s.r" << int(i) << ".regType == " << this_reg_type;
				trans_dafny << " || " << "s.r" << int(i) << ".regType == NULL;\n";
			} else {
				trans_dafny << "\t" << "s.r" << int(i) << ".regType := " << this_reg_type << ";\n";
			}
		}

		// Value
		if (reg_states[i].type != NOT_INIT) {

			if (i == 1 || i == 10) {
				trans_dafny << "\t" << "s.r" << int(i) << ".regVal := AnyBv64();\n";
				// trans_dafny << "\t" << "s.r" << int(i) << ".memId := AnyInt64();\n";
			}
			
			// assume (!mask) & var == value
			// var := var + off
			trans_reg_val(&(reg_states[i]), "s.r"+std::to_string(i)+".regVal", trans_dafny);

			if (reg_states[i].type != SCALAR_VALUE) {
				// reg.memId := id
				trans_dafny << "\t" << "s.r"+std::to_string(i) << ".memId := " << uint32_t(reg_states[i].id) << ";\n";
			}

			if (reg_states[i].type == CONST_PTR_TO_MAP || reg_states[i].type == PTR_TO_MAP_VALUE || reg_states[i].type == PTR_TO_MAP_KEY) {
				// reg.mapfd := mapfd
				trans_dafny << "\t" << "s.r"+std::to_string(i) << ".mapFd := " << uint32_t(reg_states[i].mapfd) << ";\n";
			}
		}
	}

	if (!used_reg_with_stack_ptr) return;

	// Note: alloc_slots is always a multiple of BPF_REG_SIZE
	uint64_t spi_type, stackNo = reg_states[10].id;
	std::string reg_type;

	for (int stackIdx = 0; stackIdx <= stackNo; stackIdx++) {

		struct stk_spi *stk_spis = itm_state->stk_spis[stackIdx],
				   *cur_spi = stk_spis;

		trans_dafny << "\t // stack slots " << int(stackIdx) << " : " << int(itm_state->alloc_slots[stackIdx]) << "\n";

		for (int i=0; i < (itm_state->alloc_slots[stackIdx])/BPF_REG_SIZE; i++) {

			cur_spi = stk_spis + i;

			/*
				is_spilled:
					- 1: a 64-bit reg is spilled here
					- 2: a non-64-bit scalar reg or imm is spilled here
					- 0: no spilled reg
			*/

			if (cur_spi->is_spilled == 1) {

				spi_type = cur_spi->spilled_reg.type;
				reg_type = bpf_types_2_dafny_types(spi_type);
				// TODO, different stacks
				trans_dafny << "\t" << "s.update_stack_type(" << int(stackIdx) << ", " << int((63 - i) * BPF_REG_SIZE) << ", " << int(((63 - i) * BPF_REG_SIZE) + 7) << ", " << reg_type << ");\n";
				
				std::string var_name = "tmpbv"+std::to_string(i);
				
				// var tmpbv64:bv64 := AnyBv64();
				trans_dafny << "\t" << "var " << var_name << " := AnyBv64();\n";
				// assume (!mask) & tmpbv64 == value; tmpbv64 := tmpbv64 + off
				// cur_spi->spilled_reg.mask, cur_spi->spilled_reg.value, cur_spi->spilled_reg.off
				trans_reg_val(&(cur_spi->spilled_reg), var_name, trans_dafny);
				
				for (int j = 0; j < BPF_REG_SIZE; j++) {
					trans_dafny << "\t" << "s.update_stack_value(" << int(stackIdx) << ", " << int((63 - i) * BPF_REG_SIZE + j) << ", " << "getRegByteX(" << var_name << ", " << int(j) << "));\n";
				}
			
			} else {

				std::string var_name = "tmpbv_"+std::to_string(i);

				if (cur_spi->is_spilled == 2) {

					spi_type = cur_spi->spilled_reg.type;
					reg_type = bpf_types_2_dafny_types(spi_type);
					
					// var tmpbv64:bv64 := AnyBv64();
					trans_dafny << "\t" << "var " << var_name << " := AnyBv64();\n";
					// assume (!mask) & tmpbv64 == value; tmpbv64 := tmpbv64 + off
					// cur_spi->spilled_reg.mask, cur_spi->spilled_reg.value, cur_spi->spilled_reg.off
					trans_reg_val(&(cur_spi->spilled_reg), var_name, trans_dafny);
				}

				for (int j = 0; j < BPF_REG_SIZE; j++) {
					
					uint64_t cur_type = cur_spi->slots.type[BPF_REG_SIZE - j - 1];

					switch (cur_type) {
						case STACK_SPILL:
							trans_dafny << "\t" << "s.update_stack_type(" << int(stackIdx) << ", " << int((63 - i) * BPF_REG_SIZE + j) << ", " << int((63 - i) * BPF_REG_SIZE + j) << ", " << reg_type << ");\n";
							trans_dafny << "\t" << "s.update_stack_value(" << int(stackIdx) << ", " << int((63 - i) * BPF_REG_SIZE + j) << ", " << "getRegByteX(" << var_name << ", " << int(j) << "));\n";
							break;
						
						case STACK_ZERO:
							trans_dafny << "\t" << "s.update_stack_type(" << int(stackIdx) << ", " << int((63 - i) * BPF_REG_SIZE + j) << ", " << int((63 - i) * BPF_REG_SIZE + j) << ", " << "SCALAR" << ");\n";
							trans_dafny << "\t" << "s.update_stack_value(" << int(stackIdx) << ", " << int((63 - i) * BPF_REG_SIZE + j) << ", 0);\n";
							break;
						
						case STACK_MISC:
							trans_dafny << "\t" << "s.update_stack_type(" << int(stackIdx) << ", " << int((63 - i) * BPF_REG_SIZE + j) << ", " << int((63 - i) * BPF_REG_SIZE + j) << ", " << "SCALAR" << ");\n";
							// fallthrough
						case STACK_INVALID:
							break;

						default:
							std::cerr << "Unexpected stack slot type: " << cur_type << std::endl;
					}
				}
			}
		}
	}
}

struct verify_range trans_dafy_wrapper(char *itm_states, std::stringstream & trans_dafny, struct interm_state **latest_state, uint64_t *sample_time) {

	struct verify_range range = {0, 0};

	struct state_hdr *states_info = (struct state_hdr *)itm_states;
	int total = states_info->total;
	// std::cerr << "total: " << int(total) << std::endl;

	// We collect states at the begining of every N insns and the exit of the program.
	// So, it is impossible to be 0 or less then 0
	if (total <= 0) {
		std::cerr << "No collected states" << std::endl;
		return range;
	}

	struct interm_state * itm_states_all = (struct interm_state *) (states_info + 1);

	if (total == 1) {
		range.start = 0;
		range.end = itm_states_all[total-1].insn_idx;

	} else if (total > 1) {
		*latest_state = itm_states_all + (total > 1 ? (total -2) : 0);

		int latest_insn_idx = (*latest_state)->insn_idx;
	    int err_insn_idx = itm_states_all[total-1].insn_idx;

		range.start = latest_insn_idx;
		range.end = err_insn_idx;

		// trans_dafny << "// Start state translation: range " << int(range.start) << ", " << int(range.end) << std::endl;
		// itm_state_2_dafny(latest_state, trans_dafny);
	}


	for (int i = 0; i < total; i++) {
		*sample_time += itm_states_all[total-1].sample_time;
	}

	// std::cout << "finish state translation: range " << int(range.start) << ", " << int(range.end) << std::endl;
	return range;
}

void create_statistic_file(char *workdir) {

	if (statistic_file.is_open()) return;

	if (workdir) {
		std::string workdir_str(workdir);
		statistic_file.open(workdir_str+"/verify-per.csv");
	
		if (!statistic_file) {
        	std::cerr << "Error opening statistic_file!" << std::endl;
			exit(1);
    	}

		statistic_file << "prog_name\truntime_res\tveri_res\tinsn_cnt\ttrans_cnt1\tpaths1\ttrans_time1\tveri_time1\tsample_time\ttrans_cnt2\tpaths2\ttrans_time2\tveri_time2" << std::endl;
	}
}

void create_log_file(char *workdir) {
	if (log_file.is_open()) return;

	if (workdir) {
		std::string workdir_str(workdir);
                log_file.open(workdir_str+"/tests-log");
		if (!log_file) {
			std::cerr << "Error opening log_file!" << std::endl;
                        exit(1);
		}
	}
}

bool sat_assumption(char *runtime_log, union bpf_attr *progAttr) {
	/*
		Instruction syntax incorrectness:
			- unknown opcode 1b
			- R15 is invalid
			- BPF_ST uses reserved fields
			- invalid BPF_LD mode
			- unknown insn class
			- invalid BPF_ALU opcode
		
		control flow checks:
			- last insn is not an exit or jmp
			- jump out of range from insn
	 */
	std::regex pattern(R"((unknown opcode )|(R[0-9]+ is invalid)|( uses reserved fields)|(invalid \w+ mode)|(unknown insn class)|(invalid \w+ opcode)|(last insn is not an exit or jmp)|(jump out of range from insn)|(unreachable insn)|(back-edge from))");
	std::string log_str(runtime_log);
	return !std::regex_search(log_str, pattern) && progAttr->insn_cnt > 0;
}

void write_to_eval_log(union bpf_attr* progAttr, int runtime_res, int veri_res, uint64_t trans_cnt1, uint64_t paths1, uint64_t trans_time1,
	uint64_t veri_time1, uint64_t sample_time, uint64_t trans_cnt2, uint64_t paths2, uint64_t trans_time2, uint64_t veri_time2,
	bool is_same_error, std::string prog1, std::string prog2) {
	
	std::lock_guard<std::mutex> lock(file_mutex);
	if (statistic_file.is_open()) {
		
		statistic_file
			<< progAttr->prog_name << "\t"
			<< ((runtime_res == -1) ? "Runtime:unsafe\t" : "Runtime:safe\t");
		
		if (veri_res == 0)
			statistic_file << "Oracle:safe";
		else if (veri_res == 1)
			statistic_file << "Oracle:unsafe";
		else if (veri_res == 2)
			statistic_file << "Oracle:timeout";
		
		statistic_file
			<< "\t"
			<< uint64_t(progAttr->insn_cnt)
			<< "\t" << uint64_t(trans_cnt1) << "\t" << uint64_t(paths1) << "\t" << uint64_t(trans_time1) << "\t" << uint64_t(veri_time1)
			<< "\t" << uint64_t(sample_time)
			<< "\t" << uint64_t(trans_cnt2) << "\t" << uint64_t(paths2) << "\t" << uint64_t(trans_time2) << "\t" << uint64_t(veri_time2)
			<< "\t" << is_same_error
			<< std::endl;
	
	}

	if (log_file.is_open() && veri_time1 > veri_time2 && veri_time2 > 0) {
		log_file << "\n"
			 << uint64_t(veri_time1) << "; " << uint64_t(veri_time2) << "\n"
			 << prog1 << "\n-----------\n"
			 << prog2 << "\n\n" << std::endl;
	}
}


void create_prog_statistic_file(char *workdir) {

	if (prog_staticstic_file.is_open()) return;

	if (workdir) {
		std::string workdir_str(workdir);
		prog_staticstic_file.open(workdir_str+"/prog-size.csv");
	
		if (!prog_staticstic_file) {
        	std::cerr << "Error opening statistic_file!" << std::endl;
			exit(1);
    	}
	}
}

void write_to_prog_staticstic_log(char *progname, int insn_cnt, int alu, int ld, int mem, int jmp, int paths) {
	std::lock_guard<std::mutex> lock(file_mutex);
	if (prog_staticstic_file.is_open()) {
		prog_staticstic_file
			<< std::string(progname) << "\t"
			<< int(insn_cnt) << "\t" << int(paths) << "\t" << int(alu) << "\t"
			<< int(ld) << "\t" << int(mem) << "\t" << int(jmp) << std::endl;
	}
}

void count_insns_per_category(union bpf_attr *prog, int *alu, int *ld, int *mem, int *ctrl) {
	int i = 0;
	struct bpf_insn *insns = (struct bpf_insn *)prog->insns;

	for (i = 0; i < prog->insn_cnt; i++) {

		struct bpf_insn *insn = insns + i;

		switch (BPF_CLASS(insn->code)) {

			case BPF_ALU:
			case BPF_ALU64:
				*alu += 1;
				break;

			case BPF_LD:
				*ld += 1;
				i ++;
				break;

			case BPF_LDX:
			case BPF_ST:
			case BPF_STX:
				*mem += 1;
				break;

			case BPF_JMP:
			case BPF_JMP32:
				*ctrl += 1;
				break;
		}
	}
}

int VerifyOneProg(char *progAttr1, char *mapAttrs1, int map_cnt, int priv, char *itm_states,
	int runtime_res, int err_lineno, char *workdir, char *dafny_veri_log, char *runtime_log, bool is_eval) {

	std::stringstream header, trans_dafny, trans_dafny_eval, tmp_dafny;
	int isBug = 0, veri_res = 0;
	uint64_t trans_cnt = 0, trans_cnt2 = 0, paths1 = 0, paths2 = 0;
	uint64_t veri_time1 = 0, veri_time2 = 0, trans_time1 = 0, trans_time2 = 0, sample_time = 0;
	bool used_regs[11] = {false};
	struct verify_range range = {0, 0};

	// bool is_eval = true;
	bool is_same_error = true;

	union bpf_attr *progAttr = (union bpf_attr*)progAttr1;
	union bpf_attr *mapAttrs = (union bpf_attr*)mapAttrs1;

	// ------------ ensure instructions satisfy our syntax correctness assumption ------------ //
	if (runtime_res < 0 && !sat_assumption(runtime_log, progAttr)) {
		return -1;
	}

	// statistics
	// int alu = 0, mem = 0, ld = 0, ctrl = 0, paths1 = 0, paths2 = 0;
	// count_insns_per_category(progAttr, &alu, &ld, &mem, &ctrl);
	// trans_cnt = insns2Dafny(progAttr, trans_dafny, NULL, &paths);
	// create_prog_statistic_file(workdir);
	// std::cout << "paths: " << int(paths) << std::endl;
	// return 0;
	//


	// ------ Translate initial settings ------ // 
	// 
	header << "include \"spec.dfy\"" << "\n" << "method testMain() {" << "\n\t"
				<< "var s := new State(\n";
	//
	// allow_ptr_leak_set:bool, bypass_spec_v1_set:bool, priv_set:bool, has_net_admin:bool
	header << "\t\t// allow_ptr_leak_set:bool, bypass_spec_v1_set:bool, priv_set:bool, has_net_admin:bool\n";
	//
	switch (priv) {
		case PRIV_UNPRIV:
			header << "\t\t" << "false, false, false, false, \n";
			break;
		case PRIV_CAP_BPF:
			header << "\t\t" << "false, false, true, false, \n";
			break;
		case PRIV_CAP_PERFMON:
			header << "\t\t" << "true, true, false, false, \n";
			break;
		case PRIV_CAP_NET_ADMIN:
			header << "\t\t" << "false, false, false, true, \n";
			break;
		case PRIV_CAP_SYS_ADMIN:
			header << "\t\t" << "true, true, true, true, \n";
			break;
		default:
			std::cerr << "privlege error: " << int(priv) << std::endl;
			return -1;
	}
	//
	// strict_alignment_set:bool
	// CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS is Y in testing env
	// Only when BPF_F_ANY_ALIGNMENT is unset while BPF_F_STRICT_ALIGNMENT is set ==> strict == true
	if (progAttr->prog_flags & BPF_F_ANY_ALIGNMENT) {
		header << "\t\t" << "false";
	} else if (progAttr->prog_flags & BPF_F_STRICT_ALIGNMENT) {
		header << "\t\t" << "true";
	} else {
		header << "\t\t" << "false";
	}
	//
	header << ");\n\t";

	header << "s.progType := " << bpf_prog_type_str[progAttr->prog_type] << ";\n\t"
				<< "s.attachType := " << expected_attach_type_str[progAttr->expected_attach_type] << ";\n\n";

	// ------ Translate map informations ------ //
	header << "\t" << "assume {:axiom} s.maps.Length == " << int(map_cnt) << ";\n";
	for (int i = 0; i < map_cnt; i++) {
		if (mapAttrs[i].map_type == 0)
			continue;

		header << "\t" << "s.CreateMap(" << int(i) << ", "
					<< bpf_map_type_str[mapAttrs[i].map_type] << ", "
					<< mapAttrs[i].key_size		<< ", "
					<< mapAttrs[i].value_size		<< ", "
					<< mapAttrs[i].max_entries		<< ", "
					<< mapAttrs[i].flags			<< ", "
					<< mapAttrs[i].inner_map_fd	<< ");\n";
	}
	header << "\n";

	// ------ Translate ebpf bytecode to Dafny code instruction by instruction ------ // 
	//
	trans_dafny << header.str();
	if (runtime_res == -1 && itm_states) {
        // Negatives -> if it's a bug, then a false negative
		struct interm_state *latest_state = NULL;
		range = trans_dafy_wrapper(itm_states, trans_dafny, &latest_state, &sample_time);
		if (range.end == 0 && range.start == 0) {
			// std::cerr << "Failed to extract the verificaiton range" << std::endl;
			return isBug;
		}
		trans_cnt = insns2Dafny(progAttr, tmp_dafny, used_regs, &range, &paths1, &trans_time1);

		// used registers
		if (latest_state) {
			trans_dafny << "// ";
			for (size_t i = 0; i < 11; ++i) {
        		trans_dafny << int(i) << ":" << (used_regs[i] ? "true " : "false ");
			}
			trans_dafny << std::endl;
			itm_state_2_dafny(latest_state, trans_dafny, used_regs);
		}

		trans_dafny << tmp_dafny.str();

    	} else {
        	// Positives -> if it's a bug, then a false positive
		trans_cnt = insns2Dafny(progAttr, trans_dafny, used_regs, NULL, &paths1, &trans_time1);
	}

	if (trans_cnt < 1) {
		sprintf(dafny_veri_log, "return trans_cnt: %ld, insn_cnt: %d\n",  trans_cnt, progAttr->insn_cnt);
		return -1;
	}

	// ------ Run dafny verifier to verify the above translated dafny code ------ // 

	std::string final_dafny = trans_dafny.str() + "\n}";
	std::string veri_output = execute_cmd(final_dafny, &veri_time1);
	
	std::string veri_output_eval;
	std::string final_dafny_eval;
	if (is_eval && runtime_res == -1 && itm_states && range.start != 0) {
		trans_dafny_eval << header.str();
		trans_cnt2 = insns2Dafny(progAttr, trans_dafny_eval, used_regs, NULL, &paths2, &trans_time2);
		final_dafny_eval = trans_dafny_eval.str() + "\n}";
		veri_output_eval = execute_cmd(final_dafny_eval, &veri_time2);
		is_same_error = (regex_match_error_insn(veri_output) == regex_match_error_insn(veri_output_eval));
	}

	// write_to_prog_staticstic_log(progAttr->prog_name, progAttr->insn_cnt, alu, ld, mem, ctrl, paths);


	// ------ Check if the verification result is consistent with the original runtime result ------ //
	
	// Dafny verification times out
	if (veri_output.find("timed out after ") != std::string::npos) {
		veri_res = 2;
		isBug = -1;
	} 
	// Dafny verification succeeds
	else if (veri_output.find("verified, 0 errors") != std::string::npos) {
		// Runtime fails -> false negatives
		if (runtime_res < 0)
			isBug = 2;
	}
	// Dafny verification failed
	else {
		veri_res = 1;
		int dafny_err_insn = regex_match_error_insn(veri_output);
		// Runtime succeeds -> false positives
		if (runtime_res >= 0)
			isBug = 1;
		// Both fail but having an inconsistent failure insn
		else if (dafny_err_insn != err_lineno)
			isBug = 3;
	}

	create_log_file(workdir);
	create_statistic_file(workdir);
	write_to_eval_log(progAttr, runtime_res, veri_res, trans_cnt, paths1, trans_time1, veri_time1,
					sample_time, trans_cnt2, paths2, trans_time2, veri_time2,
					is_same_error, final_dafny, final_dafny_eval);

	/*
	if (veri_time2 <= veri_time1) {
		std::cout << "bad perf: " << "is_same_error " << is_same_error << "  " << uint64_t(veri_time1) << " " << uint64_t(veri_time2) << std::endl;
		std::cout << runtime_log << "\n" << final_dafny << "\n" << veri_output << "\n-----\n" << final_dafny_eval << "\n" << veri_output_eval <<std::endl;
	}
	*/

	if (isBug) {
		// Verification fails or find the inconsistency between runtime and dafny verification
		std::string concatenated = final_dafny + "\n" + veri_output;
		strncpy(dafny_veri_log, concatenated.c_str(), 4194304);
		// std::cerr << "!!!!!! Verification and runtime result is inconsistent. !!!!!!!!!\n" << veri_output << std::endl;
	} else {
		// std::cerr << "correct" << std::endl;
	}

	return isBug;
}
