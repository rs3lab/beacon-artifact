#include <algorithm>
#include <array>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <chrono>

#include "translator.hpp"
// ============================================================
// Attach_type and prog_type strings
// ============================================================
static const std::string bpf_prog_type_str[] = {
    "BPF_PROG_TYPE_UNSPEC",
    "BPF_PROG_TYPE_SOCKET_FILTER",
    "BPF_PROG_TYPE_KPROBE",
    "BPF_PROG_TYPE_SCHED_CLS",
    "BPF_PROG_TYPE_SCHED_ACT",
    "BPF_PROG_TYPE_TRACEPOINT",
    "BPF_PROG_TYPE_XDP",
    "BPF_PROG_TYPE_PERF_EVENT",
    "BPF_PROG_TYPE_CGROUP_SKB",
    "BPF_PROG_TYPE_CGROUP_SOCK",
    "BPF_PROG_TYPE_LWT_IN",
    "BPF_PROG_TYPE_LWT_OUT",
    "BPF_PROG_TYPE_LWT_XMIT",
    "BPF_PROG_TYPE_SOCK_OPS",
    "BPF_PROG_TYPE_SK_SKB",
    "BPF_PROG_TYPE_CGROUP_DEVICE",
    "BPF_PROG_TYPE_SK_MSG",
    "BPF_PROG_TYPE_RAW_TRACEPOINT",
    "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
    "BPF_PROG_TYPE_LWT_SEG6LOCAL",
    "BPF_PROG_TYPE_LIRC_MODE2",
    "BPF_PROG_TYPE_SK_REUSEPORT",
    "BPF_PROG_TYPE_FLOW_DISSECTOR",
    "BPF_PROG_TYPE_CGROUP_SYSCTL",
    "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
    "BPF_PROG_TYPE_CGROUP_SOCKOPT",
    "BPF_PROG_TYPE_TRACING",
    "BPF_PROG_TYPE_STRUCT_OPS",
    "BPF_PROG_TYPE_EXT",
    "BPF_PROG_TYPE_LSM",
    "BPF_PROG_TYPE_SK_LOOKUP",
    "BPF_PROG_TYPE_SYSCALL",
    "BPF_PROG_TYPE_NETFILTER",
};


static const std::string expected_attach_type_str[] = {
    "BPF_CGROUP_INET_INGRESS",
    "BPF_CGROUP_INET_EGRESS",
    "BPF_CGROUP_INET_SOCK_CREATE",
    "BPF_CGROUP_SOCK_OPS",
    "BPF_SK_SKB_STREAM_PARSER",
    "BPF_SK_SKB_STREAM_VERDICT",
    "BPF_CGROUP_DEVICE",
    "BPF_SK_MSG_VERDICT",
    "BPF_CGROUP_INET4_BIND",
    "BPF_CGROUP_INET6_BIND",
    "BPF_CGROUP_INET4_CONNECT",
    "BPF_CGROUP_INET6_CONNECT",
    "BPF_CGROUP_INET4_POST_BIND",
    "BPF_CGROUP_INET6_POST_BIND",
    "BPF_CGROUP_UDP4_SENDMSG",
    "BPF_CGROUP_UDP6_SENDMSG",
    "BPF_LIRC_MODE2",
    "BPF_FLOW_DISSECTOR",
    "BPF_CGROUP_SYSCTL",
    "BPF_CGROUP_UDP4_RECVMSG",
    "BPF_CGROUP_UDP6_RECVMSG",
    "BPF_CGROUP_GETSOCKOPT",
    "BPF_CGROUP_SETSOCKOPT",
    "BPF_TRACE_RAW_TP",
    "BPF_TRACE_FENTRY",
    "BPF_TRACE_FEXIT",
    "BPF_MODIFY_RETURN",
    "BPF_LSM_MAC",
    "BPF_TRACE_ITER",
    "BPF_CGROUP_INET4_GETPEERNAME",
    "BPF_CGROUP_INET6_GETPEERNAME",
    "BPF_CGROUP_INET4_GETSOCKNAME",
    "BPF_CGROUP_INET6_GETSOCKNAME",
    "BPF_XDP_DEVMAP",
    "BPF_CGROUP_INET_SOCK_RELEASE",
    "BPF_XDP_CPUMAP",
    "BPF_SK_LOOKUP",
    "BPF_XDP",
    "BPF_SK_SKB_VERDICT",
    "BPF_SK_REUSEPORT_SELECT",
    "BPF_SK_REUSEPORT_SELECT_OR_MIGRATE",
    "BPF_PERF_EVENT",
    "BPF_TRACE_KPROBE_MULTI",
    "BPF_LSM_CGROUP",
    "BPF_STRUCT_OPS",
    "BPF_NETFILTER",
    "BPF_TCX_INGRESS",
    "BPF_TCX_EGRESS",
    "BPF_TRACE_UPROBE_MULTI",
    "BPF_CGROUP_UNIX_CONNECT",
    "BPF_CGROUP_UNIX_SENDMSG",
    "BPF_CGROUP_UNIX_RECVMSG",
    "BPF_CGROUP_UNIX_GETPEERNAME",
    "BPF_CGROUP_UNIX_GETSOCKNAME",
    "BPF_NETKIT_PRIMARY",
    "BPF_NETKIT_PEER",
    "BPF_TRACE_KPROBE_SESSION",
};


// ============================================================
// Dispatch a non-control-flow instruction to the appropriate
// translator. The output state name is supplied by the caller
// so the CFG translation layer can decide how states flow across
// branches.
// ============================================================

static int translate_stateful_insn(const bpf_insn& insn,
                                   const std::string& in_state,
                                   const std::string& out_state,
                                   std::stringstream& out,
                                   RegUsage& regs,
                                   int depth) {
    if (MemoryDecoder::is_memory(insn))
        return translate_memory_insn(insn, in_state, out_state, out, regs, depth);
    if (DataMovDecoder::is_datamov(insn))
        return translate_datamov_insn(insn, in_state, out_state, out, regs, depth);
    if (ArithDecoder::is_arithmetic(insn))
        return translate_arith_insn(insn, in_state, out_state, out, regs, depth);
    return -1;
}

// ============================================================
// Core CFG-walking translation loop
// ============================================================

int insns_to_dafny(const bpf_insn* insns,
                   int insn_cnt,
                   std::stringstream& trans_dafny,
                   bool* used_regs,
                   uint64_t *duration,
                   struct verify_range *range
                   ) {
    if (!insns || !used_regs || insn_cnt < 1){
        if (duration) *duration = 0;
        return -1;
    }
        

    auto start = std::chrono::high_resolution_clock::now();

    FreshStateGen fresh_states;
    std::vector<ResumePoint> stack;

    int insn_idx     = 0;
    int trans_cnt    = 0;
    std::string current_state = "init_s";

    // If we have a range, start from the checkpoint
    if (range) insn_idx = range->start;

    while (true) {
        if (trans_cnt > 5000) {
            trans_dafny << indent(0) << "// translation stopped: program too large\n";
            return -2;
        }

        // ── Path finished: drain resume stack ──────────────────────────────
        if (insn_idx == -1) {
            if (stack.empty()) break;

            ResumePoint rp = stack.back();
            stack.pop_back();

            if (rp.kind == ResumeKind::CloseBlock) {
                trans_dafny << indent(static_cast<int>(stack.size() / 2)) << "}\n";
                continue;
            }

            if (rp.kind == ResumeKind::ElseBranch) {
                trans_dafny << indent(static_cast<int>(stack.size() / 2)) << "} else {\n";
                insn_idx      = rp.target_idx;
                current_state = rp.state_name;
                continue;
            }

            if (rp.kind == ResumeKind::ReturnFromCall) {
                trans_dafny << indent(static_cast<int>(stack.size() / 2)) << "}\n";
                insn_idx      = rp.target_idx;
                current_state = rp.state_name;
                continue;
            }

            if (rp.kind == ResumeKind::MergeContinue) {
                trans_dafny << indent(static_cast<int>(stack.size() / 2)) << "}\n";
                if (rp.target_idx == -1) {
                    continue;  // no common tail, keep draining
                }
                insn_idx      = rp.target_idx;
                current_state = rp.join_state_name;
                continue;
            }
        }

        if (insn_idx < 0 || insn_idx >= insn_cnt) {
            if (insn_idx == insn_cnt) {
                insn_idx = -1;
                continue;
            }
            trans_dafny << indent(static_cast<int>(stack.size() / 2))
                        << "// ERROR: out of range: " << insn_idx << "\n";
            return -1;
        }
        
        // Stop translating past the error instruction
        if (range && insn_idx > range->end) {
            // Force-close all open if/else blocks
            while (!stack.empty()) {
                ResumePoint rp = stack.back();
                stack.pop_back();
                if (rp.kind == ResumeKind::CloseBlock ||
                    rp.kind == ResumeKind::MergeContinue) {
                    trans_dafny << indent(static_cast<int>(stack.size() / 2))
                                << "}\n";
                }
            }
            break;
        }

        ++trans_cnt;
        const bpf_insn& insn = insns[insn_idx];

        RegUsage regs;
        std::copy(used_regs, used_regs + BPF_REG_COUNT, regs.used.begin());

        try {
            const int header_depth = static_cast<int>(stack.size() / 2);
            const int stmt_depth   = static_cast<int>((stack.size() + 1) / 2);

            // ── Fall-through-into-merge detection ──────────────────────────
            for (int i = static_cast<int>(stack.size()) - 1; i >= 0; --i) {
                if (stack[i].kind == ResumeKind::MergeContinue) {
                    if (stack[i].target_idx != -1 &&
                        insn_idx == stack[i].target_idx) {
                        trans_dafny << indent(stmt_depth)
                                    << stack[i].join_state_name
                                    << " := " << current_state << ";\n";
                        insn_idx = -1;
                    }
                    break;
                }
            }
            if (insn_idx == -1) continue;

            // ── Exit ───────────────────────────────────────────────────────
            if (is_exit_insn(insn)) {
                used_regs[0] = true;
                const std::string exit_state = fresh_states.next();
                trans_dafny << indent(stmt_depth)
                            << "var " << exit_state << " := Exit(" << current_state << ");\n";
                trans_dafny << indent(stmt_depth) << "return;\n";
                insn_idx = -1;
                continue;
            }

            // ── Call (opaque: helper or BPF-to-BPF subprogram) ─────────────────
            
                
            if (is_call(insn)) {
                const std::string out_state = fresh_states.next();
                trans_dafny << indent(stmt_depth)
                            << "var " << out_state
                            << " := call_step(" << current_state << ", CALL);\n";
                current_state = out_state;
                insn_idx      = insn_idx + 1;
                continue;
            }
            

            // ── Conditional jump ───────────────────────────────────────────
            if (is_cond_jump(insn)) {
                const bool reg_src = (insn.code & bpf_opcode::SRC_MASK) == bpf_opcode::X;
                regs.mark(insn.dst_reg);
                if (reg_src) regs.mark(insn.src_reg);

                const std::string jump_state = fresh_states.next();
                const std::string join_state = fresh_states.next();
                const std::string jump_call  = emit_cond_jump_call(insn, current_state);

                trans_dafny << indent(stmt_depth)
                            << "var " << jump_state << " := " << jump_call << ";\n";
                trans_dafny << indent(stmt_depth)
                            << "var " << join_state << " : State;\n";
                trans_dafny << indent(header_depth)
                            << "if " << jump_state << ".jmp_res {\n";

                std::copy(regs.used.begin(), regs.used.end(), used_regs);

                const int then_idx  = jump_target_idx(insn, insn_idx);
                const int else_idx  = insn_idx + 1;
                const int merge_target = find_merge_target(insns, insn_cnt, else_idx, then_idx);

                ResumePoint merge_rp;
                merge_rp.kind            = ResumeKind::MergeContinue;
                merge_rp.target_idx      = merge_target;
                merge_rp.state_name      = jump_state;
                merge_rp.join_state_name = join_state;

                ResumePoint else_rp;
                else_rp.kind       = ResumeKind::ElseBranch;
                else_rp.target_idx = else_idx;
                else_rp.state_name = jump_state;

                stack.push_back(merge_rp);
                stack.push_back(else_rp);

                current_state = jump_state;
                insn_idx      = then_idx;
                continue;
            }

            // ── Unconditional jump ─────────────────────────────────────────
            if (is_uncond_jump(insn)) {
                const int merge_target = jump_target_idx(insn, insn_idx);
                if (!stack.empty()) {
                    for (int i = static_cast<int>(stack.size()) - 1; i >= 0; --i) {
                        if (stack[i].kind == ResumeKind::MergeContinue) {
                            trans_dafny << indent(stmt_depth)
                                        << stack[i].join_state_name
                                        << " := " << current_state << ";\n";
                            break;
                        }
                    }
                    insn_idx = -1;
                } else {
                    insn_idx = merge_target;
                }
                continue;
            }

            // ── LD_IMM64 — two-slot wide immediate ─────────────────────────
            if (is_ld_imm64_pair(insn)) {
                if (insn_idx + 1 >= insn_cnt) {
                    trans_dafny << indent(stmt_depth)
                                << "// ERROR: LD_IMM64 at end of program\n";
                    return -1;
                }
                const bpf_insn& next = insns[insn_idx + 1];
                // Validate LD_IMM64 reserved fields
                if (insn.off != 0 ||
                    next.code != 0 ||
                    next.dst_reg != 0 ||
                    next.src_reg != 0 ||
                    next.off != 0) {
                    trans_dafny << indent(stmt_depth)
                                << "// ERROR: LD_IMM64 uses reserved fields\n";
                    return -1;
                }
                const uint64_t wide = ((uint64_t)(uint32_t)insn.imm) |
                                      ((uint64_t)(uint32_t)next.imm << 32);

                const char* moviop;
                if (insn.src_reg == BPF_PSEUDO_MAP_FD)
                    moviop = "LOADMAPFD";
                else if (insn.src_reg == BPF_PSEUDO_MAP_IDX)
                    moviop = "LOADMAPIDX";
                else
                    moviop = "LOADIMM64";

                const std::string out_state = fresh_states.next();
                trans_dafny << indent(stmt_depth)
                            << "var " << out_state << " := datamov_imm("
                            << current_state << ", DATAMOVIMM("
                            << reg_to_dafny(insn.dst_reg) << ", "
                            << bv64_literal(wide) << ", "
                            << moviop << "));\n";

                current_state = out_state;
                insn_idx += 2;
                ++trans_cnt;
                continue;
            }

            // ── Normal instruction ─────────────────────────────────────────
            const std::string out_state = fresh_states.next();
            const int rc = translate_stateful_insn(
                insn, current_state, out_state, trans_dafny, regs, stmt_depth);

            if (rc != 0) {
                trans_dafny << indent(stmt_depth)
                            << "// insn " << insn_idx << ": unsupported\n";
                return -1;
            }

            std::copy(regs.used.begin(), regs.used.end(), used_regs);
            current_state = out_state;
            insn_idx      = next_linear_insn_idx(insn, insn_idx);

        } catch (const std::exception& ex) {
            trans_dafny << indent(static_cast<int>((stack.size() + 1) / 2))
                        << "// insn " << insn_idx
                        << ": translation error: " << ex.what() << "\n";
            return -1;
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    if (duration){
        *duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    }

    return trans_cnt;
}


std::string build_dafny_string(const bpf_insn* insns,
                               int insn_cnt,
                               const std::string& method_name,
                               uint32_t prog_type,
                               uint32_t attach_type) {
    std::stringstream trans;
    bool used_regs[BPF_REG_COUNT] = {false};

    trans << "include \"../spec/arith-spec.dfy\"\n";
    trans << "include \"../spec/datamov-spec.dfy\"\n";
    trans << "include \"../spec/ctrlflow-spec.dfy\"\n";
    trans << "include \"../spec/mem-spec.dfy\"\n";
    trans << "include \"../spec/mem-init.dfy\"\n";
    trans << "include \"../proof/proof-utils.dfy\"\n\n";
    trans << "module Embedded_" << method_name << " {\n\n";
    trans << "    import opened Terms\n";
    trans << "    import opened DataTypes\n";
    trans << "    import opened States\n";
    trans << "    import opened MemInit\n";
    trans << "    import opened Utils\n\n";
    trans << "    import opened eBPFArithSpec\n";
    trans << "    import opened eBPFDataMoveSpec\n";
    trans << "    import opened eBPFCtrlFlowSpec\n";
    trans << "    import opened eBPFMemSpec\n\n";
    trans << "    import opened ProofUtils\n\n";

    trans << "    ghost method {:timeLimit 30} {:priority 10} " << method_name << "(\n";
    trans << "        cfg: ConfigState, rand: bv64\n";
    trans << "    )\n";

    // prog_type: index 0 (BPF_PROG_TYPE_UNSPEC) not in Dafny spec
    if (prog_type > 0 && prog_type < (uint32_t)bpf_prog_type_str_size) {
        trans << "    requires cfg.progType == "
              << bpf_prog_type_str[prog_type] << "\n";
    }

    // attach_type: index 56 (BPF_TRACE_KPROBE_SESSION) not in Dafny spec
    if (attach_type < (uint32_t)expected_attach_type_str_size - 1) {
        trans << "    requires cfg.attachType == "
              << expected_attach_type_str[attach_type] << "\n";
    }

    // scan instructions for LOADMAPFD to find max map fd used
    int max_mapfd = -1;
    int max_mapidx = -1;
    for (int i = 0; i < insn_cnt - 1; i++) {
        if (is_ld_imm64_pair(insns[i])) {
            if (insns[i].src_reg == BPF_PSEUDO_MAP_FD) {
                if (insns[i].imm > max_mapfd)
                    max_mapfd = insns[i].imm;
            } 
            else if (insns[i].src_reg == BPF_PSEUDO_MAP_IDX) {
                if (insns[i].imm > max_mapidx)
                    max_mapidx = insns[i].imm;
            }
            i++; // skip second word of LD_IMM64
        }
    }

    if (max_mapidx >= 0) {
        trans << "    requires |cfg.map_fd_arr| > "
              << max_mapidx << "\n";
    
        int maps_meta_len = max_mapfd + 1;  // matches the seq() you emit in the body
    
        trans << "    requires forall i | 0 <= i < |cfg.map_fd_arr| "
              << ":: 0 <= cfg.map_fd_arr[i] < "
              << maps_meta_len << "\n";
    }

    trans << "    {\n";
    trans << "        var init_s := init_state(cfg, rand);\n\n";

    // If the program uses LOADMAPFD, we need to patch the initial state to have enough maps_meta entries and corresponding mems entries to avoid out-of-range errors during translation. We use max_mapfd to determine how many entries are needed.
    if (max_mapfd >= 0 || max_mapidx >= 0) {
        int map_meta_rid = 14; // r2id(PTR_TO_MAP_META)
        int n_maps = max_mapfd + 1;
    
        // Patch maps_meta
        trans << "        var dummy_map := MapState("
              << "BPF_MAP_TYPE_ARRAY, 4, 8, 1, 0, 0);\n";
        trans << "        init_s := init_s.(maps_meta := seq("
              << n_maps << ", i => dummy_map));\n";
    
        // Patch mems so PTR_TO_MAP_META region has n_maps entries
        trans << "        var dummy_map_mem := Mem(\n"
              << "            mem_type := STRUCT,\n"
              << "            is_concur := false,\n"
              << "            base := 0,\n"  // placeholder
              << "            data := []\n"
              << "        );\n";
        trans << "        init_s := init_s.(mems := init_s.mems["
              << map_meta_rid << " := seq("
              << n_maps << ", i => dummy_map_mem)]);\n";
    }

    
    uint64_t duration = 0;
    const int translated = insns_to_dafny(insns, insn_cnt, trans, used_regs, &duration,NULL);
    if (translated == -2) 
        throw std::runtime_error("Program too large");  // UNSUPPORTED
    if (translated < 0)
        throw std::runtime_error("Translation failed");

    trans << "\n    }\n";
    trans << "} // module Embedded_" << method_name << "\n";

    return trans.str();
}