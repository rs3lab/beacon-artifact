#include "translator.hpp"


// ============================================================
// 2. Jump / control-flow helpers
// ============================================================

[[nodiscard]] bool is_jump_class(uint8_t cls) noexcept {
    return cls == bpf_opcode::JMP || cls == bpf_opcode::JMP32;
}

[[nodiscard]] bool is_exit_insn(const bpf_insn& insn) noexcept {
    const uint8_t cls = insn.code & bpf_opcode::CLASS_MASK;
    const uint8_t op  = insn.code & bpf_opcode::OP_MASK;
    return is_jump_class(cls) && op == bpf_opcode::EXIT;
}

[[nodiscard]] bool is_uncond_jump(const bpf_insn& insn) noexcept {
    const uint8_t cls = insn.code & bpf_opcode::CLASS_MASK;
    const uint8_t op  = insn.code & bpf_opcode::OP_MASK;
    return is_jump_class(cls) && op == bpf_opcode::JA;
}

[[nodiscard]] bool is_cond_jump(const bpf_insn& insn) noexcept {
    const uint8_t cls = insn.code & bpf_opcode::CLASS_MASK;
    const uint8_t op  = insn.code & bpf_opcode::OP_MASK;

    if (!is_jump_class(cls)) {
        return false;
    }

    switch (op) {
        case bpf_opcode::JEQ:
        case bpf_opcode::JGT:
        case bpf_opcode::JGE:
        case bpf_opcode::JSET:
        case bpf_opcode::JNE:
        case bpf_opcode::JSGT:
        case bpf_opcode::JSGE:
        case bpf_opcode::JLT:
        case bpf_opcode::JLE:
        case bpf_opcode::JSLT:
        case bpf_opcode::JSLE:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] bool is_call(const bpf_insn& insn) noexcept {
    const uint8_t cls = insn.code & bpf_opcode::CLASS_MASK;
    const uint8_t op  = insn.code & bpf_opcode::OP_MASK;
    return cls == bpf_opcode::JMP && op == bpf_opcode::CALL;
}
[[nodiscard]] bool is_pseudo_call(const bpf_insn& insn) noexcept {
    const uint8_t cls = insn.code & bpf_opcode::CLASS_MASK;
    const uint8_t op  = insn.code & bpf_opcode::OP_MASK;
    return cls == bpf_opcode::JMP && op == bpf_opcode::CALL && insn.src_reg == BPF_PSEUDO_CALL;
}



// eBPF jumps are PC-relative to the next instruction, hence +1.
[[nodiscard]] int jump_target_idx(const bpf_insn& insn, int insn_idx) {
    return insn_idx + insn.off + 1;
}

bool CtrlFlowDecoder::is_control_flow(const bpf_insn& insn) noexcept {
    return ControlFlowDecoder::is_control_flow(insn);
}

std::optional<DecodedCtrlFlowInsn> CtrlFlowDecoder::decode(const bpf_insn& insn, int insn_idx) {
    if (!is_control_flow(insn)) {
        return std::nullopt;
    }

    DecodedCtrlFlowInsn out;

    if (is_exit_insn(insn)) {
        out.kind = CtrlFlowKind::EXIT;
        return out;
    }
    if (is_uncond_jump(insn)) {
        out.kind = CtrlFlowKind::JA;
        out.target_idx = jump_target_idx(insn, insn_idx);
        return out;
    }
    if (is_pseudo_call(insn)) {
        out.kind = CtrlFlowKind::PSEUDO_CALL;
        out.target_idx = insn_idx + insn.imm + 1;
        out.fallthrough_idx = insn_idx + 1;
        return out;
    }
    if ((insn.code & bpf_opcode::OP_MASK) == bpf_opcode::CALL) {
        out.kind = CtrlFlowKind::CALL;
        return out;
    }
    if (is_cond_jump(insn)) {
        out.kind = CtrlFlowKind::COND_JMP;
        out.target_idx = jump_target_idx(insn, insn_idx);
        out.fallthrough_idx = insn_idx + 1;
        return out;
    }

    return std::nullopt;
}


bool ControlFlowDecoder::is_control_flow(const bpf_insn& insn) noexcept {
    return is_jump_class(insn.code & bpf_opcode::CLASS_MASK);
}

std::optional<DecodedControlFlowInsn> ControlFlowDecoder::decode(const bpf_insn& insn) {
    if (!is_control_flow(insn)) {
        return std::nullopt;
    }

    DecodedControlFlowInsn out;
    out.dst = insn.dst_reg;
    out.src = insn.src_reg;
    out.imm = insn.imm;
    out.off = insn.off;

    const uint8_t cls      = insn.code & bpf_opcode::CLASS_MASK;
    const bool is_jmp32    = cls == bpf_opcode::JMP32;
    const uint8_t op       = insn.code & bpf_opcode::OP_MASK;
    const bool uses_regsrc = (insn.code & bpf_opcode::SRC_MASK) == bpf_opcode::X;

    if (op == bpf_opcode::EXIT) {
        out.kind = ControlFlowKind::EXIT;
        return out;
    }
    if (op == bpf_opcode::JA) {
        out.kind = ControlFlowKind::JA;
        return out;
    }
    if (op == bpf_opcode::CALL) {
        out.kind = ControlFlowKind::CALL;
        return out;
    }
    if (is_cond_jump(insn)) {
        out.kind     = uses_regsrc ? ControlFlowKind::COND_REG : ControlFlowKind::COND_IMM;
        out.uses_src = uses_regsrc;
        out.uses_imm = !uses_regsrc;
        out.jmp_op   = decode_jump_op(op, is_jmp32);
        return out;
    }

    return std::nullopt;
}

JumpOp ControlFlowDecoder::decode_jump_op(uint8_t op, bool is_jmp32) {
    switch (op) {
        case bpf_opcode::JEQ:  return is_jmp32 ? JumpOp::JEQ32  : JumpOp::JEQ64;
        case bpf_opcode::JNE:  return is_jmp32 ? JumpOp::JNE32  : JumpOp::JNE64;
        case bpf_opcode::JSET: return is_jmp32 ? JumpOp::JSET32 : JumpOp::JSET64;
        case bpf_opcode::JGT:  return is_jmp32 ? JumpOp::JGT32  : JumpOp::JGT64;
        case bpf_opcode::JGE:  return is_jmp32 ? JumpOp::JGE32  : JumpOp::JGE64;
        case bpf_opcode::JLT:  return is_jmp32 ? JumpOp::JLT32  : JumpOp::JLT64;
        case bpf_opcode::JLE:  return is_jmp32 ? JumpOp::JLE32  : JumpOp::JLE64;
        case bpf_opcode::JSGT: return is_jmp32 ? JumpOp::JSGT32 : JumpOp::JSGT64;
        case bpf_opcode::JSGE: return is_jmp32 ? JumpOp::JSGE32 : JumpOp::JSGE64;
        case bpf_opcode::JSLT: return is_jmp32 ? JumpOp::JSLT32 : JumpOp::JSLT64;
        case bpf_opcode::JSLE: return is_jmp32 ? JumpOp::JSLE32 : JumpOp::JSLE64;
        default:
            throw std::runtime_error("Unsupported jump opcode");
    }
}



// Scan forward from a branch start to find the merge/join target.
// Returns the target instruction index, or -1 if the branch ends with exit.
int find_merge_target(const bpf_insn* insns, int insn_cnt,
                              int scan_start, int scan_end) {
    for (int i = scan_start; i < scan_end && i < insn_cnt; ++i) {
        if (is_uncond_jump(insns[i])) {
            return jump_target_idx(insns[i], i);
        }
        if (is_exit_insn(insns[i])) {
            return -1;
        }
        if (is_ld_imm64_pair(insns[i])) {
            ++i;  // skip wide instruction pair
        }
    }
    // No explicit JA — the branch falls through to scan_end.
    return scan_end;
}


[[nodiscard]] static std::string jumpop_to_dafny(const bpf_insn& insn) {
    const bool is_jmp32 = (insn.code & bpf_opcode::CLASS_MASK) == bpf_opcode::JMP32;
    const uint8_t op    = insn.code & bpf_opcode::OP_MASK;

    switch (op) {
        case bpf_opcode::JEQ:  return is_jmp32 ? "JEQ32"  : "JEQ64";
        case bpf_opcode::JNE:  return is_jmp32 ? "JNE32"  : "JNE64";
        case bpf_opcode::JSET: return is_jmp32 ? "JSET32" : "JSET64";
        case bpf_opcode::JGT:  return is_jmp32 ? "JGT32"  : "JGT64";
        case bpf_opcode::JGE:  return is_jmp32 ? "JGE32"  : "JGE64";
        case bpf_opcode::JSGT: return is_jmp32 ? "JSGT32" : "JSGT64";
        case bpf_opcode::JSGE: return is_jmp32 ? "JSGE32" : "JSGE64";
        case bpf_opcode::JLT:  return is_jmp32 ? "JLT32"  : "JLT64";
        case bpf_opcode::JLE:  return is_jmp32 ? "JLE32"  : "JLE64";
        case bpf_opcode::JSLT: return is_jmp32 ? "JSLT32" : "JSLT64";
        case bpf_opcode::JSLE: return is_jmp32 ? "JSLE32" : "JSLE64";
        default:
            throw std::runtime_error("Unsupported conditional jump opcode");
    }
}

// Emit the Dafny semantic call for a conditional jump. The actual branching is
// handled later by insns_to_dafny() via jump_state.jmp_res.
[[nodiscard]] std::string emit_cond_jump_call(const bpf_insn& insn,
                                                     const std::string& current_state) {
    const bool reg_src = (insn.code & bpf_opcode::SRC_MASK) == bpf_opcode::X;
    const std::string jop = jumpop_to_dafny(insn);

    if (reg_src) {
        return "cond_jump_reg(" + current_state + ", CONDJMPREG(" +
               reg_to_dafny(insn.dst_reg) + ", " +
               reg_to_dafny(insn.src_reg) + ", " +
               jop + "))";
    }

    return "cond_jump_imm(" + current_state + ", CONDJMPIMM(" +
           reg_to_dafny(insn.dst_reg) + ", " +
           bv64_literal(sign_ext32_to_u64(insn.imm)) + ", " +
           jop + "))";
}








std::string_view DafnyEmitter::to_string(JumpOp op) noexcept {
    switch (op) {
        case JumpOp::JEQ32:  return "JEQ32";
        case JumpOp::JNE32:  return "JNE32";
        case JumpOp::JSET32: return "JSET32";
        case JumpOp::JGT32:  return "JGT32";
        case JumpOp::JGE32:  return "JGE32";
        case JumpOp::JLT32:  return "JLT32";
        case JumpOp::JLE32:  return "JLE32";
        case JumpOp::JSGT32: return "JSGT32";
        case JumpOp::JSGE32: return "JSGE32";
        case JumpOp::JSLT32: return "JSLT32";
        case JumpOp::JSLE32: return "JSLE32";
        case JumpOp::JEQ64:  return "JEQ64";
        case JumpOp::JNE64:  return "JNE64";
        case JumpOp::JSET64: return "JSET64";
        case JumpOp::JGT64:  return "JGT64";
        case JumpOp::JGE64:  return "JGE64";
        case JumpOp::JLT64:  return "JLT64";
        case JumpOp::JLE64:  return "JLE64";
        case JumpOp::JSGT64: return "JSGT64";
        case JumpOp::JSGE64: return "JSGE64";
        case JumpOp::JSLT64: return "JSLT64";
        case JumpOp::JSLE64: return "JSLE64";
    }
    return "<unknown-jmp>";
}



void DafnyEmitter::emit(const DecodedControlFlowInsn& insn, std::stringstream& out) {
    switch (insn.kind) {
        case ControlFlowKind::COND_REG:
            if (!insn.jmp_op) throw std::runtime_error("Missing jmp_op");
            out << "CONDJMPREG(" << reg_to_dafny(insn.dst) << ", "
                << reg_to_dafny(insn.src) << ", "
                << DafnyEmitter::to_string(*insn.jmp_op) << ")";
            return;
        case ControlFlowKind::COND_IMM:
            if (!insn.jmp_op) throw std::runtime_error("Missing jmp_op");
            out << "CONDJMPIMM(" << reg_to_dafny(insn.dst) << ", "
                << bv64_literal(sign_ext32_to_u64(insn.imm)) << ", "
                << DafnyEmitter::to_string(*insn.jmp_op) << ")";
            return;
        case ControlFlowKind::JA:
            out << "JA";
            return;
        case ControlFlowKind::CALL:
            out << "CALL";
            return;
        case ControlFlowKind::EXIT:
            out << "EXIT";
            return;
    }
    throw std::runtime_error("Unknown control-flow instruction kind");
}

