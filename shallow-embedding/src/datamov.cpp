#include <sstream>
#include <stdexcept>
#include <string>
#include <iomanip>
#include "translator.hpp"


// Note: LOADIMM64/LOADMAPFD/LOADMAPIDX are handled in main.cpp
// for the two-instruction BPF_LD|BPF_DW|BPF_IMM encoding.

// ── DataMovDecoder ────────────────────────────────────────────────

bool DataMovDecoder::is_datamov(const bpf_insn& insn) noexcept {
    const uint8_t cls = insn.code & bpf_opcode::CLASS_MASK;
    if (cls != bpf_opcode::ALU && cls != bpf_opcode::ALU64)
        return false;
    const uint8_t op = insn.code & bpf_opcode::OP_MASK;
    return op == bpf_opcode::MOV;
}

std::optional<DecodedDataMovInsn> DataMovDecoder::decode(const bpf_insn& insn) {
    if (!is_datamov(insn)) return std::nullopt;

    const bool is64       = (insn.code & bpf_opcode::CLASS_MASK) == bpf_opcode::ALU64;
    const bool reg_source = (insn.code & bpf_opcode::SRC_MASK) == bpf_opcode::X;

    DecodedDataMovInsn out;
    out.dst = insn.dst_reg;
    out.src = insn.src_reg;
    out.imm = insn.imm;

    if (reg_source) {
        out.kind = DataMovKind::REG;
        if (insn.off == 0) {
            out.mov_reg_op = is64 ? MovRegOp::MOV64 : MovRegOp::MOV32;
        } else if (is64) {
            if (insn.off == 8)       out.mov_reg_op = MovRegOp::MOVSX8TO64;
            else if (insn.off == 16) out.mov_reg_op = MovRegOp::MOVSX16TO64;
            else if (insn.off == 32) out.mov_reg_op = MovRegOp::MOVSX32TO64;
            else return std::nullopt;
        } else {
            if (insn.off == 8)       out.mov_reg_op = MovRegOp::MOVSX8TO32;
            else if (insn.off == 16) out.mov_reg_op = MovRegOp::MOVSX16TO32;
            else return std::nullopt;
        }
    } else {
        out.kind = DataMovKind::IMM;
        out.mov_imm_op = is64 ? MovImmOp::MOVIMM64 : MovImmOp::MOVIMM32;
    }

    return out;
}

// ── DafnyEmitter ─────────────────────────────────────────────────

std::string_view DafnyEmitter::to_string(MovImmOp op) noexcept {
    switch (op) {
        case MovImmOp::MOVIMM32:   return "MOVIMM32";
        case MovImmOp::MOVIMM64:   return "MOVIMM64";
        case MovImmOp::LOADIMM64:  return "LOADIMM64";
        case MovImmOp::LOADMAPFD:  return "LOADMAPFD";
        case MovImmOp::LOADMAPIDX: return "LOADMAPIDX";
    }
    return "<unknown-movimm>";
}

std::string_view DafnyEmitter::to_string(MovRegOp op) noexcept {
    switch (op) {
        case MovRegOp::MOV32:       return "MOV32";
        case MovRegOp::MOVSX8TO32:  return "MOVSX8TO32";
        case MovRegOp::MOVSX16TO32: return "MOVSX16TO32";
        case MovRegOp::MOV64:       return "MOV64";
        case MovRegOp::MOVSX8TO64:  return "MOVSX8TO64";
        case MovRegOp::MOVSX16TO64: return "MOVSX16TO64";
        case MovRegOp::MOVSX32TO64: return "MOVSX32TO64";
    }
    return "<unknown-movreg>";
}

// ── internal helpers ──────────────────────────────────────────────

struct DataMovSpecCall {
    std::string semantic_fun;
    std::string ctor_name;
    std::string op_name;
    bool uses_src = false;
    bool uses_imm = false;
};

[[nodiscard]] static DataMovSpecCall map_datamov_to_spec_call(
        const DecodedDataMovInsn& insn) {
    DataMovSpecCall out{};
    switch (insn.kind) {
        case DataMovKind::IMM:
            if (!insn.mov_imm_op)
                throw std::runtime_error("Missing mov_imm_op");
            out.semantic_fun = "datamov_imm";
            out.ctor_name    = "DATAMOVIMM";
            out.op_name      = std::string(DafnyEmitter::to_string(*insn.mov_imm_op));
            out.uses_imm     = true;
            return out;
        case DataMovKind::REG:
            if (!insn.mov_reg_op)
                throw std::runtime_error("Missing mov_reg_op");
            out.semantic_fun = "datamov_reg";
            out.ctor_name    = "DATAMOVREG";
            out.op_name      = std::string(DafnyEmitter::to_string(*insn.mov_reg_op));
            out.uses_src     = true;
            return out;
    }
    throw std::runtime_error("Unknown DataMovKind");
}

static void emit_datamov_ctor(const DecodedDataMovInsn& insn,
                               const DataMovSpecCall& spec,
                               std::stringstream& out) {
    out << spec.ctor_name << "(" << reg_to_dafny(insn.dst);
    if (spec.uses_imm) {
        if (!insn.mov_imm_op)
            throw std::runtime_error("Missing mov_imm_op");
        const uint64_t val = (*insn.mov_imm_op == MovImmOp::MOVIMM32)
            ? static_cast<uint64_t>(static_cast<uint32_t>(insn.imm))
            : sign_ext32_to_u64(insn.imm);
        out << ", " << bv64_literal(val);
    }
    if (spec.uses_src)
        out << ", " << reg_to_dafny(insn.src);
    out << ", " << spec.op_name << ")";
}

void DafnyEmitter::emit(const DecodedDataMovInsn& insn, std::stringstream& out) {
    const DataMovSpecCall spec = map_datamov_to_spec_call(insn);
    emit_datamov_ctor(insn, spec, out);
}

// ── translate_datamov_insn ────────────────────────────────────────

int translate_datamov_insn(const bpf_insn& insn,
                           const std::string& in_state,
                           const std::string& out_state,
                           std::stringstream& out,
                           RegUsage& regs,
                           int depth) {
    auto decoded = DataMovDecoder::decode(insn);
    if (!decoded) return -1;

    regs.mark(insn.dst_reg);
    if (decoded->kind == DataMovKind::REG)
        regs.mark(insn.src_reg);

    const DataMovSpecCall spec = map_datamov_to_spec_call(*decoded);

    out << indent(depth) << "var " << out_state << " := "
        << spec.semantic_fun << "(" << in_state << ", ";
    emit_datamov_ctor(*decoded, spec, out);
    out << ");\n";

    return 0;
}