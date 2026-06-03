#include <cstdint>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <iomanip>

#include "translator.hpp"

// ============================================================
// Forward declarations
// ============================================================

struct ArithSpecCall {
    std::string semantic_fun;
    std::string ctor_name;
    std::string op_name;
    bool uses_src = false;
    bool uses_imm = false;
};

[[nodiscard]] static ArithSpecCall map_arith_to_spec_call(const DecodedArithInsn& insn);
static void emit_arith_ctor(const DecodedArithInsn& insn,
                            const ArithSpecCall& spec,
                            std::stringstream& out);

static std::string bv64_literal_from_s32(int32_t imm);

// ============================================================
// Helpers
// ============================================================

static std::string bv64_literal_from_s32(int32_t imm) {
    const uint64_t v = sign_ext32_to_u64(imm);
    std::ostringstream ss;
    ss << "0x" << std::hex << std::setfill('0') << std::setw(16) << v;
    return ss.str();
}



// ============================================================
// Arithmetic decoder
// ============================================================

bool ArithDecoder::is_arithmetic(const bpf_insn& insn) noexcept {
    const uint8_t cls = insn.code & bpf_opcode::CLASS_MASK;
    if (cls != bpf_opcode::ALU && cls != bpf_opcode::ALU64) {
        return false;
    }

    const uint8_t op = insn.code & bpf_opcode::OP_MASK;
    return op != bpf_opcode::MOV;
}

std::optional<DecodedArithInsn> ArithDecoder::decode(const bpf_insn& insn) {
    if (!is_arithmetic(insn)) {
        return std::nullopt;
    }

    const uint8_t op      = insn.code & bpf_opcode::OP_MASK;
    const bool is64       = (insn.code & bpf_opcode::CLASS_MASK) == bpf_opcode::ALU64;

    DecodedArithInsn out;
    out.dst = insn.dst_reg;
    out.src = insn.src_reg;
    out.imm = insn.imm;

    if (op == bpf_opcode::NEG || op == bpf_opcode::END) {
        out.kind     = ArithKind::UNARY;
        out.unary_op = decode_unary(insn, is64, op);
        return out;
    }

    const bool reg_source = (insn.code & bpf_opcode::SRC_MASK) == bpf_opcode::X;
    
    out.kind   = reg_source ? ArithKind::BIN_REG : ArithKind::BIN_IMM;
    out.bin_op = decode_binary(op, is64, insn.off);
    return out;
}

UnaryOp ArithDecoder::decode_unary(const bpf_insn& insn, bool is64, uint8_t op) {
    if (op == bpf_opcode::NEG) {
        return is64 ? UnaryOp::NEG64 : UnaryOp::NEG32;
    }

    // END decoding:
    // - width is in imm: 16/32/64
    // - source bit selects TO_LE / TO_BE
    // - for your current Dafny conventions, ALU64 + END is lowered to SWAPxx
    const int width = insn.imm;
    const uint8_t src_mode = insn.code & bpf_opcode::SRC_MASK;
    const bool to_be = (src_mode == bpf_opcode::END_TO_BE);

    if (is64) {
        // ALU64 + END + TO_BE is invalid (unknown opcode 0xdf)
        if (to_be) {
            throw std::runtime_error("END: ALU64 with TO_BE is invalid");
        }
        switch (width) {
            case 16: return UnaryOp::BV2_SWAP16;
            case 32: return UnaryOp::BV2_SWAP32;
            case 64: return UnaryOp::BV2_SWAP64;
            default:
                throw std::runtime_error("END/BSWAP: invalid width " + std::to_string(width));
        }
    }

    if (!to_be) {
        switch (width) {
            case 16: return UnaryOp::BV2_LE16;
            case 32: return UnaryOp::BV2_LE32;
            case 64: return UnaryOp::BV2_LE64;
            default:
                throw std::runtime_error("END/LE: invalid width " + std::to_string(width));
        }
    } else {
        switch (width) {
            case 16: return UnaryOp::BV2_BE16;
            case 32: return UnaryOp::BV2_BE32;
            case 64: return UnaryOp::BV2_BE64;
            default:
                throw std::runtime_error("END/BE: invalid width " + std::to_string(width));
        }
    }
}

BinOp ArithDecoder::decode_binary(uint8_t op, bool is64, int16_t off) {
    auto select = [&](BinOp b32, BinOp b64) -> BinOp {
        return is64 ? b64 : b32;
    };

    switch (op) {
        case bpf_opcode::ADD:  return select(BinOp::ADD32,      BinOp::ADD64);
        case bpf_opcode::SUB:  return select(BinOp::SUB32,      BinOp::SUB64);
        case bpf_opcode::MUL:  return select(BinOp::MUL32,      BinOp::MUL64);
        case bpf_opcode::DIV:  return (off == 1) ? select(BinOp::SDIV32, BinOp::SDIV64)
                                                 : select(BinOp::DIV32,  BinOp::DIV64);
        case bpf_opcode::MOD:  return (off == 1) ? select(BinOp::SMOD32, BinOp::SMOD64)
                                                 : select(BinOp::MOD32,  BinOp::MOD64);
        case bpf_opcode::OR:   return select(BinOp::BV_OR32,    BinOp::BV_OR64);
        case bpf_opcode::AND:  return select(BinOp::BV_AND32,   BinOp::BV_AND64);
        case bpf_opcode::XOR:  return select(BinOp::BV_XOR32,   BinOp::BV_XOR64);
        case bpf_opcode::LSH:  return select(BinOp::BV_SHL32,   BinOp::BV_SHL64);
        case bpf_opcode::RSH:  return select(BinOp::BV_LSHR32,  BinOp::BV_LSHR64);
        case bpf_opcode::ARSH: return select(BinOp::BV_ASHR32,  BinOp::BV_ASHR64);
        default: {
            std::ostringstream ss;
            ss << "Unsupported binary opcode 0x" << std::hex << static_cast<int>(op);
            throw std::runtime_error(ss.str());
        }
    }
}

// ============================================================
// Dafny token rendering
// ============================================================

std::string_view DafnyEmitter::to_string(UnaryOp op) noexcept {
    switch (op) {
        case UnaryOp::NEG32:      return "NEG32";
        case UnaryOp::NEG64:      return "NEG64";
        case UnaryOp::BV2_LE16:   return "BV2LE16";
        case UnaryOp::BV2_LE32:   return "BV2LE32";
        case UnaryOp::BV2_LE64:   return "BV2LE64";
        case UnaryOp::BV2_BE16:   return "BV2BE16";
        case UnaryOp::BV2_BE32:   return "BV2BE32";
        case UnaryOp::BV2_BE64:   return "BV2BE64";
        case UnaryOp::BV2_SWAP16: return "BV2SWAP16";
        case UnaryOp::BV2_SWAP32: return "BV2SWAP32";
        case UnaryOp::BV2_SWAP64: return "BV2SWAP64";
    }
    return "<unknown-unary>";
}

std::string_view DafnyEmitter::to_string(BinOp op) noexcept {
    switch (op) {
        case BinOp::ADD32:     return "ADD32";
        case BinOp::SUB32:     return "SUB32";
        case BinOp::MUL32:     return "MUL32";
        case BinOp::DIV32:     return "DIV32";
        case BinOp::SDIV32:    return "SDIV32";
        case BinOp::MOD32:     return "MOD32";
        case BinOp::SMOD32:    return "SMOD32";
        case BinOp::BV_OR32:   return "BVOR32";
        case BinOp::BV_AND32:  return "BVAND32";
        case BinOp::BV_XOR32:  return "BVXOR32";
        case BinOp::BV_LSHR32: return "BVLSHR32";
        case BinOp::BV_ASHR32: return "BVASHR32";
        case BinOp::BV_SHL32:  return "BVSHL32";
        case BinOp::ADD64:     return "ADD64";
        case BinOp::SUB64:     return "SUB64";
        case BinOp::MUL64:     return "MUL64";
        case BinOp::DIV64:     return "DIV64";
        case BinOp::SDIV64:    return "SDIV64";
        case BinOp::MOD64:     return "MOD64";
        case BinOp::SMOD64:    return "SMOD64";
        case BinOp::BV_OR64:   return "BVOR64";
        case BinOp::BV_AND64:  return "BVAND64";
        case BinOp::BV_XOR64:  return "BVXOR64";
        case BinOp::BV_LSHR64: return "BVLSHR64";
        case BinOp::BV_ASHR64: return "BVASHR64";
        case BinOp::BV_SHL64:  return "BVSHL64";
    }
    return "<unknown-bin>";
}

void DafnyEmitter::emit(const DecodedArithInsn& insn, std::stringstream& out) {
    const ArithSpecCall spec = map_arith_to_spec_call(insn);
    emit_arith_ctor(insn, spec, out);
}

// ============================================================
// Arith mapping + emission
// ============================================================

[[nodiscard]] static ArithSpecCall map_arith_to_spec_call(const DecodedArithInsn& insn) {
    ArithSpecCall out{};

    switch (insn.kind) {
        case ArithKind::UNARY:
            if (!insn.unary_op) {
                throw std::runtime_error("Missing unary op for unary arithmetic instruction");
            }
            out.semantic_fun = "arith_unary";
            out.ctor_name    = "ARITHUNARY";
            out.op_name      = std::string(DafnyEmitter::to_string(*insn.unary_op));
            return out;

        case ArithKind::BIN_REG:
            if (!insn.bin_op) {
                throw std::runtime_error("Missing binary op for BIN_REG arithmetic instruction");
            }
            out.ctor_name = "ARITHBINREG";
            out.op_name   = std::string(DafnyEmitter::to_string(*insn.bin_op));
            out.uses_src  = true;

            switch (*insn.bin_op) {
                case BinOp::ADD64: out.semantic_fun = "add64_reg"; return out;
                case BinOp::SUB64: out.semantic_fun = "sub64_reg"; return out;
                default:           out.semantic_fun = "arith_binop_reg"; return out;
            }

        case ArithKind::BIN_IMM:
            if (!insn.bin_op) {
                throw std::runtime_error("Missing binary op for BIN_IMM arithmetic instruction");
            }
            out.ctor_name = "ARITHBINIMM";
            out.op_name   = std::string(DafnyEmitter::to_string(*insn.bin_op));
            out.uses_imm  = true;

            switch (*insn.bin_op) {
                case BinOp::ADD64: out.semantic_fun = "add64_imm"; return out;
                case BinOp::SUB64: out.semantic_fun = "sub64_imm"; return out;
                default:           out.semantic_fun = "arith_binop_imm"; return out;
            }
    }

    throw std::runtime_error("Unknown arithmetic instruction kind");
}

static void emit_arith_ctor(const DecodedArithInsn& insn,
                            const ArithSpecCall& spec,
                            std::stringstream& out) {
    out << spec.ctor_name << "(" << reg_to_dafny(insn.dst);

    if (spec.uses_src) {
        out << ", " << reg_to_dafny(insn.src);
    }
    if (spec.uses_imm) {
        // Keep the useful idea from implementation 1:
        // emit the imm as a sign-extended 64-bit literal.
        out << ", " << bv64_literal_from_s32(insn.imm);
    }

    out << ", " << spec.op_name << ")";
}

int translate_arith_insn(const bpf_insn& insn,
                                const std::string& in_state,
                                const std::string& out_state,
                                std::stringstream& out,
                                RegUsage& regs,
                                int depth) {
    auto decoded = ArithDecoder::decode(insn);
    if (!decoded) {
        return -1;
    }

    regs.mark(insn.dst_reg);
    if (decoded->kind == ArithKind::BIN_REG) {
        regs.mark(insn.src_reg);
    }

    const ArithSpecCall spec = map_arith_to_spec_call(*decoded);

    out << indent(depth)
        << "var " << out_state << " := "
        << spec.semantic_fun << "(" << in_state << ", ";

    emit_arith_ctor(*decoded, spec, out);
    out << ");\n";

    return 0;
}