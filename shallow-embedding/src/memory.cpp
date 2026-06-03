#include "translator.hpp"



bool MemoryDecoder::is_memory(const bpf_insn& insn) noexcept {
    const uint8_t cls  = insn.code & bpf_opcode::CLASS_MASK;
    const uint8_t mode = insn.code & bpf_opcode::MODE_MASK;

    if (cls == bpf_opcode::LDX) {
        return mode == bpf_opcode::MEM || mode == bpf_opcode::MEMSX;
    }
    if (cls == bpf_opcode::ST) {
        return mode == bpf_opcode::MEM;
    }
    if (cls == bpf_opcode::STX) {
        return mode == bpf_opcode::MEM || mode == bpf_opcode::ATOMIC;
    }
    return false;
}

std::optional<DecodedMemoryInsn> MemoryDecoder::decode(const bpf_insn& insn) {
    if (!is_memory(insn)) {
        return std::nullopt;
    }

    const uint8_t cls  = insn.code & bpf_opcode::CLASS_MASK;
    const uint8_t mode = insn.code & bpf_opcode::MODE_MASK;

    DecodedMemoryInsn out;
    out.dst  = insn.dst_reg;
    out.src  = insn.src_reg;
    out.imm  = insn.imm;
    out.off  = insn.off;
    out.size = decode_size(insn.code);

    if (cls == bpf_opcode::LDX) {
        out.kind = MemoryKind::LOAD;
        out.sign_ext = (mode == bpf_opcode::MEMSX);
        return out;
    }

    if (cls == bpf_opcode::ST) {
        out.kind = MemoryKind::STORE_IMM;
        return out;
    }

    if (cls == bpf_opcode::STX && mode == bpf_opcode::MEM) {
        out.kind = MemoryKind::STORE_REG;
        return out;
    }

    if (cls == bpf_opcode::STX && mode == bpf_opcode::ATOMIC) {
        out.kind = MemoryKind::ATOMIC;
        out.atomic_op = decode_atomic_op(insn.imm);
        return out;
    }

    return std::nullopt;
}

Size MemoryDecoder::decode_size(uint8_t code) {
    switch (code & bpf_opcode::SIZE_MASK) {
        case bpf_opcode::B_SIZE:  return Size::B;
        case bpf_opcode::HW_SIZE: return Size::HW;
        case bpf_opcode::W_SIZE:  return Size::W;
        case bpf_opcode::DW_SIZE: return Size::DW;
        default:
            throw std::runtime_error("Unsupported memory size");
    }
}

AtomicOp MemoryDecoder::decode_atomic_op(int32_t imm) {
    if ((imm & bpf_opcode::ATOMIC_OP_MASK) == bpf_opcode::ATOMIC_XCHG)    return AtomicOp::ATOMIC_XCHG;
    if ((imm & bpf_opcode::ATOMIC_OP_MASK) == bpf_opcode::ATOMIC_CMPXCHG) return AtomicOp::ATOMIC_CMPXCHG;
    const bool fetch = (imm & bpf_opcode::ATOMIC_FETCH) != 0;
    const int32_t op = imm & bpf_opcode::ATOMIC_OP_MASK;
    switch (op) {
        case bpf_opcode::ADD:
            return fetch ? AtomicOp::ATOMIC_FETCH_ADD : AtomicOp::ATOMIC_ADD;
        case bpf_opcode::AND:
            return fetch ? AtomicOp::ATOMIC_FETCH_AND : AtomicOp::ATOMIC_AND;
        case bpf_opcode::OR:
            return fetch ? AtomicOp::ATOMIC_FETCH_OR : AtomicOp::ATOMIC_OR;
        case bpf_opcode::XOR:
            return fetch ? AtomicOp::ATOMIC_FETCH_XOR : AtomicOp::ATOMIC_XOR;
        default:
            throw std::runtime_error(
                "Unsupported atomic operation immediate " + std::to_string(imm)
            );
    }
}



// ============================================================
// 5. Memory mapping + emission
// ============================================================

struct MemorySpecCall {
    std::string semantic_fun;
    std::string ctor_name;
};

[[nodiscard]] static MemorySpecCall map_memory_to_spec_call(const DecodedMemoryInsn& insn) {
    switch (insn.kind) {
        case MemoryKind::LOAD:
            return {"mem_load", "MEMLD"};
        case MemoryKind::STORE_REG:
            return {"mem_store_reg", "MEMSTX"};
        case MemoryKind::STORE_IMM:
            return {"mem_store_imm", "MEMST"};
        case MemoryKind::ATOMIC:
            return {"mem_atomic", "ATOMICLS"};
    }

    throw std::runtime_error("Unknown memory instruction kind");
}

static void emit_memory_ctor(const DecodedMemoryInsn& insn,
                             const MemorySpecCall& spec,
                             std::stringstream& out) {
    switch (insn.kind) {
        case MemoryKind::LOAD:
            out << spec.ctor_name << "("
                << reg_to_dafny(insn.dst) << ", "
                << reg_to_dafny(insn.src) << ", "
                << insn.off << ", "
                << DafnyEmitter::to_string(insn.size) << ", "
                << bool_to_dafny(insn.sign_ext) << ")";
            return;

        case MemoryKind::STORE_REG:
            out << spec.ctor_name << "("
                << reg_to_dafny(insn.dst) << ", "
                << reg_to_dafny(insn.src) << ", "
                << insn.off << ", "
                << DafnyEmitter::to_string(insn.size) << ")";
            return;

        case MemoryKind::STORE_IMM:
            out << spec.ctor_name << "("
                << reg_to_dafny(insn.dst) << ", "
                << bv64_literal(sign_ext32_to_u64(insn.imm)) << ", "
                << insn.off << ", "
                << DafnyEmitter::to_string(insn.size) << ")";
            return;

        case MemoryKind::ATOMIC:
            if (!insn.atomic_op)
                throw std::runtime_error("Missing atomic_op");
            out << spec.ctor_name << "("
                << reg_to_dafny(insn.dst) << ", "
                << reg_to_dafny(insn.src) << ", "
                << insn.off << ", "
                << DafnyEmitter::to_string(insn.size) << ", "
                << DafnyEmitter::to_string(*insn.atomic_op) << ")";
            return;
    }

    throw std::runtime_error("Unknown memory instruction kind");
}

int translate_memory_insn(const bpf_insn& insn,
                                 const std::string& in_state,
                                 const std::string& out_state,
                                 std::stringstream& out,
                                 RegUsage& regs,
                                 int depth) {
    auto decoded = MemoryDecoder::decode(insn);
    if (!decoded) return -1;

    if (decoded->kind == MemoryKind::ATOMIC) {
        if (decoded->size != Size::W && decoded->size != Size::DW)
            throw std::runtime_error("Atomic only supports W/DW sizes");
    }

    regs.mark(insn.dst_reg);
    if (decoded->kind == MemoryKind::LOAD ||
        decoded->kind == MemoryKind::STORE_REG ||
        decoded->kind == MemoryKind::ATOMIC) {
        regs.mark(insn.src_reg);
    }

    const MemorySpecCall spec = map_memory_to_spec_call(*decoded);

    out << indent(depth) << "var " << out_state << " := "
        << spec.semantic_fun << "(" << in_state << ", ";
    emit_memory_ctor(*decoded, spec, out);
    out << ");\n";

    return 0;
}




std::string_view DafnyEmitter::to_string(Size size) noexcept {
    switch (size) {
        case Size::B:  return "B";
        case Size::HW: return "HW";
        case Size::W:  return "W";
        case Size::DW: return "DW";
    }
    return "<unknown-size>";
}

std::string_view DafnyEmitter::to_string(AtomicOp op) noexcept {
    switch (op) {
        case AtomicOp::ATOMIC_ADD:       return "ATOMIC_ADD";
        case AtomicOp::ATOMIC_AND:       return "ATOMIC_AND";
        case AtomicOp::ATOMIC_OR:        return "ATOMIC_OR";
        case AtomicOp::ATOMIC_XOR:       return "ATOMIC_XOR";
        case AtomicOp::ATOMIC_FETCH_ADD: return "ATOMIC_FETCH_ADD";
        case AtomicOp::ATOMIC_FETCH_AND: return "ATOMIC_FETCH_AND";
        case AtomicOp::ATOMIC_FETCH_OR:  return "ATOMIC_FETCH_OR";
        case AtomicOp::ATOMIC_FETCH_XOR: return "ATOMIC_FETCH_XOR";
        case AtomicOp::ATOMIC_XCHG:      return "ATOMIC_XCHG";
        case AtomicOp::ATOMIC_CMPXCHG:   return "ATOMIC_CMPXCHG";
    }
    return "<unknown-atomic>";
}



void DafnyEmitter::emit(const DecodedMemoryInsn& insn, std::stringstream& out) {
    const MemorySpecCall spec = map_memory_to_spec_call(insn);
    emit_memory_ctor(insn, spec, out);
}