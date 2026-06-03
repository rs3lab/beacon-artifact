#include <string>
#include <sstream>
#include <stdexcept>
#include <iomanip>
#include "translator.hpp"

/* ================================================================
 *  Helpers: 
 * ================================================================ */



// Convert register index to Dafny name (R0..R10).
[[nodiscard]] std::string reg_to_dafny(uint8_t reg) {
    if (reg >= BPF_REG_COUNT) {
        throw std::runtime_error("Invalid register index " + std::to_string(reg));
    }
    return "R" + std::to_string(reg);
}

// Dafny expects lowercase boolean literals.
[[nodiscard]] std::string bool_to_dafny(bool value) {
    return value ? "true" : "false";
}

// Indentation - 8 spaces base + 4 per nesting level.
[[nodiscard]] std::string indent(int depth) {
    return std::string(8 + 4 * depth, ' ');
}

uint64_t sign_ext32_to_u64(int32_t x) {
    return static_cast<uint64_t>(static_cast<int64_t>(x));
}

std::string bv64_literal(uint64_t v) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::setfill('0') << std::setw(16) << v;
    return ss.str();
}

[[nodiscard]] bool is_ld_imm64_pair(const bpf_insn& insn) noexcept {
    const uint8_t cls  = insn.code & bpf_opcode::CLASS_MASK;
    const uint8_t size = insn.code & bpf_opcode::SIZE_MASK;
    const uint8_t mode = insn.code & bpf_opcode::MODE_MASK;

    return cls == 0x00 &&   // BPF_LD
           size == bpf_opcode::DW_SIZE &&
           mode == 0x00;  // BPF_IMM
}


[[nodiscard]] int next_linear_insn_idx(const bpf_insn& insn, int insn_idx) {
    return is_ld_imm64_pair(insn) ? (insn_idx + 2) : (insn_idx + 1);
}

