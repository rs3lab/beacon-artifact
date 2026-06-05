#ifndef TRANSLATOR_HPP
#define TRANSLATOR_HPP

#include <array>
#include <cstdint>
#include <linux/bpf.h>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

static constexpr std::size_t BPF_REG_COUNT = 11;

// --------------------------------------------------
// Prog_type and attach_type strings 
// --------------------------------------------------
constexpr int bpf_prog_type_str_size = 33;
constexpr int expected_attach_type_str_size = 57;
// --------------------------------------------------
// Helpers
// --------------------------------------------------

// Fresh state names are required because each translated instruction produces a
// new verifier state in Dafny.
struct FreshStateGen {
    int counter{0};
    std::string next() {
        return "s" + std::to_string(counter++);
    }
};

// --------------------------------------------------
// Register usage
// --------------------------------------------------
struct RegUsage {
    std::array<bool, BPF_REG_COUNT> used{};

    void mark(uint8_t r) {
        if (r < BPF_REG_COUNT) {
            used[r] = true;
        }
    }
};

std::string reg_to_dafny(uint8_t reg);
std::string bool_to_dafny(bool value);
std::string indent(int depth);
uint64_t sign_ext32_to_u64(int32_t x);
std::string bv64_literal(uint64_t v);




int find_merge_target(const bpf_insn* insns, int insn_cnt,
                      int scan_start, int scan_end);
                      
std::string emit_cond_jump_call(const bpf_insn& insn,
                                const std::string& current_state);

// translation functions — declared here, defined in their .cpp files
int translate_arith_insn(const bpf_insn& insn,
                         const std::string& in_state,
                         const std::string& out_state,
                         std::stringstream& out,
                         RegUsage& regs,
                         int depth);

int translate_datamov_insn(const bpf_insn& insn,
                           const std::string& in_state,
                           const std::string& out_state,
                           std::stringstream& out,
                           RegUsage& regs,
                           int depth);

int translate_memory_insn(const bpf_insn& insn,
                          const std::string& in_state,
                          const std::string& out_state,
                          std::stringstream& out,
                          RegUsage& regs,
                          int depth);


// --------------------------------------------------
// Arithmetic
// --------------------------------------------------
enum class ArithKind {
    UNARY,
    BIN_REG,
    BIN_IMM
};

enum class UnaryOp {
    NEG32,
    NEG64,
    BV2_LE16, BV2_LE32, BV2_LE64,
    BV2_BE16, BV2_BE32, BV2_BE64,
    BV2_SWAP16, BV2_SWAP32, BV2_SWAP64
};

enum class BinOp {
    ADD32, SUB32, MUL32,
    DIV32, SDIV32, MOD32, SMOD32,
    BV_OR32, BV_AND32, BV_XOR32,
    BV_LSHR32, BV_ASHR32, BV_SHL32,

    ADD64, SUB64, MUL64,
    DIV64, SDIV64, MOD64, SMOD64,
    BV_OR64, BV_AND64, BV_XOR64,
    BV_LSHR64, BV_ASHR64, BV_SHL64
};

struct DecodedArithInsn {
    ArithKind kind{};
    uint8_t dst{};
    uint8_t src{};
    int32_t imm{};
    std::optional<UnaryOp> unary_op;
    std::optional<BinOp> bin_op;
};

// --------------------------------------------------
// Data movement
// --------------------------------------------------
enum class DataMovKind {
    IMM,
    REG
};

enum class MovImmOp {
    MOVIMM32,
    MOVIMM64,
    LOADIMM64,
    LOADMAPFD,
    LOADMAPIDX
};

enum class MovRegOp {
    MOV32,
    MOVSX8TO32,
    MOVSX16TO32,
    MOV64,
    MOVSX8TO64,
    MOVSX16TO64,
    MOVSX32TO64
};

struct DecodedDataMovInsn {
    DataMovKind kind{};
    uint8_t dst{};
    uint8_t src{};
    int32_t imm{};
    std::optional<MovImmOp> mov_imm_op;
    std::optional<MovRegOp> mov_reg_op;
};

// --------------------------------------------------
// Memory
// --------------------------------------------------
enum class Size {
    B,
    HW,
    W,
    DW
};

enum class AtomicOp {
    ATOMIC_ADD,
    ATOMIC_AND,
    ATOMIC_OR,
    ATOMIC_XOR,
    ATOMIC_FETCH_ADD,
    ATOMIC_FETCH_AND,
    ATOMIC_FETCH_OR,
    ATOMIC_FETCH_XOR,
    ATOMIC_XCHG,
    ATOMIC_CMPXCHG
};

enum class MemoryKind {
    LOAD,
    STORE_REG,
    STORE_IMM,
    ATOMIC
};

struct DecodedMemoryInsn {
    MemoryKind kind{};
    uint8_t dst{};
    uint8_t src{};
    int32_t imm{};
    int16_t off{};
    Size size{};
    bool sign_ext{false};
    std::optional<AtomicOp> atomic_op;
};

// --------------------------------------------------
// Control flow
// --------------------------------------------------
enum class ControlFlowKind {
    COND_REG,
    COND_IMM,
    JA,
    CALL,
    EXIT
};

enum class JumpOp {
    JEQ32, JNE32, JSET32, JGT32, JGE32, JLT32, JLE32, JSGT32, JSGE32, JSLT32, JSLE32,
    JEQ64, JNE64, JSET64, JGT64, JGE64, JLT64, JLE64, JSGT64, JSGE64, JSLT64, JSLE64
};

struct DecodedControlFlowInsn {
    ControlFlowKind kind{};
    uint8_t dst{};
    uint8_t src{};
    int32_t imm{};
    int16_t off{};
    std::optional<JumpOp> jmp_op;
    bool uses_src{false};
    bool uses_imm{false};
};

// More CFG-oriented decoded form used by the structured translator.
enum class CtrlFlowKind {
    EXIT,
    JA,
    COND_JMP,
    CALL,
    PSEUDO_CALL
};

struct DecodedCtrlFlowInsn {
    CtrlFlowKind kind{};
    int target_idx{};
    int fallthrough_idx{};
};

// Continuation stack entries used when recursively structuring the CFG into
// nested Dafny if/else blocks.
enum class ResumeKind {
    CloseBlock,
    ElseBranch,
    ReturnFromCall,
    MergeContinue
};

struct ResumePoint {
    ResumeKind kind{};
    int target_idx{-1};
    std::string state_name;       // ElseBranch: jump_state to restore current_state
                                  // MergeContinue: jump_state (diagnostic / else restore)
    std::string join_state_name;  // MergeContinue only: the unified phi-state name
                                  // that both branches must assign before closing
};


struct verify_range {
    int start;
    int end;
};

// --------------------------------------------------
// Opcodes
// --------------------------------------------------
namespace bpf_opcode {

inline constexpr uint8_t CLASS_MASK = 0x07;

inline constexpr uint8_t LDX   = 0x01;
inline constexpr uint8_t ST    = 0x02;
inline constexpr uint8_t STX   = 0x03;
inline constexpr uint8_t ALU   = 0x04;
inline constexpr uint8_t ALU64 = 0x07;

inline constexpr uint8_t SRC_MASK = 0x08;
inline constexpr uint8_t K = 0x00;
inline constexpr uint8_t X = 0x08;

inline constexpr uint8_t SIZE_MASK = 0x18;
inline constexpr uint8_t W_SIZE    = 0x00;
inline constexpr uint8_t HW_SIZE   = 0x08;
inline constexpr uint8_t B_SIZE    = 0x10;
inline constexpr uint8_t DW_SIZE   = 0x18;

inline constexpr uint8_t MODE_MASK = 0xe0;
inline constexpr uint8_t MEM       = 0x60;
inline constexpr uint8_t MEMSX     = 0x80;
inline constexpr uint8_t ATOMIC    = 0xc0;

inline constexpr uint8_t END_TO_LE = K;
inline constexpr uint8_t END_TO_BE = X;

inline constexpr uint8_t OP_MASK = 0xf0;

inline constexpr uint8_t ADD  = 0x00;
inline constexpr uint8_t SUB  = 0x10;
inline constexpr uint8_t MUL  = 0x20;
inline constexpr uint8_t DIV  = 0x30;
inline constexpr uint8_t OR   = 0x40;
inline constexpr uint8_t AND  = 0x50;
inline constexpr uint8_t LSH  = 0x60;
inline constexpr uint8_t RSH  = 0x70;
inline constexpr uint8_t NEG  = 0x80;
inline constexpr uint8_t MOD  = 0x90;
inline constexpr uint8_t XOR  = 0xa0;
inline constexpr uint8_t MOV  = 0xb0;
inline constexpr uint8_t ARSH = 0xc0;
inline constexpr uint8_t END  = 0xd0;

inline constexpr int32_t ATOMIC_FETCH   = 0x01;
inline constexpr int32_t ATOMIC_OP_MASK = 0xf0;
inline constexpr int32_t ATOMIC_XCHG    = 0xe0;
inline constexpr int32_t ATOMIC_CMPXCHG = 0xf0;

inline constexpr uint8_t JMP   = 0x05;
inline constexpr uint8_t JMP32 = 0x06;

inline constexpr uint8_t JA    = 0x00;
inline constexpr uint8_t JEQ   = 0x10;
inline constexpr uint8_t JGT   = 0x20;
inline constexpr uint8_t JGE   = 0x30;
inline constexpr uint8_t JSET  = 0x40;
inline constexpr uint8_t JNE   = 0x50;
inline constexpr uint8_t JSGT  = 0x60;
inline constexpr uint8_t JSGE  = 0x70;
inline constexpr uint8_t CALL  = 0x80;
inline constexpr uint8_t EXIT  = 0x90;
inline constexpr uint8_t JLT   = 0xa0;
inline constexpr uint8_t JLE   = 0xb0;
inline constexpr uint8_t JSLT  = 0xc0;
inline constexpr uint8_t JSLE  = 0xd0;

} // namespace bpf_opcode


// --------------------------------------------------
// Decoders
// --------------------------------------------------
class ArithDecoder {
public:
    [[nodiscard]] static bool is_arithmetic(const bpf_insn& insn) noexcept;
    [[nodiscard]] static std::optional<DecodedArithInsn> decode(const bpf_insn& insn);

private:
    [[nodiscard]] static UnaryOp decode_unary(const bpf_insn& insn, bool is64, uint8_t op);
    [[nodiscard]] static BinOp decode_binary(uint8_t op, bool is64, int16_t off);
};

class DataMovDecoder {
public:
    [[nodiscard]] static bool is_datamov(const bpf_insn& insn) noexcept;
    [[nodiscard]] static std::optional<DecodedDataMovInsn> decode(const bpf_insn& insn);
};

class MemoryDecoder {
public:
    [[nodiscard]] static bool is_memory(const bpf_insn& insn) noexcept;
    [[nodiscard]] static std::optional<DecodedMemoryInsn> decode(const bpf_insn& insn);

private:
    [[nodiscard]] static Size decode_size(uint8_t code);
    [[nodiscard]] static AtomicOp decode_atomic_op(int32_t imm);
};

class ControlFlowDecoder {
public:
    [[nodiscard]] static bool is_control_flow(const bpf_insn& insn) noexcept;
    [[nodiscard]] static std::optional<DecodedControlFlowInsn> decode(const bpf_insn& insn);

private:
    [[nodiscard]] static JumpOp decode_jump_op(uint8_t op, bool is_jmp32);
};

class CtrlFlowDecoder {
public:
    [[nodiscard]] static bool is_control_flow(const bpf_insn& insn) noexcept;
    [[nodiscard]] static std::optional<DecodedCtrlFlowInsn> decode(const bpf_insn& insn, int insn_idx);
};

// --------------------------------------------------
// Dafny emitter
// --------------------------------------------------
class DafnyEmitter {
public:
    [[nodiscard]] static std::string_view to_string(UnaryOp op) noexcept;
    [[nodiscard]] static std::string_view to_string(BinOp op) noexcept;
    [[nodiscard]] static std::string_view to_string(MovImmOp op) noexcept;
    [[nodiscard]] static std::string_view to_string(MovRegOp op) noexcept;
    [[nodiscard]] static std::string_view to_string(Size size) noexcept;
    [[nodiscard]] static std::string_view to_string(AtomicOp op) noexcept;
    [[nodiscard]] static std::string_view to_string(JumpOp op) noexcept;

    static void emit(const DecodedArithInsn& insn, std::stringstream& out);
    static void emit(const DecodedDataMovInsn& insn, std::stringstream& out);
    static void emit(const DecodedMemoryInsn& insn, std::stringstream& out);
    static void emit(const DecodedControlFlowInsn& insn, std::stringstream& out);
};



// --------------------------------------------------
// Public API
// --------------------------------------------------

int insns_to_dafny(const bpf_insn* insns,
                   int insn_cnt,
                   std::stringstream& trans_dafny,
                   bool* used_regs,
                   uint64_t *duration,
                   struct verify_range *range
                   );

// Build a complete, self-contained Dafny module string directly from a
// bpf_insn array.  Throws std::runtime_error if translation fails.
// Used by both main.cpp (standalone binary) and bpf_verify_wrapper.cpp
std::string build_dafny_string(const bpf_insn* insns,
                               int insn_cnt,
                               const std::string& method_name,
                               uint32_t prog_type,
                               uint32_t attach_type);

#endif


bool is_ld_imm64_pair(const bpf_insn& insn) noexcept;
int next_linear_insn_idx(const bpf_insn& insn, int insn_idx);

bool is_exit_insn(const bpf_insn& insn) noexcept;
bool is_uncond_jump(const bpf_insn& insn) noexcept;
bool is_cond_jump(const bpf_insn& insn) noexcept;
bool is_pseudo_call(const bpf_insn& insn) noexcept;
bool is_call(const bpf_insn& insn) noexcept;
bool is_jump_class(uint8_t cls) noexcept;
int  jump_target_idx(const bpf_insn& insn, int insn_idx);