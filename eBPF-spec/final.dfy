include "utils.dfy"
include "ctxmem-precond.dfy"
include "call2progmap.dfy"

/*
    Issue check manual: https://www.cse.chalmers.se/edu/course.2018/TDA567_Testing_Debugging_Verification/dafny_troubleshooting.pdf

    Must check:
    1. variable at right-hand size of ensures must be old()
    2. Once there is a modifies, ensure the fixed part are reassigned and use old() to refer the pre-state of the modifed veriables
    3. use conditional modifies and reads, e.g., reads if flag then {this} else {}
    4. as long as it the dst type is a pointer, must maintain the mapfd
    5. arithmetic operation on all pointers, like PTR_TO_PACKET_END is forbidden
    6. HARD-TODO: speculative executions

    TODO:
    1. Verify 32/64 bit signed division and modulo, modify +, -, *, /, % as signed
    2. Organize in one doc and sync with code comments
    3. Check permission levels and corresponding checks
    4. Test with bpf regression test dataset
    5. REGTYPES: scalar, PTR, NULL
    6. Raw and writable tracepoint:
        - Variable offset: raw and writable tracepoint buffer only allows const instead of variable offset
        - Buffer size: access bound is checked when attached to a concrete tracepoint/event
    4. have load/store/atomic for each instruction even if it doesn't support store or atomic

    Something:
    1. Verify 32/64 bit signed division and modulo, modify +, -, *, /, % as signed
    2. What is the permission model, especially for ptr leakage 
    3. Relaxation:
        - Atomic insn on context and stack memory
        - Store pointer to context
        - Pointer arithemtic
        - what is the need for loading from const context ptr?
        - very coarse-grained checks on helper calls. For example you can even pass a map ptr to 
        - what is the basis of the design of compatible_reg_types for helper call args?
        - Arithmetic on <ptr, scala> and <ptr, ptr>: why allow neg on ptr but not xor, or on ptr under allow_ptr_leak?
        - is it meaningful to sub64/32 on different types of pointers? The purpose of sub32/64 is for knowing the data length, which should be the same type.
    4. Stack, context memory
    5. Helper calls: map related helper calls
    6. Back to map memory
    7. check Serval and Rosette
    8. Add this: No 64-bit arith insns on a PTR_MAYBE_NULL and a scalar.
    9. alignment on different config and prog flag, and pointer types
    10. zero_size_allowed: https://github.com/torvalds/linux/commit/9fd29c08e5202
    11. it makes sense to not allow addition on map_ptr because it is a structure ptr not an array,
        every element can be accessed with name instead of accounting by adding offset from users.
    12. is it necessary to prevent integer overflow?

    Ironclad: https://github.com/Microsoft/Ironclad
    Loop invariant: https://www.toomey.org/tutor/text_books/Digital_Logic/Discrete%20Mathematics%20with%20Applications%20-%20Susanna%20S.%20Epp%20(2019).pdf
    Hoare logic and loop invariant: https://www.cs.cmu.edu/~aldrich/courses/15-819O-13sp/resources/hoare-logic.pdf
    
    Generating Loop Invariants for Program Verification by Transformation : https://arxiv.org/pdf/1708.07223
    Finding Loop Invariants for Programs over Arrays Using a Theorem Prover: https://citeseerx.ist.psu.edu/document?repid=rep1&type=pdf&doi=4f253291065a81776fd68e5c8f6b60eaf8aab9db
    Simplifying Loop Invariant Generation Using Splitter Predicates: https://theory.stanford.edu/~aiken/publications/papers/cav11full.pdf

    Fine-grained Caching of Verification Results: https://www.microsoft.com/en-us/research/wp-content/uploads/2016/12/krml245.pdf

    Dafny blogs: https://dafny.org/blog/


    Two ways:
    - unroll
    - loop invariant


    1.  Not every loop can have accurate loop invariants.
        For example:
        method Collatz(n: nat)
            requires n > 0
            ensures n == 1
        {
            var current := n;
            while current != 1
                invariant current > 0
                decreases *
            {
                if current % 2 == 0 {
                    current := current / 2;
                } else {
                    current := 3 * current + 1;
                }
            }
        }

    2.  If loop invariant cannot express the accurate state, it can fail the safety verification.


*/

class State {

    // Capabilities
    ghost var allow_ptr_leak: bool, bypass_spec_v1: bool, priv: bool

    //
    var attachType: AttachTypes, progType: ProgTypes

    // Registers
    ghost var r0:RegState, r1:RegState, r2:RegState, r3:RegState, r4:RegState, r5:RegState,
              r6:RegState, r7:RegState, r8:RegState, r9:RegState, r10: RegState

    // Memories
    // Stack
    var stack: array<bv8>
    var stackSlotType: array<REGTYPE>
    var idMeta: array<int64>
    // CTX
    var context: array<bv8>
    // Maps
    var maps: array<MapState>
    
    // The packet data and metadata length we can predicate from `if`
    var packet_data_range: int64, packet_meta_range: int64

    // Alignment
    var strict_alignment: bool

    constructor {:axiom} ()
        //
        ensures this.allow_ptr_leak == true
        ensures this.bypass_spec_v1 == true
        ensures this.priv == true
        //
        ensures fresh(this.r0) && fresh(this.r1) && fresh(this.r2) && fresh(this.r3) && fresh(this.r4) && fresh(this.r5)
        ensures fresh(this.r6) && fresh(this.r7) && fresh(this.r8) && fresh(this.r9) && fresh(this.r10)
        //
        ensures this.r0.regNo == R0 && this.r0.regType == UNINT
        ensures this.r1.regNo == R1 && this.r1.regType == CTXMEM && this.r1.regVal == 0
        ensures this.r2.regNo == R2 && this.r2.regType == UNINT
        ensures this.r3.regNo == R3 && this.r3.regType == UNINT
        ensures this.r4.regNo == R4 && this.r4.regType == UNINT
        ensures this.r5.regNo == R5 && this.r5.regType == UNINT
        ensures this.r6.regNo == R6 && this.r6.regType == UNINT
        ensures this.r7.regNo == R7 && this.r7.regType == UNINT
        ensures this.r8.regNo == R8 && this.r8.regType == UNINT
        ensures this.r9.regNo == R9 && this.r9.regType == UNINT
        ensures this.r10.regNo == R10 && this.r10.regType == STACKMEM && this.r10.regVal == 0
        // Stack
        ensures this.stack.Length == 512
        ensures this.stackSlotType.Length == 512
        ensures this.idMeta.Length == 64
        ensures fresh(stack)
        ensures fresh(stackSlotType)
        ensures fresh(idMeta)
        // assume the stack value are unknown
        // ensures forall i: int :: 0 <= i < 512 ==> this.stack[i] ==  0 // should be None
        ensures forall i: int :: 0 <= i < 512 ==> this.stackSlotType[i] == SCALAR // UNINT
        ensures forall i: int :: 0 <= i < 64 ==> this.idMeta[i] == -1

        //
        // Context: Context of syscall_prog is the maximum, which is 65536
        ensures this.context.Length == 65536
        // Maps
        //
        // Packet range
        // ensures packet_data_range == 0 && packet_meta_range == 0
        //
        ensures strict_alignment == false 

    /* Comment constraints */
    ghost function common_constraints_single_arg_ins(dst: RegState, src: RegState) :bool
        reads src
        reads dst
        {
            // Src register must be unused (R0)
            // Dst operand must not be R10 and initialized
            src.regNo == R0 && dst.regNo != R10 && dst.regType != UNINT
        }

    ghost predicate allow_ptr_leak_or_scalars(dst: RegState)
        reads this
        reads dst
        {
            (this.allow_ptr_leak == true && dst.regType != UNINT) ||
            (allow_ptr_leak == false && dst.regType == SCALAR)
        }

    /* Per-instruction verification
        - All non-64-bit operations zero out the upper bits
        - https://docs.kernel.org/bpf/standardization/instruction-set.html

        # TODO
        - For unsigned operations (DIV and MOD), for ALU, ‘imm’ is interpreted as a 32-bit unsigned value.
          For ALU64, ‘imm’ is first sign extended from 32 to 64 bits, and then interpreted as a 64-bit unsigned value.
        - For signed operations (SDIV and SMOD), for ALU, ‘imm’ is interpreted as a 32-bit signed value.
          For ALU64, ‘imm’ is first sign extended from 32 to 64 bits, and then interpreted as a 64-bit signed value.
    */

    //////////////////////////////// 32-bit Arithmetic Operations ////////////////////////////////

    ghost method {:axiom} Neg32(dst: RegState, src: RegState)
        requires common_constraints_single_arg_ins(dst, src)
        requires allow_ptr_leak_or_scalars(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == !old(dst.regVal)

    ghost method {:axiom} Bv2be16(dst: RegState, src: RegState)
        requires common_constraints_single_arg_ins(dst, src)
        requires allow_ptr_leak_or_scalars(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == byteswapN(old(dst.regVal), 0, 2)

    ghost method {:axiom} Bv2be32(dst: RegState, src: RegState)
        requires common_constraints_single_arg_ins(dst, src)
        requires allow_ptr_leak_or_scalars(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == byteswapN(old(dst.regVal), 0, 4)

    // Here we assume the arch is X86-64, whichs is big endian
    // And thus, we do nothing here
    ghost method {:axiom} Bv2le16(dst: RegState, src: RegState)
        requires common_constraints_single_arg_ins(dst, src)
        requires allow_ptr_leak_or_scalars(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == old(dst.regVal)

    ghost method {:axiom} Bv2le32(dst: RegState, src: RegState)
        requires common_constraints_single_arg_ins(dst, src)
        requires allow_ptr_leak_or_scalars(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == old(dst.regVal)

    ghost method {:axiom} Bv2swap16(dst: RegState, src: RegState)
        requires common_constraints_single_arg_ins(dst, src)
        requires allow_ptr_leak_or_scalars(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == byteswapN(old(dst.regVal), 0, 2)

    ghost method {:axiom} Bv2swap32(dst: RegState, src: RegState)
        requires common_constraints_single_arg_ins(dst, src)
        requires allow_ptr_leak_or_scalars(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == byteswapN(old(dst.regVal), 0, 4)

    ghost method {:axiom} Mov32_REG(dst: RegState, src: RegState)
        requires dst.regNo != R10
        // requires src.regType != UNINT
        requires allow_ptr_leak_or_scalars(src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == (old(src.regVal) & 0x00000000FFFFFFFF)

    // Note: mov32 from imm will overwrite the upper 32 bits,
    // and thus even if dst is a ptr, the upper 32 bits will not be disclosed.
    ghost method {:axiom} Mov32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == (srcImm & 0x00000000FFFFFFFF)

    // Note: sign extended operations can only be used between registers not immediates.
    // Signed extending 8-bits register to 32-bits register
    ghost method {:axiom} Mov32SX8(dst: RegState, src: RegState)
        requires dst.regNo != R10
        // requires src.regType != UNINT
        requires allow_ptr_leak_or_scalars(src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if ((old(src.regVal) & 0x0000000000000080) != 0)
                                then old(src.regVal) | 0x00000000FFFFFF00
                                else old(src.regVal) & 0x00000000000000FF

    // Signed extending 16-bits register to 32-bits register
    ghost method {:axiom} Mov32SX16(dst: RegState, src: RegState)
        requires dst.regNo != R10
        // requires src.regType != UNINT
        requires allow_ptr_leak_or_scalars(src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if ((old(src.regVal) & 0x0000000000008000) != 0)
                                then old(src.regVal) | 0x00000000FFFF0000
                                else old(src.regVal) & 0x000000000000FFFF

    // Upper 32bits are zeroed out
    ghost method {:axiom} Add32_REG(dst: RegState, src: RegState)
        requires dst.regNo != R10
        // requires dst.regType != UNINT && src.regType != UNINT
        requires src.regType == SCALAR && dst.regType == SCALAR
        // ??? Why even if allow_ptr_leak is enabled, still cannot use Add32 on ptr
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == ((old(dst.regVal) & 0xFFFFFFFF) + (old(src.regVal) & 0xFFFFFFFF)) & 0xFFFFFFFF

    ghost method {:axiom} Add32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        // requires dst.regType != UNINT
        requires dst.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == ((old(dst.regVal) & 0xFFFFFFFF) + (srcImm & 0xFFFFFFFF)) & 0xFFFFFFFF

    // Note: with allow_ptr_leak permission, sub32 can work on ptr-ptr, ptr-imm, imm-ptr, and imm-imm
    // TODO: on other memories: context, map, ...
    ghost method {:axiom} Sub32_REG(dst: RegState, src: RegState)
        requires dst.regNo != R10
        requires (allow_ptr_leak && dst.regType != UNINT && src.regType != UNINT) ||
                 (!allow_ptr_leak && dst.regType == SCALAR && src.regType == SCALAR)
        //
        modifies dst
        ensures dst.regType == SCALAR 
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == ((old(dst.regVal) & 0xFFFFFFFF) - (old(src.regVal) & 0xFFFFFFFF)) & 0xFFFFFFFF

    // TODO: on other memories: context, map, ...
    ghost method {:axiom} Sub32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        // requires dst.regType != UNINT
        requires allow_ptr_leak || (!allow_ptr_leak && dst.regType == SCALAR)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == ((old(dst.regVal) & 0xFFFFFFFF) - (srcImm & 0xFFFFFFFF)) & 0xFFFFFFFF

    ghost method {:axiom} Mul32_REG(dst: RegState, src: RegState)
        requires dst.regNo != R10
        // requires dst.regType != UNINT && src.regType != UNINT
        requires dst.regType == SCALAR && src.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR 
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == ((old(dst.regVal) & 0xFFFFFFFF) * (old(src.regVal) & 0xFFFFFFFF)) & 0xFFFFFFFF

    ghost method {:axiom} Mul32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        // requires dst.regType != UNINT
        requires dst.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == ((old(dst.regVal) & 0xFFFFFFFF) * (srcImm & 0xFFFFFFFF)) & 0xFFFFFFFF

    //  If BPF program execution would result in division by zero, the destination register is instead set to zero.
    ghost method {:axiom} Div32_REG(dst: RegState, src: RegState)
        requires dst.regNo != R10
        // requires dst.regType != UNINT && src.regType != UNINT
        requires dst.regType == SCALAR && src.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if old(src.regVal) & 0xFFFFFFFF == 0
                                then 0x0
                                else ((old(dst.regVal) & 0xFFFFFFFF) / (old(src.regVal) & 0xFFFFFFFF)) & 0xFFFFFFFF

    ghost method {:axiom} Div32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        // requires dst.regType != UNINT
        requires dst.regType == SCALAR
        // Note: If the divisor is immediate and is zero, it violates the safety properties
        requires srcImm != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if srcImm & 0xFFFFFFFF == 0
                                then 0x0
                                else ((old(dst.regVal) & 0xFFFFFFFF) / (srcImm & 0xFFFFFFFF)) & 0xFFFFFFFF

    ghost method {:axiom} SDiv32_REG(dst: RegState, src: RegState)
        requires dst.regNo != R10
        requires dst.regType == SCALAR && src.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if twocom2Abs32Bit(old(src.regVal)) == 0 
                                then 0x0
                                else signDiv32Bit((old(dst.regVal) & 0xFFFFFFFF), (old(src.regVal) & 0xFFFFFFFF))

    ghost method {:axiom} SDiv32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        // requires dst.regType != UNINT
        requires dst.regType == SCALAR
        // Note: If the divisor is immediate and is zero, it violates the safety properties
        requires srcImm != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if twocom2Abs32Bit(srcImm) == 0 
                                then 0x0
                                else signDiv32Bit((old(dst.regVal) & 0xFFFFFFFF), (srcImm & 0xFFFFFFFF))

    // Note: If execution would result in modulo by zero, the upper 32 bits of the destination register are zeroed.
    ghost method {:axiom} Mod32_REG(dst: RegState, src: RegState)
        requires dst.regNo != R10
        // requires dst.regType != UNINT && src.regType != UNINT
        requires dst.regType == SCALAR && src.regType == SCALAR
        // requires src.regVal & 0xFFFFFFFF != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if old(src.regVal) & 0xFFFFFFFF == 0
                                then old(dst.regVal) & 0xFFFFFFFF
                                else ((old(dst.regVal)  & 0xFFFFFFFF) % (old(src.regVal) & 0xFFFFFFFF)) & 0xFFFFFFFF

    ghost method {:axiom} Mod32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        // Note: If the divisor is immediate and is zero, it violates the safety properties
        requires srcImm != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if srcImm & 0xFFFFFFFF == 0
                                then old(dst.regVal) & 0xFFFFFFFF
                                else ((old(dst.regVal)  & 0xFFFFFFFF) % (srcImm & 0xFFFFFFFF)) & 0xFFFFFFFF

    // The signed modulo definition in eBPF ISA: dst % src = dst - src * trunc(dst / src)                                                 
    ghost method {:axiom} SMod32_REG(dst: RegState, src:RegState)
        requires dst.regNo != R10
        // requires dst.regType != UNINT && src.regType != UNINT
        requires dst.regType == SCALAR && src.regType == SCALAR
        // requires src.regVal & 0xFFFFFFFF != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if twocom2Abs32Bit(old(src.regVal)) == 0
                                then old(dst.regVal) & 0xFFFFFFFF
                                else signMod32Bit((old(dst.regVal) & 0xFFFFFFFF), (old(src.regVal) & 0xFFFFFFFF))

    // Note: If the divisor is immediate and is zero, it violates the safety properties
    ghost method {:axiom} SMod32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        // Note: If the divisor is immediate and is zero, it violates the safety properties
        requires srcImm != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if twocom2Abs32Bit(srcImm) == 0
                                then old(dst.regVal) & 0xFFFFFFFF
                                else signMod32Bit((old(dst.regVal) & 0xFFFFFFFF), (srcImm & 0xFFFFFFFF))

    ghost method {:axiom} Bvor32_REG(dst: RegState, src:RegState)
        requires dst.regNo != R10
        // requires dst.regType != UNINT && src.regType != UNINT
        requires dst.regType == SCALAR && src.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == (old(dst.regVal) & 0xFFFFFFFF) | (old(src.regVal) & 0xFFFFFFFF)

    ghost method {:axiom} Bvor32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == (old(dst.regVal) & 0xFFFFFFFF) | (srcImm & 0xFFFFFFFF)

    ghost method {:axiom} Bvand32_REG(dst: RegState, src:RegState)
        requires dst.regNo != R10
        // requires dst.regType != UNINT && src.regType != UNINT
        requires dst.regType == SCALAR && src.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == (old(dst.regVal) & 0xFFFFFFFF) & (old(src.regVal) & 0xFFFFFFFF)

    ghost method {:axiom} Bvand32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == (old(dst.regVal) & 0xFFFFFFFF) & (srcImm & 0xFFFFFFFF)

    ghost method {:axiom} Bvlshr32_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        // requires dst.regType != UNINT && src.regType != UNINT
        requires dst.regType == SCALAR && src.regType == SCALAR
        requires src.regVal < 32
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == (old(dst.regVal) & 0xFFFFFFFF) >> ((old(src.regVal) & 0x1F) as bv5)

    ghost method {:axiom} Bvlshr32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        requires srcImm < 32
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == (old(dst.regVal) & 0xFFFFFFFF) >> ((srcImm & 0x1F) as bv5)

    ghost method {:axiom} Bvashr32_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        // requires dst.regType != UNINT && src.regType != UNINT
        requires dst.regType == SCALAR && src.regType == SCALAR
        requires src.regVal < 32
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == signShift32Bit((old(dst.regVal) & 0xFFFFFFFF), (old(src.regVal) & 0x1F))

    ghost method {:axiom} Bvashr32_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        requires srcImm < 32
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == signShift32Bit((old(dst.regVal) & 0xFFFFFFFF), (srcImm & 0x1F))

    ghost method {:axiom} Bvshl32_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        // requires dst.regType != UNINT && src.regType != UNINT
        requires dst.regType == SCALAR && src.regType == SCALAR
        requires src.regVal < 32
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == ((old(dst.regVal) & 0xFFFFFFFF) << ((old(src.regVal) & 0x1F) as bv5)) & 0xFFFFFFFF

    ghost method {:axiom} Bvshl32_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        requires srcImm < 32
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == ((old(dst.regVal) & 0xFFFFFFFF) << ((srcImm & 0x1F) as bv5)) & 0xFFFFFFFF

    ghost method {:axiom} Bvxor32_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        // requires dst.regType != UNINT && src.regType != UNINT
        requires dst.regType == SCALAR && src.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == (old(dst.regVal) & 0xFFFFFFFF) ^ (old(src.regVal) & 0xFFFFFFFF)

    ghost method {:axiom} Bvxor32_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == (old(dst.regVal) & 0xFFFFFFFF) ^ (srcImm & 0xFFFFFFFF)

    //////////////////////////////// 64-bit Arithmetic Operations ////////////////////////////////

    ghost method {:axiom} Neg64(dst:RegState, src:RegState)
        requires common_constraints_single_arg_ins(dst, src)
        requires allow_ptr_leak_or_scalars(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == !old(dst.regVal)

    ghost method {:axiom} Bv2be64(dst:RegState, src:RegState)
        requires common_constraints_single_arg_ins(dst, src)
        requires allow_ptr_leak_or_scalars(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == byteswapN(old(dst.regVal), 0, 8)

    ghost method {:axiom} Bv2le64(dst:RegState, src:RegState)
        requires common_constraints_single_arg_ins(dst, src)
        requires allow_ptr_leak_or_scalars(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo) 
        ensures dst.regVal == old(dst.regVal)

    ghost method {:axiom} Bv2swap64(dst:RegState, src:RegState)
        requires common_constraints_single_arg_ins(dst, src)
        requires allow_ptr_leak_or_scalars(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == byteswapN(old(dst.regVal), 0, 8)

    ghost method {:axiom} Mov64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires src.regType != UNINT
        //
        modifies dst
        ensures dst.regType == old(src.regType)
        ensures dst.mapFd == old(src.mapFd)
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == old(src.regVal)

    ghost method {:axiom} Mov64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == srcImm

    ghost method {:axiom} Mov64SX8(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires (allow_ptr_leak && src.regType != UNINT) || (!allow_ptr_leak && src.regType == SCALAR)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if ((old(src.regVal) & 0x0000000000000080) != 0)
                                then old(src.regVal) | 0xFFFFFFFFFFFFFF00
                                else old(src.regVal) & 0x00000000000000FF

    ghost method {:axiom} Mov64SX16(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires (allow_ptr_leak && src.regType != UNINT) || (!allow_ptr_leak && src.regType == SCALAR)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if ((old(src.regVal) & 0x0000000000008000) != 0)
                                then old(src.regVal) | 0xFFFFFFFFFFFF0000
                                else old(src.regVal) & 0x000000000000FFFF

    ghost method {:axiom} Mov64SX32(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires (allow_ptr_leak && src.regType != UNINT) || (!allow_ptr_leak && src.regType == SCALAR)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if ((old(src.regVal) & 0x0000000080000000) != 0)
                                then old(src.regVal) | 0xFFFFFFFF00000000
                                else old(src.regVal) & 0x00000000FFFFFFFF

    // TODO: on other memories: context, map, ...
    ghost method {:axiom} Add64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        // SCALAR+SCALAR
        // STACK+SCALAR || SCALAR+STACK if bypass_spec_v1
        // TODO: other memory types
        requires (dst.regType == SCALAR && src.regType == SCALAR) ||
                 (bypass_spec_v1 && ((dst.regType == STACKMEM && src.regType == SCALAR) || (dst.regType == SCALAR && src.regType == STACKMEM)))
        //
        modifies dst
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == if old(dst.regType) != SCALAR then old(dst.regType)
                                else if old(src.regType) != SCALAR then old(src.regType)
                                else SCALAR
        ensures dst.mapFd == if isMapPtr(old(dst.regType)) then old(dst.mapFd)
                                else if isMapPtr(old(src.regType)) then old(src.mapFd)
                                else -1
        ensures dst.regVal == old(dst.regVal) + old(src.regVal)

    // TODO: on other memories: context, map, ...
    ghost method {:axiom} Add64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        // SCALAR+SCALAR || STACK+SCALAR
        // TODO: other memory types ???
        //
        modifies dst
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == old(dst.regType)
        ensures dst.mapFd == old(dst.mapFd)
        ensures dst.regVal == old(dst.regVal) + srcImm

    // TODO: on other memories: context, map, ...
    ghost method {:axiom} Sub64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        // Must exist as below precond uses !=
        requires dst.regType != UNINT && src.regType != UNINT
        // SCALAR-SCALAR; PTR-PTR; PTR(not stack)-SCALAR
        // Note: (1) STACK-scalar is forbidden as JIT cannot handle it while STACK-STACK is allowed
        //       (2) ptr-scalar is allowed in all priv while ptr-ptr is only allowed with allow_ptr_leak
        //       (3) ptr-ptr can be two different ptr types
        requires (dst.regType == SCALAR && src.regType == SCALAR)
                 ||
                 (dst.regType != SCALAR && src.regType == SCALAR)
                 ||
                 // Discussion: can two pointer subtraction really leak pointer?
                 (allow_ptr_leak ==> isPtr(dst.regType) && isPtr(src.regType))
                 // No scalar - pointer, which leads to meaning numbers
        //
        modifies dst
        ensures dst.regNo == old(dst.regNo)
        // The res type is ptr only when ptr-scalar, otherwise (ptr-ptr, scalar-scalar) it's scalar
        ensures dst.regType == if isPtr(old(dst.regType)) && old(src.regType) == SCALAR then old(dst.regType)
                                else SCALAR
        ensures dst.mapFd == if isMapPtr(old(dst.regType)) && old(src.regType) == SCALAR then old(dst.mapFd)
                                else -1
        // Discussion: we cannot subtract between two different pointers, meaningless to subtract their offset
        ensures dst.regVal == old(dst.regVal) - old(src.regVal)

    // TODO: on other memories: context, map, ...
    ghost method {:axiom} Sub64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires dst.regType != UNINT && dst.regType != STACKMEM
        //
        modifies dst
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == if old(dst.regType) != SCALAR then old(dst.regType)
                                else SCALAR
        ensures dst.mapFd == if isMapPtr(old(dst.regType)) then old(dst.mapFd)
                                else -1
        ensures dst.regVal == old(dst.regVal) - srcImm

    ghost method {:axiom} Mul64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires dst.regType == SCALAR && src.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == old(dst.regVal) * old(src.regVal)

    ghost method {:axiom} Mul64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == old(dst.regVal) * srcImm

    // Note: If BPF program execution would result in division by zero, the destination register is instead set to zero.
    ghost method {:axiom} Div64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires dst.regType == SCALAR && src.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if old(src.regVal) == 0 then 0x0
                                else old(dst.regVal) / old(src.regVal)
    
    // Note: In ALU64 unsigned division, IMM is sign extended from 32 to 64 bits and then interpreted as a 64-bit unsigned value.
    ghost method {:axiom} Div64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        // Note: If the divisor is immediate and is zero, it violates the safety properties
        requires srcImm != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if signExtend32To64(srcImm) == 0 then 0x0
                                else old(dst.regVal) / signExtend32To64(srcImm)

    ghost method {:axiom} SDiv64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires dst.regType == SCALAR && src.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if twocom2Abs64Bit(old(src.regVal)) == 0 then 0x0
                                else signDiv64Bit(old(dst.regVal), old(src.regVal))

    // Note: In ALU64 signed division, IMM is sign extended from 32 to 64 bits and then interpreted as a 64-bit signed value.
    //       If the divisor is immediate and is zero, it violates the safety properties
    ghost method {:axiom} SDiv64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        // Note: If the divisor is immediate and is zero, it violates the safety properties
        requires srcImm != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if signExtend32To64(srcImm) == 0 then 0x0
                                else signDiv64Bit(old(dst.regVal), signExtend32To64(srcImm))

    // Note: If execution would result in modulo by zero in ALU64, the value of the destination register is unchanged.
    // TODO: prove
    // a % n = a - n * trunc(a / n)
    ghost method {:axiom} Mod64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires dst.regType == SCALAR && src.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if old(src.regVal) == 0x0 then old(dst.regVal)
                                else old(dst.regVal) % old(src.regVal)
    
    // Note: In ALU64 unsigned modulo, IMM is sign extended from 32 to 64 bits and then interpreted as a 64-bit unsigned value.
    //       If the divisor is immediate and is zero, it violates the safety properties
    ghost method {:axiom} Mod64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        // Note: If the divisor is immediate and is zero, it violates the safety properties
        requires srcImm != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if signExtend32To64(srcImm) == 0x0 then old(dst.regVal)
                                else old(dst.regVal) % signExtend32To64(srcImm)

    // Signed modulo MUST use truncated division： a % n = a - n * trunc(a / n)
    ghost method {:axiom} SMod64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires dst.regType == SCALAR && src.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if twocom2Abs64Bit(old(src.regVal)) == 0 then old(dst.regVal)
                                else signMod64Bit(old(dst.regVal), old(src.regVal))
    
    // Note: In ALU64 signed modulo, IMM is sign extended from 32 to 64 bits and then interpreted as a 64-bit signed value.
    //       If the divisor is immediate and is zero, it violates the safety properties
    ghost method {:axiom} SMod64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        // Note: If the divisor is immediate and is zero, it violates the safety properties
        requires srcImm != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == if signExtend32To64(srcImm) == 0 then old(dst.regVal)
                                else signMod64Bit(old(dst.regVal), signExtend32To64(srcImm))

    ghost method {:axiom} Bvor64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires dst.regType == SCALAR && src.regType ==  SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == old(dst.regVal) | old(src.regVal)

    ghost method {:axiom} Bvor64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires dst.regType ==  SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == old(dst.regVal) | srcImm

    ghost method {:axiom} Bvand64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires dst.regType == SCALAR && src.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == old(dst.regVal) & old(src.regVal)

    ghost method {:axiom} Bvand64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == old(dst.regVal) & srcImm

    ghost method {:axiom} Bvlshr64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires dst.regType == SCALAR && src.regType == SCALAR
        requires src.regVal < 64
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == old(dst.regVal) >> ((old(src.regVal) & 0x3F) as bv6)

    ghost method {:axiom} Bvlshr64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        requires srcImm < 64
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == old(dst.regVal) >> ((srcImm & 0x3F) as bv6)

    ghost method {:axiom} Bvashr64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires dst.regType == SCALAR && src.regType == SCALAR
        requires src.regVal < 64
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == signShift64Bit(old(dst.regVal), old(src.regVal))

    ghost method {:axiom} Bvashr64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        requires srcImm < 64
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == signShift64Bit(old(dst.regVal), srcImm)

    ghost method {:axiom} Bvshl64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires dst.regType == SCALAR && src.regType == SCALAR
        requires src.regVal < 64
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == old(dst.regVal) << ((old(src.regVal) & 0x3F) as bv6)
    
    ghost method {:axiom} Bvshl64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        requires srcImm < 64
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == old(dst.regVal) << ((srcImm & 0x3F) as bv6)

    ghost method {:axiom} Bvxor64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires dst.regType == SCALAR && src.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == old(dst.regVal) ^ old(src.regVal)

    ghost method {:axiom} Bvxor64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires dst.regType == SCALAR
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regVal == old(dst.regVal) ^ srcImm

    //////////////////////////// Stack memory ///////////////////////////

    ghost predicate stack_writable(memReg: RegState, off: int64, size: int64)
        reads memReg, this, this.stackSlotType
        {
            memReg.regType == STACKMEM                                      
            &&
            (this.stack.Length == 512 && this.stackSlotType.Length == 512 && idMeta.Length == 64)  
            &&
            // Allow access with byte, half word, workd, and double word
            (size == 1 || size == 2 || size == 4 || size == 8)              
            &&
            // Access offset must aglins to size
            (((bv64ToInt64(memReg.regVal) + off) % size) == 0)              
            &&
            // Access between [-512, -1] inclusive
            (var curOff := (bv64ToInt64(memReg.regVal) + off); -512 <= curOff < (curOff +size) <= 0)   
            &&
            // Cannot partially overwrite a ptr at the offset
            (
                size != 8 ==> var curOff := (bv64ToInt64(memReg.regVal) + off)+512;
                        (
                            allow_ptr_leak ||
                            (!allow_ptr_leak && (stackSlotType[curOff] == SCALAR || stackSlotType[curOff] == UNINT))
                        )
            )
        }

    // Note: the stack memory in eBPF VM is little endian
    // *(size *) (dst + offset) = src
    // MEM_STX_B, MEM_STX_H, MEM_STX_W, MEM_STX_DW, MEM_ST_B, MEM_ST_H, MEM_ST_W, MEM_ST_DW
    // 
    ghost method {:axiom} Store_STACKMEM(dst:RegState, src:RegState, off:int64, size:int64)
        requires src.regType != UNINT
        requires stack_writable(dst, off, size)
        // Original: Check_stack_write_fixed_off:4546 : Cannot partially store a ptr from src reg, 
        // Change: allow partially store a pointer to stack as SCALAR
        requires !allow_ptr_leak && size != 8 ==> src.regType == SCALAR
        requires size != 8 ==> src.regType == SCALAR
        //
        modifies this.stack, this.stackSlotType, this.idMeta
        //
        // Update the affected stack values while keeping the unchanged ones
        ensures var start := (bv64ToInt64(dst.regVal) + off + 512);
                forall i, j | start <= i < (start + size)
                              &&
                              ((0 <= j < 512) && !(0 <= start <= j < start + size <= 512)) ::
                    // TODO: if it's a pointer, the real stored value should be its pointer addres, which is unknown
                    // It should not be regVal, which is just the offset.
                    (stack[i] == getRegByteX(src.regVal, i- start))
                    &&
                    (stack[j] == old(stack[j]))
        //
        // Update the affected stack types while keeping the unchanged ones
        ensures var start := (bv64ToInt64(dst.regVal) + off + 512);
                // If partially overwrite a ptr slot, the tyeps of unwritten bytes within the 8-byte slot should be changed as well
                var new_size := if isPtr(stackSlotType[start]) then 8 else size;
                ((isMapPtr(src.regType) && size == 8) ==> idMeta[start/8] == src.mapFd)
                &&
                (
                    forall i, j | (
                        // isMapPtr(src.regType) && size == 8 ==> idMeta[] = src.mapFd
                        (0 <= start <= i < (start + new_size) < 512)
                        &&
                        ((0 <= j < 512) && !(start <= j < start + new_size))
                    )
                    ::
                    (
                        (stackSlotType[i] == if size == 8 then old(src.regType) else SCALAR)
                        &&
                        (stackSlotType[j] == old(stackSlotType[j]))
                    )
                )
                
    ghost predicate stack_readable(memReg: RegState, off: int64, size: int64)
        reads memReg, this, this.stackSlotType
        {
            memReg.regType == STACKMEM                                         
            &&
            (this.stack.Length == 512 && this.stackSlotType.Length == 512 && idMeta.Length == 64)
            &&
            // Allow access with byte, half word, workd, and double word
            (size == 1 || size == 2 || size == 4 || size == 8)                  
            &&
            // Access offset must aglins to size
            (((bv64ToInt64(memReg.regVal) + off) % size) == 0)                  
            &&
            // Access between [-512, -1] inclusive
            (var curOff := (bv64ToInt64(memReg.regVal) + off); -512 <= curOff < (curOff +size) <= 0)    
            &&
            // All slots are initialized
            (var curOff := bv64ToInt64(memReg.regVal) + off + 512;
                    forall i | curOff <= i < (curOff + size) :: this.stackSlotType[i] != UNINT)      
            &&
            // Partially loading a pointer
            (var curOff := bv64ToInt64(memReg.regVal) + off + 512;
                    size != 8 ==> forall i | curOff <= i < curOff+size :: this.stackSlotType[i] == SCALAR)
        }

    // dst = *(unsigned size *) (src + offset)
    // MEM_LDX_B, MEM_LDX_H, MEM_LDX_W, MEM_LDX_DW, MEMSX_LDX_S8, MEMSX_LDX_S16, MEMSX_LDX_S32
    //
    ghost method {:axiom} Load_STACKMEM(dst:RegState, src:RegState, off:int64, size:int64, signExt:bool)
        requires dst.regNo != R10
        requires stack_readable(src, off, size)
        //
        modifies dst
        //
        ensures var curOff := bv64ToInt64(old(src.regVal))+off+512;
                (dst.regType == if size == 8 then stackSlotType[curOff] else SCALAR)
                &&
                (isMapPtr(stackSlotType[curOff]) ==> dst.mapFd == idMeta[curOff/8])
        ensures dst.regNo == old(dst.regNo)
        // Note: Non-64-bit unsigned loads zero out the upper bits, while non-64-bit signed loads extend the sign bit to 64-bit width,
        //       for example, assume the byte at (r10 -8) is 0xff, then:
        //       r2 = *(s8 *)(r10 -8) ==> r2 == -1; 
        //       r2 = *(u8 *)(r10 -8) ==> r2 == 255
        ensures var curOff := bv64ToInt64(old(src.regVal)) + off + 512;
                dst.regVal == if signExt
                            then signExtend64(loadNbytesStack(this.stack, this.stack.Length, curOff, 0, size), size*8)
                            else loadNbytesStack(this.stack, this.stack.Length, curOff, 0, size)

    ghost method {:axiom} AtomicLS_STACKMEM(dst:RegState, src:RegState, off:int64, size:int64, isFetch: bool)
        requires false

    //////////////////////////// Context memory ///////////////////////////
    
    // *(size *) (dst + offset) = src
    ghost method {:axiom} Store_CTXMEM(dst:RegState, src:RegState, off:int64, size:int64)
        requires dst.regType == CTXMEM
        requires src.regType != UNINT
        // Discussion: Allow store pointers to context as a Scalar when having capabilities
        requires !allow_ptr_leak ==> src.regType == SCALAR
        //
        requires this.context.Length == 65536
        requires var curOff := (bv64ToInt64(dst.regVal) + off);
                 0 <= curOff < (curOff +size) <= 65536
        requires context_access_safe(this.progType, (bv64ToInt64(dst.regVal) + off), size, WRITE, this.attachType, this.priv)
        //
        modifies this.context
        //
        // Keep the unchanged bytes
        ensures var curOff := bv64ToInt64(dst.regVal) + off + 512;
                forall i | 0 <= i < context.Length :: !(curOff <= i < curOff + size) ==> context[i] == old(context[i])
        // Update the affected bytes
        ensures var curOff := bv64ToInt64(dst.regVal) + off + 512;
                forall i | 0 <= i < context.Length ::   curOff <= i < curOff + size  ==> context[i] == getRegByteX(src.regVal, i- curOff)        
        //
        // Note need to update slot types: the slot types are fixed, which means store does not change them, and thus no need to update them 
    
    ghost method {:axiom} Load_CTXMEM(dst:RegState, src:RegState, off:int64, size:int64, signExt:bool)
        requires dst.regNo != R10
        requires src.regType == CTXMEM
        requires this.context.Length == 65536
        requires var curOff := (bv64ToInt64(src.regVal) + off);
                 0 <= curOff < (curOff +size) <= 65536
        requires context_access_safe(this.progType, (bv64ToInt64(src.regVal) + off), size, READ, this.attachType, this.priv)
        //
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        // ensures dst.regType == context_load_type(this.progType, (bv64ToInt64(old(src.regVal)) + off), size, READ, this.attachType, this.priv)
        ensures context_load_type(dst.regType, this.progType, (bv64ToInt64(old(src.regVal)) + off), size, READ, this.attachType, this.priv)
        ensures dst.regVal == loadNbytesStack(this.context, this.context.Length, (bv64ToInt64(old(src.regVal)) + off), 0, size)

    ghost method {:axiom} AtomicLS_CTXMEM(dst:RegState, src:RegState, off:int64, size:int64, isFetch: bool)
        requires false


    //////////////////////////// PTR_TO_MAP ///////////////////////////
    
    ghost method {:axiom} CreateMap(mapFd:int64, mapType:MapTypes, keySize:int64, valSize:int64,
                                    maxEntries:int64, mapFlag:int64, innerMapFd:int64)
        requires 0 <= mapFd < this.maps.Length
        requires 0 <= innerMapFd <= this.maps.Length
        // Note: Checking the map creation is out of the scope, we only focus on eBPF instruction verification
        //
        modifies this.maps[mapFd]
        //
        ensures this.maps[mapFd].mapType == mapType
        ensures this.maps[mapFd].keySize == keySize
        ensures this.maps[mapFd].valSize == valSize
        ensures this.maps[mapFd].maxEntries == maxEntries
        ensures this.maps[mapFd].mapFlag == mapFlag
        ensures this.maps[mapFd].innerMapFd == innerMapFd


    ghost method {:axiom} Load_MAPFD(dst:RegState, src:RegState, mapFd:int64) 
        requires dst.regNo != R10
        // Note: src == BPF_PSEUDO_MAP_FD, but we do not check instruction format
        // Note: mapFd should be checked, but it's kernel runtime info,
        //       we cannot check it and thus assume it is correct.
        //
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == MAP_PTR
        // dst.regVal is not used
        ensures dst.mapFd == mapFd

    // TODO: BTF related
    ghost predicate requires_on_map_ptr_load(memReg: RegState, off: int64, size: int64)
        {
            false
        }
    
    ghost method {:axiom} Load_MAPMEM(dst:RegState, src:RegState, off:int64, size:int64, signExt:bool)
        // check_ptr_to_map_access
        // requires allow_ptr_leak
        // TODO: needs to know the BTF
        requires false

    // Map_ptr is read-only
    ghost method {:axiom} Store_MAPMEM(dst:RegState, src:RegState, off:int64, size:int64)
        requires false

    ghost method {:axiom} AtomicLS_MAPMEM(dst:RegState, src:RegState, off:int64, size:int64, isFetch: bool)
        requires false

    //////////////////////////// PTR_TO_MAP_VALUE ///////////////////////////

    ghost predicate map_value_readable(memReg: RegState, off: int64, size: int64)
        reads memReg
        reads this
        reads this.maps
        requires 0 <= memReg.mapFd < this.maps.Length
        reads this.maps[memReg.mapFd]
        {
            (memReg.regType == PTR_TO_MAP_VALUE)
            &&
            (size == 1 || size == 2 || size == 4 || size == 8)
            &&
            // aligned
            (strict_alignment ==> ((bv64ToInt64(memReg.regVal) + off) % size) == 0)
            &&
            // readable
            (this.maps[memReg.mapFd].readable)
            &&
            // In-bound access
            (var start := (bv64ToInt64(memReg.regVal) + off);
                    0 <= start < start + size < this.maps[memReg.mapFd].valSize)
            /*
                check_map_access: 
                    check_mem_region_access -> __check_mem_access: access within bounds, 
                TODO: checks on map->record, looks related to kptr: https://lore.kernel.org/bpf/20220424214901.2743946-1-memxor@gmail.com/
            */
        }

    ghost method {:axiom} Load_MAPVALUE(dst:RegState, src:RegState, off:int64, size:int64, signExt:bool)
        requires 0 <= src.mapFd < this.maps.Length
        requires map_value_readable(src, off, size)
        modifies dst
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == SCALAR
        // TODO: if map is read-only, then directly read the memory data and assign it to the dst else just scalar
        // ensures dst.regVal == ???

    ghost predicate map_value_writable(memReg: RegState, off: int64, size: int64)
        reads memReg
        reads this
        reads this.maps
        requires 0 <= memReg.mapFd < this.maps.Length
        reads  this.maps[memReg.mapFd]
        {
            (memReg.regType == PTR_TO_MAP_VALUE)
            &&
            (size == 1 || size == 2 || size == 4 || size == 8)
            &&
            // aligned
            (strict_alignment ==> ((bv64ToInt64(memReg.regVal) + off) % size) == 0)
            &&
            this.maps[memReg.mapFd].writable
            &&
            // In-bound access, TODO as Load_MAPVALUE
            (var start := (bv64ToInt64(memReg.regVal) + off);
                    0 <= start < start + size < this.maps[memReg.mapFd].valSize)
        }

    ghost method {:axiom} Store_MAPVALUE(dst:RegState, src:RegState, off:int64, size:int64)
        requires 0 <= dst.mapFd < this.maps.Length
        requires map_value_writable(dst, off, size)
        // Cannot store a pointer to map if without allow_ptr_leak
        requires !allow_ptr_leak ==> src.regType == SCALAR
        // Note: since the data store to map will be changed by other programs,
        //       we do not maintain the its symbol values.

    ghost method {:axiom} AtomicLS_MAPVALUE(dst:RegState, src:RegState, off:int64, size:int64, isFetch: bool)
        requires dst.regType == PTR_TO_MAP_VALUE
        requires !allow_ptr_leak ==> src.regType == SCALAR
        requires size == 4 || size == 8
        // Atomic accesses must be aligned: ARM64 needs atomic insn to be aligned
        // https://github.com/torvalds/linux/commit/ca36960211eb2#diff-edbb57adf10d1ce1fbb830a34fa92712fd01db1fbd9b6f2504001eb7bcc7b9d0R1365
        requires ((bv64ToInt64(dst.regVal) + off) % size) == 0
        // TODO: should we allow add, or, xor, and on pointers ??
        // In-bound access, TODO as Load_MAPVALUE
        requires 0 <= dst.mapFd < this.maps.Length
        requires (var start := (bv64ToInt64(dst.regVal) + off);
                    0 <= start < start + size < this.maps[dst.mapFd].valSize)
        // TODO: should we allow atomic add, or, xor, and on pointers ??
        //
        modifies src
        //
        ensures src.regNo == old(src.regNo)
        ensures !isFetch ==> src.regType == old(src.regType) && src.regVal == old(src.regVal)
        ensures isFetch  ==> src.regType == SCALAR
    
    ghost method {:axiom} AtomicCMPEXCHG_MAPVALUE(dst:RegState, src:RegState, off:int64, size:int64)
        requires dst.regType == PTR_TO_MAP_VALUE
        requires !allow_ptr_leak ==> (src.regType == SCALAR && this.r0.regType == SCALAR)
        requires size == 4 || size == 8
        requires ((bv64ToInt64(dst.regVal) + off) % size) == 0
        // In-bound access, TODO as Load_MAPVALUE
        requires 0 <= dst.mapFd < this.maps.Length
        requires (var start := (bv64ToInt64(dst.regVal) + off);
                    0 <= start < start + size < this.maps[dst.mapFd].valSize)
        //
        modifies this.r0
        //
        ensures this.r0.regNo == old(this.r0.regNo)
        ensures this.r0.regType == SCALAR

    //////////////////////////// PTR_TO_MAP_VALUE ///////////////////////////

    ghost method {:axiom} Load_MAPKEY(dst:RegState, src:RegState, off:int64, size:int64, signExt:bool)
        requires src.regType == PTR_TO_MAP_KEY
        requires dst.regNo != R10
        requires size == 1 || size == 2 || size == 4 || size == 8
        requires strict_alignment ==> (bv64ToInt64(dst.regVal) + off) % size == 0
        //
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == SCALAR
        // dst.regVal is unknown

    ghost method {:axiom} Store_MAPKEY(dst:RegState, src:RegState, off:int64, size:int64)
        requires false

    ghost method {:axiom} AtomicLS_MAPKEY(dst:RegState, src:RegState, off:int64, size:int64, isFetch: bool)
        requires false

    //////////////////////////// Packet memory ///////////////////////////
    
    ghost predicate packetReadable()
        reads this
        {
            match this.progType {
                case BPF_PROG_TYPE_LWT_IN           => true
                case BPF_PROG_TYPE_LWT_OUT          => true
                case BPF_PROG_TYPE_LWT_SEG6LOCAL    => true
                case BPF_PROG_TYPE_SK_REUSEPORT     => true
                case BPF_PROG_TYPE_FLOW_DISSECTOR   => true
                case BPF_PROG_TYPE_CGROUP_SKB       => true
                case BPF_PROG_TYPE_SCHED_CLS        => true
                case BPF_PROG_TYPE_SCHED_ACT        => true
                case BPF_PROG_TYPE_XDP              => true
                case BPF_PROG_TYPE_LWT_XMIT         => true
                case BPF_PROG_TYPE_SK_SKB           => true
                case BPF_PROG_TYPE_SK_MSG           => true
                case BPF_PROG_TYPE_CGROUP_SOCKOPT   => true
                case _ => false
            }
        }

    ghost predicate packetWritable()
        reads this
        {
            match this.progType {
                case BPF_PROG_TYPE_SCHED_CLS        => true
                case BPF_PROG_TYPE_SCHED_ACT        => true
                case BPF_PROG_TYPE_XDP              => true
                case BPF_PROG_TYPE_LWT_XMIT         => true
                case BPF_PROG_TYPE_SK_SKB           => true
                case BPF_PROG_TYPE_SK_MSG           => true
                case BPF_PROG_TYPE_CGROUP_SOCKOPT   => true
                case _ => false
            }
        }

    /*
        TODO: why "if (meta) return meta->pkt_access;" ==> when helper access packet memory, only some can access even the program types can load/store that packet
     */

    // Note: check_mem_access()
    // Load PACKET_META, PACKET, PACKET_END
    // Note: PACKET_END is the end of a packet, so no memory access with this pointer
    ghost method {:axiom} Load_PACKET(dst:RegState, src:RegState, off:int64, size:int64, signExt:bool)
        requires dst.regNo != R10
        requires src.regType == PTR_TO_PACKET_META || src.regType == PTR_TO_PACKET
        requires size == 1 || size == 2 || size == 4 || size == 8
        // Alignment check, check the link to see why add 2: https://lwn.net/Articles/89002/
        requires strict_alignment ==> (bv64ToInt64(src.regVal) + off + 2) % size == 0
        // Check program type to know the readability and writability of the packet
        requires packetReadable()
        // Access within bounds predicted from jump on packet_* and ptr comparison
        requires var upper_bound := if src.regType == PTR_TO_PACKET_META then packet_meta_range else packet_data_range;
                 var start := bv64ToInt64(src.regVal) + off;
                 0 <= start < start + size < upper_bound < 0xffff
        //
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == SCALAR
        // dst.regVal is unknow, so no assignment here
    

    // Store PACKET_META, PACKET, PACKET_END
    ghost method {:axiom} Store_PACKET(dst:RegState, src:RegState, off:int64, size:int64)
        requires dst.regNo != R10
        requires dst.regType == PTR_TO_PACKET_META || dst.regType == PTR_TO_PACKET
        requires size == 1 || size == 2 || size == 4 || size == 8
        requires strict_alignment ==> (bv64ToInt64(dst.regVal) + off + 2) % size == 0
        // Discussion: is it really necessary to allow write pointers to packet as a scalar???
        requires !allow_ptr_leak ==> src.regType == SCALAR
        requires packetWritable()
        // Access within bounds predicted from jump on packet_* and ptr comparison
        requires var upper_bound := if dst.regType == PTR_TO_PACKET_META then packet_meta_range else packet_data_range;
                 var start := bv64ToInt64(dst.regVal) + off;
                 0 <= start < start + size < upper_bound < 0xffff
        //
        // Not track the values and types in packet
        // Discussion: is it necessary to track it? -> every slots in packet memory is scalar, so not necessary to track it, but what about the values?

    ghost method {:axiom} AtomicLS_PACKET(dst:RegState, src:RegState, off:int64, size:int64, isFetch: bool)
        requires false


    //////////////////////////// Flow_keys memory ///////////////////////////

    ghost method {:axiom} Load_FLOWKEYS(dst:RegState, src:RegState, off:int64, size:int64, signExt:bool)
        requires src.regType == PTR_TO_FLOW_KEYS
        requires dst.regNo != R10
        requires size == 1 || size == 2 || size == 3 || size == 4
        requires strict_alignment ==> (bv64ToInt64(src.regVal) + off) % size == 0
        requires var start := bv64ToInt64(src.regVal) + off; 0 <= start < start + size < 56 // 56 == sizeof(struct bpf_flow_keys)
        //
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == SCALAR
        // dst.regVal is unknown

    ghost method {:axiom} Store_FLOWKEYS(dst:RegState, src:RegState, off:int64, size:int64)
        requires dst.regType == PTR_TO_FLOW_KEYS
        requires size == 1 || size == 2 || size == 3 || size == 4
        requires strict_alignment ==> (bv64ToInt64(dst.regVal) + off) % size == 0
        requires var start := bv64ToInt64(dst.regVal) + off; 0 <= start < start + size < 56 // 56 == sizeof(struct bpf_flow_keys)
        requires !allow_ptr_leak ==> src.regType == SCALAR
        //
        // Discussion: necessary to maintain the value of flowkeys?

    ghost method {:axiom} AtomicLS_FLOWKEYS(dst:RegState, src:RegState, off:int64, size:int64, isFetch: bool)
        requires false

    //////////////////////////// Socket memory ///////////////////////////

    // Note: PTR_TO_SOCK_COMMON, PTR_TO_SOCKET, PTR_TO_TCP_SOCK, and PTR_TO_XDP_SOCK are read-only.
    ghost method {:axiom} Load_SOCK(dst:RegState, src:RegState, off:int64, size:int64, sock_type: REGTYPE)
        requires src.regType == PTR_TO_SOCK_COMMON
        requires dst.regNo != R10
        requires size == 1 || size == 2 || size == 4 || size == 8
        // aligned
        requires (bv64ToInt64(src.regVal) + off) % size == 0
        // Check field readability of different sock types
        // Add the below condition to remove the erors when passing it to validate_*_access()
        requires -0x8000_0000_0000_0000 < (bv64ToInt64(src.regVal) + off) < 0x8000_0000_0000_0000
        requires sock_type == PTR_TO_SOCK_COMMON ==> validate_sock_common_access((bv64ToInt64(src.regVal) + off), size)
        requires sock_type == PTR_TO_SOCKET ==> validate_sock_access((bv64ToInt64(src.regVal) + off), size)
        requires sock_type == PTR_TO_TCP_SOCK ==> validate_tcp_sock_access((bv64ToInt64(src.regVal) + off), size)
        requires sock_type == PTR_TO_XDP_SOCK ==> validate_xdp_sock_access((bv64ToInt64(src.regVal) + off), size)
        //
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == SCALAR
        // dst.regVal is unknown

    ghost method {:axiom} Store_SOCK(dst:RegState, src:RegState, off:int64, size:int64)
        requires false

    ghost method {:axiom} AtomicLS_SOCK(dst:RegState, src:RegState, off:int64, size:int64, isFetch: bool)
        requires false

    //////////////////////////// Tracepoint buffer memory ///////////////////////////

    // PTR_TO_TP_BUFFER: reg points to a writable raw tp's buffer
    ghost method {:axiom} Load_TPBUFFER(dst:RegState, src:RegState, off:int64, size:int64, signExt:bool)
        requires src.regType == PTR_TO_TP_BUFFER
        requires dst.regNo != R10
        requires size == 1 || size == 2 || size == 4 || size == 8
        // There is no access bound during the verification stage as the TP-BUFFER size is decided according to the attachment point,
        // Thus, verifier records the max access range and the attaching procedure will check if max access is out of the real size.
        // Discussion: Accesses to memory PTR_TO_TP_BUFFER needs to be constant offsets instead of variable offsets       
        requires strict_alignment ==> (bv64ToInt64(dst.regVal) + off) % size == 0
        //
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == SCALAR
        // dst.regVal is unkown

    ghost method {:axiom} Store_TPBUFFER(dst:RegState, src:RegState, off:int64, size:int64)
        requires dst.regType == PTR_TO_TP_BUFFER
        requires size == 1 || size == 2 || size == 4 || size == 8
        // No range check: see Load_TPBUFFER
        requires strict_alignment ==> (bv64ToInt64(dst.regVal) + off) % size == 0
        // TODO: No checks on the src type because the checks on program type has ensure the priv

    ghost method {:axiom} AtomicLS_TPBUFFER(dst:RegState, src:RegState, off:int64, size:int64, isFetch: bool)
        requires false

    //////////////////////////////////// PTR_TO_ARENA ////////////////////////////////

    // Note: the memory safety of arena is ensured by the runtime SFI
    //
    ghost method {:axiom} Load_ARENA(dst:RegState, src:RegState, off:int64, size:int64, signExt:bool)
        requires src.regType == PTR_TO_ARENA
        requires dst.regNo != R10
        requires size == 1 || size == 2 || size == 4 || size == 8
        // No alignment required

    ghost method {:axiom} Store_ARENA(dst:RegState, src:RegState, off:int64, size:int64)
        requires dst.regType == PTR_TO_ARENA
        requires size == 1 || size == 2 || size == 4 || size == 8
        // No alignment required


    ghost method {:axiom} AtomicLS_ARENA(dst:RegState, src:RegState, off:int64, size:int64, isFetch: bool)
        requires dst.regType == PTR_TO_ARENA
        requires !allow_ptr_leak ==> src.regType == SCALAR
        requires size == 4 || size == 8
        requires (bv64ToInt64(dst.regVal) + off) % size == 0
        // No alignment required
        // TODO: should we allow atomic add, or, xor, and on pointers ??
        //
        modifies if isFetch then {src} else {}
        //
        ensures src.regNo == old(src.regNo)
        ensures !isFetch ==> src.regType == old(src.regType) && src.regVal == old(src.regVal)
        ensures isFetch ==> src.regType == SCALAR

    ghost method {:axiom} AtomicCMPEXCHG_ARENA(dst:RegState, src:RegState, off:int64, size:int64)
        requires dst.regType == PTR_TO_ARENA
        requires !allow_ptr_leak ==> (src.regType == SCALAR && this.r0.regType == SCALAR)
        requires size == 4 || size == 8
        requires ((bv64ToInt64(dst.regVal) + off) % size) == 0
        //
        modifies this.r0
        //
        ensures this.r0.regNo == old(this.r0.regNo)
        ensures this.r0.regType == SCALAR

    // cast_user and cast_kern: (BPF_ALU64 | BPF_MOV | BPF_X) && insn->off == BPF_ADDR_SPACE_CAST;
    // insn->imm == (1 << 16)
    ghost method {:axiom} cast_user(dst:RegState, src:RegState)
        requires dst == src
        // TODO: any requirements on src and dst regType
        //
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == SCALAR
        // ensures dst.regVal == unknown, TODO: how is calculated in runtime?

    // insn->imm == 1
    // Note: is not interpreted in JIT
    ghost method {:axiom} cast_kern(dst:RegState, src:RegState)
        requires dst == src
        // TODO: any requirements on src and dst regType
        //
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == PTR_TO_ARENA
        // ensures dst.regVal == unknown, TODO: how is calculated in runtime?

    /*
        PTR TODO:
            - PTR_TO_FUNC
            - PTR_TO_MEM
            - PTR_TO_BUF
            - CONST_PTR_TO_DYNPTR
            - PTR_TO_BTF_ID
     */

    //////////////////////////// Helper calls ///////////////////////////

    // TODO-2: why cannot use ctx ptr as key
    // requires r2.regType == // R2 type=ctx expected=fp, pkt, pkt_meta, map_key, map_value, mem, ringbuf_mem, buf, trusted_ptr_
    // requires r2 can only be ptr when allow_ptr_leak is enabled
    // What I thought: readable memory + allow_ptr_leak if the slot stores an ptr
    
    // Why not verify the map access in the verification? Like for x/0 is rejected.
    // map has flags --> map->map_flags & BPF_F_RDONLY_PROG

    /*
        General checks on helper calls:
            - If the program type can call this helper function
            - Argument type checking
            - If it's a memory pointer, check the readability and writability ==> 
            - Check capabilities: some helper calls needs CAPs, like spin lock (see bpf_base_func_proto)

        TODO:
            - Check if "helper call is not allowed in probe" (check_helper_call)
            - check if "helper call might sleep in a non-sleepable prog" (check_helper_call)
            - check if "kernel subsystem misconfigured func %s#%d: r1 != ctx\n"

        TODO helpers:
            - locks  -> BTF??
            - loop
            - socket
     */

    /*
        Assumptions:
            - Function IDs are all valid. verifier:10182
            - GPL is compatible
            - 
    

        - check prog type and helper call mapping => env->ops->get_func_proto(func_id, env->prog); fn->allowed && !fn->allowed(env->prog)
        - sleepable (running -> sleep)
        - /* With LD_ABS/IND some JITs save/restore skb from r1. */ ??
        - check_func_proto
            - check_raw_mode_ok: only one arg is uninit memory
            - check_arg_pair_ok: the args "buf" and "len" must be paired and conistnuous args in the arg list
            - check_btf_id_ok: ??
        - env->cur_state->active_rcu_lock:
            - no sleepable helper function in rcu_read_lock region
            - if not in lock, and need to sleep, mark it as lock
        - check_func_arg
            - reg is initialized
            - if anything arg, and reg is ptr, allowr_ptr_leak is required
            - if arg is pkt pointer, check if this helper call have the access to the pkt
            - if arg is PTR_TO_MAP_VALUE, resolve_map_arg_type to adjust the arg type to its finer-grained type, like ARG_PTR_TO_BTF_ID_SOCK_COMMON or ARG_PTR_TO_MAP_VALUE
            - if arg can be NULL, and the reg is const zero, skip any checks and allow it
            - check_reg_type: check the match between reg type and required arg type, specified in compatible_reg_types
            - check_func_arg_reg_off:  
                - ensure the offset of pointer passed to the release helper calls is zero
                - check the const offset and variable offset according their allowance to the const and variable offset
            - lots of ad-hoc checks
        - ad-hoc checks on special helper calls
        
        - reset caller saved regs (BPF_REG_0, BPF_REG_1, BPF_REG_2, BPF_REG_3, BPF_REG_4, BPF_REG_5)
            - mark reg unint
        - Update return value
     */

    ghost predicate isReadableMem(reg: RegState, size: int64)
        reads reg
        reads this
        reads this.stackSlotType
        reads this.maps
        requires reg.regType == PTR_TO_MAP_VALUE ==> 0 <= reg.mapFd < this.maps.Length
        reads if reg.regType == PTR_TO_MAP_VALUE then {this.maps[reg.mapFd]} else {}
        {        
            match reg.regType {
                case UNINT | NULL | SCALAR => false
                case STACKMEM           => stack_readable(reg, 0, size)
                case CTXMEM             => context_access_safe(this.progType, bv64ToInt64(reg.regVal), size, READ, this.attachType, this.priv)
                case MAP_PTR            => requires_on_map_ptr_load(reg, 0, size) // TODO
                case PTR_TO_MAP_VALUE   => map_value_readable(reg, 0, size)
                case _                  => false
                /*
                    TODO:
                    | PTR_TO_SOCKET
                    | PTR_TO_SOCK_COMMON // TODO: what is the difference between PTR_TO_SOCKET and PTR_TO_SOCK_COMMON
                    | PTR_TO_PACKET
                    | PTR_TO_PACKET_END
                    | PTR_TO_PACKET_META
                    | PTR_TO_FLOW_KEYS
                    | PTR_TO_TP_BUFFER
                */
            }
        }

    ghost predicate isWritableMem(reg: RegState, size: int64)
        reads reg
        reads this
        reads this.maps
        reads this.stackSlotType
        requires reg.regType == PTR_TO_MAP_VALUE ==> 0 <= reg.mapFd < this.maps.Length
        reads if reg.regType == PTR_TO_MAP_VALUE then {this.maps[reg.mapFd]} else {}
       {
            match reg.regType {
                case UNINT | NULL | SCALAR => false
                case STACKMEM           => stack_writable(reg, 0, size)
                case CTXMEM             => context_access_safe(this.progType, bv64ToInt64(reg.regVal), size, WRITE, this.attachType, this.priv)
                case MAP_PTR            => false // MAP metadata is read-only
                case PTR_TO_MAP_VALUE   => map_value_writable(reg, 0, size)
                case _ => false
            }
       }



    ghost method {:axiom} bpf_map_lookup_elem()
        requires bpf_map_lookup_elem_progType(progType)
        // r1 = map
        requires r1.regType == MAP_PTR
        requires 0 <= r1.mapFd < this.maps.Length
        requires bpf_map_lookup_elem_mapType(this.maps[r1.mapFd].mapType)
        // r2 = key
        requires r2.regType == PTR_TO_MAP_VALUE ==> 0 <= r2.mapFd < this.maps.Length
        requires isReadableMem(r2, this.maps[r1.mapFd].keySize)
        //
        modifies this.r0
        //
        ensures r0.regNo == old(r0.regNo)
        ensures r0.regType == PTR_TO_MAP_VALUE || r0.regType == NULL
        // Note: r0.regVal is unknow so don't update it explicitly
        // TODO: r0.mapFd == r1.mapFd


    ghost method {:axiom} bpf_map_update_elem()
        requires bpf_map_update_elem_progType(progType)
        // r1 = map, r2 = key, r3 = value, r4 = flags,
        requires r1.regType == MAP_PTR
        requires 0 <= r1.mapFd < this.maps.Length
        requires bpf_map_update_elem_mapType(this.maps[r1.mapFd].mapType)
        // r2 = key
        requires r2.regType == PTR_TO_MAP_VALUE ==> 0 <= r2.mapFd < this.maps.Length
        requires isReadableMem(r2, this.maps[r1.mapFd].keySize)
        // r3 = value
        requires r3.regType == PTR_TO_MAP_VALUE ==> 0 <= r3.mapFd < this.maps.Length
        requires isReadableMem(r3, this.maps[r1.mapFd].valSize)
        requires r4.regType == SCALAR
        //
        modifies this.r0
        //
        ensures r0.regNo == old(r0.regNo)
        ensures r0.regType == SCALAR
        // Note: r0.regVal is unknow so don't update it explicitly

    ghost method {:axiom} bpf_map_delete_elem()
        requires bpf_map_delete_elem_progType(progType)
        // r1 = map, r2 = key
        requires r1.regType == MAP_PTR
        requires 0 <= r1.mapFd < this.maps.Length
        requires bpf_map_delete_elem_mapType(this.maps[r1.mapFd].mapType)
        // r2 = key
        requires r2.regType == PTR_TO_MAP_VALUE ==> 0 <= r2.mapFd < this.maps.Length
        requires isReadableMem(r2, this.maps[r1.mapFd].keySize)
        //
        modifies this.r0
        //
        ensures r0.regNo == old(r0.regNo)
        ensures r0.regType == SCALAR

    ghost method {:axiom} bpf_map_push_elem()
        requires bpf_map_push_elem_progType(progType)
        // r1 = map, r2 = value, r3 = flag
        requires r1.regType == MAP_PTR
        requires 0 <= r1.mapFd < this.maps.Length
        requires bpf_map_push_elem_mapType(this.maps[r1.mapFd].mapType)
        // r2 = value
        requires r2.regType == PTR_TO_MAP_VALUE ==> 0 <= r2.mapFd < this.maps.Length
        requires isReadableMem(r2, this.maps[r1.mapFd].valSize)
        requires r3.regType == SCALAR // need to constraint the flags to be more precise?
        //
        modifies this.r0
        //
        ensures r0.regNo == old(r0.regNo)
        ensures r0.regType == SCALAR

    ghost method {:axiom} bpf_map_pop_elem()
        requires bpf_map_pop_elem_progType(progType)
        // r1 = map, r2 = value
        requires r1.regType == MAP_PTR
        requires 0 <= r1.mapFd < this.maps.Length
        requires bpf_map_pop_elem_mapType(this.maps[r1.mapFd].mapType)
        //
        requires r2.regType == PTR_TO_MAP_VALUE ==> 0 <= r2.mapFd < this.maps.Length
        requires isWritableMem(r2, this.maps[r1.mapFd].valSize) // ARG_PTR_TO_MAP_VALUE | MEM_UNINIT,
        //
        modifies this.r0
        //
        ensures r0.regNo == old(r0.regNo)
        ensures r0.regType == SCALAR   

    ghost method {:axiom} bpf_map_peek_elem()
        requires bpf_map_peek_elem_progType(progType)
        // r1 = map, r2 = value
        requires r1.regType == MAP_PTR
        requires 0 <= r1.mapFd < this.maps.Length
        requires bpf_map_peek_elem_mapType(this.maps[r1.mapFd].mapType)
        //
        requires r2.regType == PTR_TO_MAP_VALUE ==> 0 <= r2.mapFd < this.maps.Length
        requires isWritableMem(r2, this.maps[r1.mapFd].valSize) // ARG_PTR_TO_MAP_VALUE | MEM_UNINIT,
        //
        modifies this.r0
        //
        ensures r0.regNo == old(r0.regNo)
        ensures r0.regType == SCALAR

    ghost method {:axiom} bpf_map_lookup_percpu_elem()
        requires bpf_map_lookup_percpu_elem_progType(progType)
        // r1 = map, r2 = key, r3 = cpu
        requires r1.regType == MAP_PTR
        requires 0 <= r1.mapFd < this.maps.Length
        requires bpf_map_lookup_percpu_elem_mapType(this.maps[r1.mapFd].mapType)
        // r2 = key
        requires r2.regType == PTR_TO_MAP_VALUE ==> 0 <= r2.mapFd < this.maps.Length
        requires isReadableMem(r2, this.maps[r1.mapFd].keySize)
        //
        requires r3.regType == SCALAR
        //
        modifies this.r0
        //
        ensures r0.regNo == old(r0.regNo)
        ensures r0.regType == PTR_TO_MAP_VALUE || r0.regType == NULL
        // Note: r0.regVal is unknow so don't update it explicitly


    /////////////////////////////////////////////////////////////////////////////////////

    // TODO: adjust arithmetic on pointers with relaxed and conservative behaviors

    // TODO: re-organize the memory load/store/atomic dafny code

    // TODO: is readable and writable on all types of pointers

    // Load functions as callback functions
    ghost method {:axiom} Load_PSEUDOFUNC(dst: RegState, off: bv64)
        requires dst.regNo != R10
        // find_subprog
        // some BTF checks
        // 
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == PTR_TO_FUNC
        ensures dst.regVal == off


    // TODO: Helper argument checks
    // 1. Helper argument checks 2. 
    ghost method {:axiom} bpf_for_each_map_elem()
        /*
            .ret_type   = RET_INTEGER,
            .arg1_type  = ARG_CONST_MAP_PTR,
            .arg2_type  = ARG_PTR_TO_FUNC,
            .arg3_type  = ARG_PTR_TO_STACK_OR_NULL,
            .arg4_type  = ARG_ANYTHING,
         */

    /*
    Note: map checks: if it doesn't using map_ptr args, then no map type checks (check_map_func_compatibility in check_helper_call)
        //
        check_func_arg
            resolve_map_arg_type
                switch (base_type(arg_type)) {
                    case ARG_CONST_MAP_PTR:
                        meta->map_ptr = reg->map_ptr;
    */
    ghost method {:axiom} bpf_tcp_sock()
        // r1 = ARG_PTR_TO_SOCK_COMMON
        // ret = RET_PTR_TO_TCP_SOCK_OR_NULL
        requires bpf_tcp_sock_progType(progType)
        requires r1.regType == PTR_TO_SOCK_COMMON || r1.regType == PTR_TO_SOCKET ||
                 r1.regType == PTR_TO_TCP_SOCK || r1.regType == PTR_TO_XDP_SOCK
        //
        modifies this.r0
        //
        ensures r0.regNo == old(r0.regNo)
        ensures r0.regType == PTR_TO_TCP_SOCK || r0.regType == NULL

    // Kfunc: TODO kfunc checks -> BTF is the problem
    ghost method {:axiom} bpf_arena_alloc_pages()
        // requires r1.regType == MAP_PTR


/*
    JMP:

    check_cfg
        push_insn
            - CAP_BPF for backward-edge
            - 

    
    TODO: requires on conditional jumps
        - add 32 bit jumps
        - initialized, readable
        - speculative execution
        - JNE and JEQ:
            - PTR and PTR comparision
            - PTR and scalar (0) comparision
            - mark_ptr_not_null_reg: PTR_TO_MAP_VALUE is a special case

    scalar, scalar: val == val

    scalar, ptr: priv, ???
    scalar, ptr|null: (1): scalar == 0 => ptr|null -> ptr; (2) ???

    ptr, ptr: same type, val == val
    ptr, ptr|null,		: same type: val == val
    ptr|null, ptr|null	: same type: val == val

    ---
    BPF_JCOND: may_goto

    ---

    BPF_JA: PC += offset
    - No requirements on JA

    ---
    
    BPF_JEQ: PC += offset if dst == src
    BPF_JSET: PC += offset if dst & src
    BPF_JNE: PC += offst if dst != src

    ---

    BPF_JGT: PC += offset if dst > src
    BPF_JGE: PC += offset if dst >= src
    Signed: BPF_JSGT: PC += offset if dst > src
    Signed: BPF_JSGE: PC += offset if dst >= src 

    ---

    BPF_JLT: PC += offset if dst < src
    BPF_JLE: PC += offset if dst <= src
    Signed: BPF_JSLT: PC += offset if dst < src
    Signed: BPF_JSLE: PC += offset if dst <= src
 */

    // Done TODO: memid // if (isPtr() && isPtr() && .memid == .memid), map_ptr_value returned by different calls must have different memids cause they might point to different memory
    // Done TODO: update mapFd in each instruction ==> how to save mapFd when spill to memory (e.g., stack)
    // TODO: packet ptr has fixed relation: is_pkt_ptr_branch_taken
    //  - JLE, JLT, JGE, JGT

    // HARD-TODO: when a ptr_or_null -> null, it becomes scalar ==> replace NULL with SCALAR
    // TODO: translator
    
    ghost predicate same_mem(dst:RegState, src:RegState)
        reads dst, src
        {
            dst.regType == src.regType && (
                dst.regType == STACKMEM
                ||
                dst.regType == CTXMEM
                ||
                dst.regType == PTR_TO_PACKET_META
                ||
                dst.regType == PTR_TO_PACKET
                ||
                dst.regType == PTR_TO_PACKET_END
                ||
                dst.regType == PTR_TO_FLOW_KEYS
                ||
                dst.regType == PTR_TO_TP_BUFFER
                ||
                (dst.regType == MAP_PTR && dst.mapFd == src.mapFd)
                // TODO: PTR_TO_MAP_KEY, PTR_TO_MAP_VALUE, SOCKET
            )
        }

    ghost function JEQ64_REG(dst:RegState, src:RegState) :bool
        reads this, dst, src
        requires dst.regType != UNINT
        requires src.regType != UNINT
        requires !allow_ptr_leak ==> (
            (dst.regType == SCALAR && src.regType == SCALAR)
            ||
            (isPtr(dst.regType) && isPtr(src.regType))
        )
        {
            // scalar == scalar
            if dst.regType == SCALAR && src.regType == SCALAR
                then dst.regVal == src.regVal
            // ptr == 0
            else if (isPtr(dst.regType) && src.regType == SCALAR && src.regVal == 0)
                then dst.regType == NULL
            // 0 == ptr
            else if (dst.regType == SCALAR && dst.regVal == 0  && isPtr(src.regType))
                then src.regType == NULL
            // ptr == ptr pointing to the same memory
            else if (isPtr(dst.regType) && isPtr(src.regType) && same_mem(dst, src)) // TODO: memid // if (isPtr() && isPtr() && .memid == .memid)
                then dst.regVal == src.regVal && dst.regType == src.regType
            // if(ptr == non_null_ptr) ==> if(ptr != NULL)
            else if (isPtr(dst.regType) && isNonNULLPtr(src.regType))
                then dst.regType != NULL
            // if(non_null_ptr == ptr) ==> if(ptr != NULL)
            else if (isNonNULLPtr(dst.regType) && isPtr(src.regType))
                then src.regType != NULL
            // ptr == ptr pointing to different memory
            // ptr == scalar
            else unknown_bool()
        }
    
    ghost function JEQ32_REG(dst:RegState, src:RegState) :bool
        reads this, dst, src
        requires dst.regType != UNINT
        requires src.regType != UNINT
        requires !allow_ptr_leak ==> (
            (dst.regType == SCALAR && src.regType == SCALAR)
            ||
            (isPtr(dst.regType) && isPtr(src.regType))
        )
        {
            // scalar == scalar
            if dst.regType == SCALAR && src.regType == SCALAR
                then bv64Tobv32(dst.regVal) == bv64Tobv32(src.regVal)
            // ptr == ptr pointing to the same memory
            // lower 32-bit offset equals does not mean their memory address equals
            // else if (isPtr(dst.regType) && isPtr(src.regType)) // TODO: memid // if (isPtr() && isPtr() && .memid == .memid)
            //    then dst.regType == src.regType && bv64Tobv32(dst.regVal) == bv64Tobv32(src.regVal)
            // ptr == ptr pointing to different memory
            // ptr == scalar
            else unknown_bool()
        }

    ghost predicate JEQ64_IMM(dst:RegState, srcImm:bv64)
        reads this, dst
        requires dst.regType != UNINT
        requires !allow_ptr_leak ==> dst.regType == SCALAR
        {
            // scalar == scalar
            if dst.regType == SCALAR
                then dst.regVal == srcImm
            // PTR == scalar (0)
            else if isPtr(dst.regType) && srcImm == 0
                then dst.regType == NULL
            // ptr == non-zero scalars
            else unknown_bool()
        }

    ghost predicate JEQ32_IMM(dst:RegState, srcImm:bv64)
        reads this, dst
        requires dst.regType != UNINT
        requires !allow_ptr_leak ==> dst.regType == SCALAR
        {
            // scalar == scalar
            if dst.regType == SCALAR
                then bv64Tobv32(dst.regVal) == bv64Tobv32(srcImm)
            // ptr == scalar
            else unknown_bool()
        }

    ghost predicate JNE64_REG(dst:RegState, src:RegState)
        reads this, dst, src
        requires dst.regType != UNINT
        requires src.regType != UNINT
        requires !allow_ptr_leak ==> (
            (dst.regType == SCALAR && src.regType == SCALAR)
            ||
            (isPtr(dst.regType) && isPtr(src.regType))
        )
        {
            // scalar == scalar
            if dst.regType == SCALAR && src.regType == SCALAR
                then dst.regVal != src.regVal
            // ptr == 0
            else if (isPtr(dst.regType) && src.regType == SCALAR && src.regVal == 0)
                then dst.regType != NULL
            // 0 == ptr
            else if (dst.regType == SCALAR && dst.regVal == 0  && isPtr(src.regType))
                then src.regType != NULL
            // ptr == ptr pointing to the same memory
            else if (isPtr(dst.regType) && isPtr(src.regType) && same_mem(dst, src))
                then dst.regVal == src.regVal
            // if(ptr != non_null_ptr) ==> if(ptr == NULL || ptr == ptr_or_null)
            else if (isPtr(dst.regType) && isNonNULLPtr(src.regType))
                then dst.regType == NULL || isNonNULLPtr(dst.regType)
            // if(non_null_ptr != ptr) ==> if(ptr == NULL || ptr == ptr_or_null)
            else if (isNonNULLPtr(dst.regType) && isPtr(src.regType))
                then src.regType == NULL || isNonNULLPtr(src.regType)
            // ptr == ptr pointing to different memory
            // ptr == scalar
            else unknown_bool()
        }

    ghost predicate JNE32_REG(dst:RegState, src:RegState)
        reads this, dst, src
        requires dst.regType != UNINT
        requires src.regType != UNINT
        requires !allow_ptr_leak ==> (
            (dst.regType == SCALAR && src.regType == SCALAR)
            ||
            (isPtr(dst.regType) && isPtr(src.regType))
        )
        {
            // scalar == scalar
            if dst.regType == SCALAR && src.regType == SCALAR
                then bv64Tobv32(dst.regVal) != bv64Tobv32(src.regVal)
            // ptr == ptr pointing to different memory
            // ptr == scalar
            else unknown_bool()
        }

    ghost predicate JNE64_IMM(dst:RegState, srcImm:bv64)
        reads this, dst
        requires dst.regType != UNINT
        requires !allow_ptr_leak ==> dst.regType == SCALAR
        {
            // scalar != scalar
            if dst.regType == SCALAR
                then dst.regVal != srcImm
            // PTR != scalar (0)
            else if isPtr(dst.regType) && srcImm == 0
                then dst.regType != NULL
            // ptr != non-zero scalars
            else unknown_bool()
        }

    ghost predicate JNE32_IMM(dst:RegState, srcImm:bv64)
        reads this, dst
        requires dst.regType != UNINT
        requires !allow_ptr_leak ==> dst.regType == SCALAR
        {
            // scalar != scalar
            if dst.regType == SCALAR
                then dst.regVal != srcImm
            // PTR != scalar
            else unknown_bool()
        }

    ghost predicate JSET64_REG(dst:RegState, src:RegState)
        reads this, dst, src
        requires dst.regType != UNINT && src.regType != UNINT
        // 
        requires !allow_ptr_leak ==> (
            (dst.regType == SCALAR && src.regType == SCALAR)
            ||
            (isPtr(dst.regType) && isPtr(src.regType))
        )
        {
            if (dst.regType == SCALAR && src.regType == SCALAR)
                then (dst.regVal & src.regVal) != 0
            else unknown_bool()
            // <ptr, scalar> or <scalar, ptr> => unknown
            // scalar, scalar   => a & b
            // ptr (or null), ptr (or null) => unknown
        }

    ghost predicate JSET32_REG(dst:RegState, src:RegState)
        reads this, dst, src
        requires dst.regType != UNINT && src.regType != UNINT
        // 
        requires !allow_ptr_leak ==> (
            (dst.regType == SCALAR && src.regType == SCALAR)
            ||
            (isPtr(dst.regType) && isPtr(src.regType))
        )
        {
            if (dst.regType == SCALAR && src.regType == SCALAR)
                then (bv64Tobv32(dst.regVal) & bv64Tobv32(src.regVal)) != 0
            else unknown_bool()
            // <ptr, scalar> or <scalar, ptr> => unknown
            // scalar, scalar   => a & b
            // ptr (or null), ptr (or null) => unknown
        }

    ghost predicate JSET64_IMM(dst:RegState, srcImm:bv64)
        reads this, dst
        requires dst.regType != UNINT
        requires !allow_ptr_leak ==> dst.regType == SCALAR
        {
            if (dst.regType == SCALAR) 
                then (dst.regVal & srcImm) != 0
            else unknown_bool()
        }

    ghost predicate JSET32_IMM(dst:RegState, srcImm:bv64)
        reads this, dst
        requires dst.regType != UNINT
        requires !allow_ptr_leak ==> dst.regType == SCALAR
        {
            if (dst.regType == SCALAR) 
                then (bv64Tobv32(dst.regVal) & bv64Tobv32(srcImm)) != 0
            else unknown_bool()
        }

    ghost predicate LGJMP64_REG(dst:RegState, src:RegState, op:LGJMP)
        reads this, dst, src
        requires dst.regType != UNINT && src.regType != UNINT
        requires !allow_ptr_leak ==> (
            (dst.regType == SCALAR && src.regType == SCALAR)
            ||
            (isPtr(dst.regType) && isPtr(src.regType))
        )
        {
            if (isPktPtr(dst.regType) && isPktPtr(src.regType)) then (
                //
                var zero_off := (dst.regVal == src.regVal == 0);
                //
                // if(pkt_meta > pkt_data) => if(pkt_meta.regVal > packet_meta_range)
                // Discussion: when pkt_data pointer's off is not zero,
                // org verifier skip the relation inference between meta and data pointer
                if (dst.regType == PTR_TO_PACKET_META && src.regType == PTR_TO_PACKET) then (
                    var cur_off := (bv64ToInt64(dst.regVal) - bv64ToInt64(src.regVal));
                    match op {
                        case JGT => if zero_off then false else cur_off > packet_meta_range
                        case JGE => if zero_off then false else cur_off >= packet_meta_range
                        case JLT => if zero_off then true  else cur_off < packet_meta_range
                        case JLE => if zero_off then true  else cur_off <= packet_meta_range
                        case _   => unknown_bool()
                    }
                )
                //
                // if(pkt_data > pkt_meta) => if (packet_meta_range > pkt_meta.regVal && )
                else if (dst.regType == PTR_TO_PACKET && src.regType == PTR_TO_PACKET_META) then (
                    var cur_off := (bv64ToInt64(src.regVal) - bv64ToInt64(dst.regVal));
                    match op {
                        case JGT => if zero_off then true  else packet_meta_range > cur_off
                        case JGE => if zero_off then true  else packet_meta_range >= cur_off
                        case JLT => if zero_off then false else packet_meta_range < cur_off
                        case JLE => if zero_off then false else packet_meta_range <= cur_off
                        case _   => unknown_bool()
                    }
                )
                //
                // if(pkt_data > pkt_end) => if(pkt_data.regVal > packet_data_range)
                else if (dst.regType == PTR_TO_PACKET && src.regType == PTR_TO_PACKET_END) then (
                    var cur_off := (bv64ToInt64(dst.regVal) - bv64ToInt64(src.regVal));
                    match op {
                        case JGT => if zero_off then false else cur_off > packet_data_range
                        case JGE => if zero_off then false else cur_off >= packet_data_range
                        case JLT => if zero_off then true  else cur_off < packet_data_range
                        case JLE => if zero_off then true  else cur_off <= packet_data_range
                        case _   => unknown_bool()
                    }
                )
                //
                // if(pkt_end > pkt_data) => if (packet_data_range > pkt_data.regVal)
                else if (dst.regType == PTR_TO_PACKET_END && src.regType == PTR_TO_PACKET) then (
                    var cur_off := (bv64ToInt64(src.regVal) - bv64ToInt64(dst.regVal));
                    match op {
                        case JGT => if zero_off then true else packet_data_range > cur_off
                        case JGE => if zero_off then true else packet_data_range >= cur_off
                        case JLT => if zero_off then false else packet_data_range < cur_off
                        case JLE => if zero_off then false else packet_data_range <= cur_off
                        case _   => unknown_bool()
                    }
                )
                //
                else unknown_bool()
            )
            // 
            else if (
                (dst.regType == SCALAR && src.regType == SCALAR)
                ||
                (isPtr(dst.regType)  && isPtr(src.regType) && same_mem(dst, src)) //TODO: memid // if (isPtr() && isPtr() && .memid == .memid)
            ) then (
                match op {
                    case JGT    => dst.regVal > src.regVal
                    case JGE    => dst.regVal >= src.regVal
                    case JSGT   => bv64ToInt64(dst.regVal) > bv64ToInt64(src.regVal)
                    case JSGE   => bv64ToInt64(dst.regVal) >= bv64ToInt64(src.regVal)
                    case JLT    => dst.regVal < src.regVal
                    case JLE    => dst.regVal <= src.regVal
                    case JSLT   => bv64ToInt64(dst.regVal) < bv64ToInt64(src.regVal)
                    case JSLE   => bv64ToInt64(dst.regVal) <= bv64ToInt64(src.regVal)
                }
            )
            else unknown_bool()
        }

    ghost predicate LGJMP64_IMM(dst:RegState, srcImm:bv64, op:LGJMP)
        reads this, dst
        requires dst.regType != UNINT
        requires !allow_ptr_leak ==> dst.regType == SCALAR
        {
            if (dst.regType == SCALAR) then (
                match op {
                    case JGT => dst.regVal > srcImm
                    case JGE    => dst.regVal >= srcImm
                    case JSGT   => bv64ToInt64(dst.regVal) > bv64ToInt64(srcImm)
                    case JSGE   => bv64ToInt64(dst.regVal) >= bv64ToInt64(srcImm)
                    case JLT    => dst.regVal < srcImm
                    case JLE    => dst.regVal <= srcImm
                    case JSLT   => bv64ToInt64(dst.regVal) < bv64ToInt64(srcImm)
                    case JSLE   => bv64ToInt64(dst.regVal) <= bv64ToInt64(srcImm)
                }
            )
            else unknown_bool()
        }

    ghost predicate LGJMP32_REG(dst:RegState, src:RegState, op:LGJMP)
        reads this, dst, src
        requires dst.regVal & 0xFFFF_FFFF_0000_0000 == 0
        requires src.regVal & 0xFFFF_FFFF_0000_0000 == 0
        requires dst.regType != UNINT && src.regType != UNINT
        requires !allow_ptr_leak ==> (
            (dst.regType == SCALAR && src.regType == SCALAR)
            ||
            (isPtr(dst.regType) && isPtr(src.regType))
        )
        {
            if (
                (dst.regType == SCALAR && src.regType == SCALAR)
                ||
                (isPtr(dst.regType) && isPtr(src.regType) && same_mem(dst, src)) //TODO: memid // if (isPtr() && isPtr() && .memid == .memid)
            ) then (
                match op {
                    case JGT    => bv64Tobv32(dst.regVal)   >   bv64Tobv32(src.regVal)
                    case JGE    => bv64Tobv32(dst.regVal)   >=  bv64Tobv32(src.regVal)
                    case JSGT   => bv32ToInt32(dst.regVal)  >   bv32ToInt32(src.regVal)
                    case JSGE   => bv32ToInt32(dst.regVal)  >=  bv32ToInt32(src.regVal)
                    case JLT    => bv64Tobv32(dst.regVal)   <   bv64Tobv32(src.regVal)
                    case JLE    => bv64Tobv32(dst.regVal)   <=  bv64Tobv32(src.regVal)
                    case JSLT   => bv32ToInt32(dst.regVal)  <   bv32ToInt32(src.regVal)
                    case JSLE   => bv32ToInt32(dst.regVal)  <=  bv32ToInt32(src.regVal)
                }
            )
            else unknown_bool()
        }

    ghost predicate LGJMP32_IMM(dst:RegState, srcImm:bv64, op:LGJMP)
        reads this, dst
        requires dst.regVal & 0xFFFF_FFFF_0000_0000 == 0
        // requires srcImm & 0xFFFF_FFFF_0000_0000 == 0
        requires dst.regType != UNINT
        requires !allow_ptr_leak ==> dst.regType == SCALAR
        {
            if (dst.regType == SCALAR) then (
                match op {
                    case JGT    => bv64Tobv32(dst.regVal)   >   bv64Tobv32(srcImm)
                    case JGE    => bv64Tobv32(dst.regVal)   >=  bv64Tobv32(srcImm)
                    case JSGT   => bv32ToInt32(dst.regVal)  >   bv32ToInt32(srcImm)
                    case JSGE   => bv32ToInt32(dst.regVal)  >=  bv32ToInt32(srcImm)
                    case JLT    => bv64Tobv32(dst.regVal)   <   bv64Tobv32(srcImm)
                    case JLE    => bv64Tobv32(dst.regVal)   <=  bv64Tobv32(srcImm)
                    case JSLT   => bv32ToInt32(dst.regVal)  <   bv32ToInt32(srcImm)
                    case JSLE   => bv32ToInt32(dst.regVal)  <=  bv32ToInt32(srcImm)
                }
            )
            else unknown_bool()
        }


    //////////////// Utility functions //////////////////////////


    ghost method {:axiom} update_stack_value(pos:int64, value:bv8)
        requires this.stack.Length == 512
        requires 0 <= pos < 512
        //
        modifies this.stack
        //
        ensures forall i | 0 <= i < 512 :: (
            ((i == pos) ==> stack[i] == value)
            &&
            ((i != pos) ==> stack[i] == old(stack[i]))
        )

    // inclusive at both sides: [start, end]
    ghost method {:axiom} update_stack_type(start:int64, end:int64, slotType:REGTYPE)
        requires this.stackSlotType.Length == 512
        requires 0 <= start <= end < 512
        //
        modifies this.stackSlotType
        //
        ensures forall i | 0 <= i < 512 :: (
            (start <= i <= end ==> stackSlotType[i] == slotType)
            &&
            (!(start <= i <= end) ==> stackSlotType[i] == old(stackSlotType[i]))
        )
}

method AnyBv64() returns (x: bv64)
{
  x :| true;  // Non-deterministically assign any value to x
}

method AnyInt64() returns (x: int64)
{
  x :| true;  // Non-deterministically assign any value to x
}