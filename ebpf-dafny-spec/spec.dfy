include "utils.dfy"
include "ctxmem-precond.dfy"
include "call2progmap.dfy"
include "return-code.dfy"
include "btf.dfy"

/*
    eBPF ISA RFC: https://www.rfc-editor.org/rfc/rfc9669.html
    Issue checking manual: https://www.cse.chalmers.se/edu/course.2018/TDA567_Testing_Debugging_Verification/dafny_troubleshooting.pdf
    Dafny blogs: https://dafny.org/blog/
    Fine-grained Caching of Verification Results: https://www.microsoft.com/en-us/research/wp-content/uploads/2016/12/krml245.pdf
    Ironclad: https://github.com/Microsoft/Ironclad
    - All non-64-bit operations zero out the upper bits
    - https://docs.kernel.org/bpf/standardization/instruction-set.html

    Must check:
        1. Refer the pre-state of variables using old() in ensures
        2. Conditional modifies and reads, e.g., reads if flag then {this} else {}
        3. Ensure mapFd and memId is maintianed correctly when loading a pointer or storing pointers onto the stack
    
    TODO:
        1. Arithmetic operations on pointers
            - Discussion: Decide on which operation is allowed
            - Cannot do arithmetic operations on <ptr, ptr> and <ptr, scalar> with ptr regVal as it is offset not ptr absolute value
        2. Capability levels and corresponding checks
        3. Discussion:
            - Limit the total size of stack access (512 in total)
            - Global and callback stack depth
        4. Global pseudo functions (note: when calling them, locks cannot be held)
        5. Spin_lock cannot be held when calling global pseudo functions, helper calls, and 
        6. Discussion: cannot modify slots with STACK_ITER and STACK_DYNPTR, special case, iter_new, iter_next, and iter_destroy
        7. Discussion: No 64-bit arith insns on a PTR_MAYBE_NULL and a scalar
        8. Speculative executions
        9. Discussion: is it necessary to prevent integer overflow?
        10. Implement the distrbuted verification
        11. Relaxation:
            - Atomic insn on context and stack memory
            - Store pointer to context
            - Pointer arithemtic
            - what is the need for loading from const context ptr?
            - very coarse-grained checks on helper calls. For example you can even pass a map ptr to 
            - what is the basis of the design of compatible_reg_types for helper call args?
            - Arithmetic on <ptr, scala> and <ptr, ptr>: why allow neg on ptr but not xor, or on ptr under allow_ptr_leak?
            - is it meaningful to sub64/32 on different types of pointers? The purpose of sub32/64 is for knowing the data length, which should be the same type.
        12. Motivation example: zero_size_allowed: https://github.com/torvalds/linux/commit/9fd29c08e5202
            - Cannot accurately track the size value and thus need to becomes much more uncessary relaxed.
*/

class State {

    // Enable original verifier constrants on this spec
    ghost var enable_org: bool

    // Capabilities
    ghost var allow_ptr_leak: bool, bypass_spec_v1: bool, priv: bool

    //
    var attachType: AttachTypes, progType: ProgTypes

    // Registers
    var r0:RegState, r1:RegState, r2:RegState, r3:RegState, r4:RegState, r5:RegState,
              r6:RegState, r7:RegState, r8:RegState, r9:RegState, r10: RegState
    // RegSavers: N-depth(8) * 4-Regs(R6-R9)
    var regSaver: array<RegState>

    // Stack
    var stacks: array<array<bv8>>
    var stackSlotTypes: array<array<REGTYPE>>
    var idMetas: array<array<int64>>

    // Discussion: CTX, is it necessary to maintain the value of context slots
    var context: array<bv8>
    // Maps
    var maps: array<MapState>
    
    // The packet data and metadata length we can predicate from `if`
    var packet_data_range: int64, packet_meta_range: int64

    // Alignment
    var strict_alignment: bool

    // Spin lock
    var spin_lock_meta: SpinLockState

    // idCounter
    var mutableVars: MutableVars

    constructor {:axiom} (allow_ptr_leak_set:bool, bypass_spec_v1_set:bool, priv_set:bool, has_net_admin:bool, strict_alignment_set:bool)
        
        //
        ensures enable_org == true

        // Priv
        ensures this.allow_ptr_leak == allow_ptr_leak_set
        ensures this.bypass_spec_v1 == bypass_spec_v1_set
        ensures this.priv == priv_set
        
        // Alginment
        ensures strict_alignment == strict_alignment_set 
        
        // Regs
        ensures fresh(this.r0) && fresh(this.r1) && fresh(this.r2) && fresh(this.r3) && fresh(this.r4) && fresh(this.r5)
        ensures fresh(this.r6) && fresh(this.r7) && fresh(this.r8) && fresh(this.r9) && fresh(this.r10)
        // Special R1 and R10
        ensures this.r1.regNo == R1 && this.r1.regType == CTXMEM && this.r1.regVal == 0
        ensures this.r10.regNo == R10 && this.r10.regType == STACKMEM && this.r10.regVal == 0 && this.r10.memId == 0
        // RegNo of R0, R2-R9
        ensures this.r0.regNo == R0 && this.r2.regNo == R2 && this.r3.regNo == R3 && this.r4.regNo == R4 && this.r5.regNo == R5 &&
                this.r6.regNo == R6 && this.r7.regNo == R7 && this.r8.regNo == R8 && this.r9.regNo == R9
        // RegType
        ensures this.r0.regType == UNINT && this.r2.regType == UNINT && this.r3.regType == UNINT &&
                this.r4.regType == UNINT && this.r5.regType == UNINT && this.r6.regType == UNINT &&
                this.r7.regType == UNINT && this.r8.regType == UNINT && this.r9.regType == UNINT
        
        /*
        ensures !this.allow_ptr_leak || this.enable_org ==>
                    this.r0.regType == UNINT && this.r2.regType == UNINT && this.r3.regType == UNINT &&
                    this.r4.regType == UNINT && this.r5.regType == UNINT && this.r6.regType == UNINT &&
                    this.r7.regType == UNINT && this.r8.regType == UNINT && this.r9.regType == UNINT
        
        ensures this.allow_ptr_leak && !this.enable_org ==>
                    this.r0.regType == SCALAR && this.r2.regType == SCALAR && this.r3.regType == SCALAR &&
                    this.r4.regType == SCALAR && this.r5.regType == SCALAR && this.r6.regType == SCALAR &&
                    this.r7.regType == SCALAR && this.r8.regType == SCALAR && this.r9.regType == SCALAR
        */

        // Regsave used when calling pseudo calls
        ensures regSaver.Length == 32
        ensures fresh(regSaver)
        ensures forall i | 0 <= i < 32 :: fresh(regSaver[i])

        // Stack: MAX_CALL_FRAMES = 8
        ensures stacks.Length == 8
        ensures forall i | 0 <= i < 8 :: stacks[i].Length == 512 && fresh(stacks[i])
        //
        ensures stackSlotTypes.Length == 8
        ensures forall i | 0 <= i < 8 :: stackSlotTypes[i].Length == 512 && fresh(stackSlotTypes[i])
        // assume the stack value and idMeta are unknown, so no need to initialize them        
        // Must not initialize the value of regs or stack slots with AnyBv64() to ensure the correct usage of assume when verifying failed programs.
        //
        // Only initilize the stack slot types of main function, others are initilaized when called
        ensures !this.allow_ptr_leak ==> forall i | 0 <= i < 512 :: this.stackSlotTypes[0][i] == UNINT
        ensures this.allow_ptr_leak ==> forall i | 0 <= i < 512 :: this.stackSlotTypes[0][i] == SCALAR

        // ensures !this.allow_ptr_leak ==> forall stackNo,i | 0 <= stackNo < 8 && 0 <= i < 512 :: this.stackSlotTypes[stackNo][i] == UNINT
        // ensures this.allow_ptr_leak  ==> forall stackNo,i | 0 <= stackNo < 8 && 0 <= i < 512 :: this.stackSlotTypes[stackNo][i] == SCALAR

        //
        ensures idMetas.Length == 8
        ensures forall i | 0 <= i < 8 :: idMetas[i].Length == 64 && fresh(idMetas[i])
        
        // Context: Context of syscall_prog is the maximum, which is 65536
        ensures this.context.Length == 65536
        // Discussion: is it necessary?
        ensures fresh(context)
        
        // Maps
        // Length is constrainted by the concrete test by the translator
        // ensures this.maps.Length == 10
        ensures forall i: int :: 0 <= i < 10 ==> fresh(maps[i])
        
        //
        ensures 0 <= packet_data_range < 0xFFFF
        ensures 0 <= packet_meta_range < 0xFFFF

        // Other states 
        ensures fresh(spin_lock_meta)
        ensures fresh(mutableVars)
        //
        ensures spin_lock_meta.isLocked == false
        
        ensures mutableVars.idCounter == 1

    ghost predicate type_check_single_src_operand(dst: RegState)
        reads this
        reads dst
        {
            if this.enable_org
                // original eBPF
                then (
                    if this.allow_ptr_leak
                        then (dst.regType != UNINT && dst.regType != NULL)
                        else (dst.regType == SCALAR)
                )
                // original eBPF
                else (
                    beacon_type_check1(dst)
                )
        }

    ghost predicate beacon_type_check1(reg: RegState)
        reads this
        reads reg
        {   
            if this.allow_ptr_leak
                then (reg.regType != NULL && reg.regType != UNINT)
                else reg.regType == SCALAR
        }

    ghost predicate beacon_type_check2(dst: RegState, src: RegState)
        reads this
        reads dst, src
        {   
            if this.allow_ptr_leak
                then (dst.regType != NULL && src.regType != NULL && dst.regType != UNINT && src.regType != UNINT)
                else (dst.regType == SCALAR && src.regType == SCALAR)
        }

    //////////////////////////////// 32-bit Arithmetic Operations ////////////////////////////////

    ghost method {:axiom} Neg32(dst: RegState, src: RegState)
        requires type_check_single_src_operand(dst)
        requires dst.regNo != R10
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == (!old(dst.regVal) & 0x0000_0000_FFFF_FFFF)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Bv2be16(dst: RegState, src: RegState)
        requires type_check_single_src_operand(dst)
        requires dst.regNo != R10
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == byteswapN(old(dst.regVal), 0, 2)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Bv2be32(dst: RegState, src: RegState)
        requires type_check_single_src_operand(dst)
        requires dst.regNo != R10
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == byteswapN(old(dst.regVal), 0, 4)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)

    // Here we assume the arch is X86-64, whichs is big endian
    // And thus, we do nothing here
    ghost method {:axiom} Bv2le16(dst: RegState, src: RegState)
        requires type_check_single_src_operand(dst)
        requires dst.regNo != R10
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == old(dst.regVal)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Bv2le32(dst: RegState, src: RegState)
        requires type_check_single_src_operand(dst)
        requires dst.regNo != R10
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == old(dst.regVal)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Bv2swap16(dst: RegState, src: RegState)
        requires type_check_single_src_operand(dst)
        requires dst.regNo != R10
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == byteswapN(old(dst.regVal), 0, 2)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Bv2swap32(dst: RegState, src: RegState)
        requires type_check_single_src_operand(dst)
        requires dst.regNo != R10
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == byteswapN(old(dst.regVal), 0, 4)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Mov32_REG(dst: RegState, src: RegState)
        requires type_check_single_src_operand(src)
        requires dst.regNo != R10
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(src.regType) == SCALAR ==> dst.regVal == (old(src.regVal) & 0x00000000FFFFFFFF)
        ensures NonNULLPtr(old(src.regType)) ==> unknownBv32(dst.regVal)

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
        requires type_check_single_src_operand(src)
        requires dst.regNo != R10
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(src.regType) == SCALAR ==> 
                    dst.regVal == if ((old(src.regVal) & 0x0000000000000080) != 0)
                        then (old(src.regVal) | 0x00000000FFFFFF00) & 0x0000_0000_FFFF_FFFF
                        else (old(src.regVal) & 0x00000000000000FF) & 0x0000_0000_FFFF_FFFF
        ensures NonNULLPtr(old(src.regType)) ==> unknownBv32(dst.regVal)

    // Signed extending 16-bits register to 32-bits register
    ghost method {:axiom} Mov32SX16(dst: RegState, src: RegState)
        requires type_check_single_src_operand(src)
        requires dst.regNo != R10
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(src.regType) == SCALAR ==>
                    dst.regVal == if ((old(src.regVal) & 0x0000000000008000) != 0)
                        then (old(src.regVal) | 0x00000000FFFF0000) & 0x0000_0000_FFFF_FFFF
                        else (old(src.regVal) & 0x000000000000FFFF) & 0x0000_0000_FFFF_FFFF
        ensures NonNULLPtr(old(src.regType)) ==> unknownBv32(dst.regVal)

    ///////////////////////////////////////////////////////////////////////////

    // Upper 32bits are zeroed out
    ghost method {:axiom} Add32_REG(dst: RegState, src: RegState)
        requires dst.regNo != R10
        requires enable_org ==> src.regType == SCALAR && dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==>
                    dst.regVal == ((old(dst.regVal) & 0xFFFFFFFF) + (old(src.regVal) & 0xFFFFFFFF)) & 0xFFFFFFFF
        ensures NonNULLPtr(old(dst.regType)) || NonNULLPtr(old(src.regType)) ==> unknownBv32(dst.regVal)
        // Note: even either dst or src are zero scalar their result is still unknown

    ghost method {:axiom} Add32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == ((old(dst.regVal) & 0xFFFFFFFF) + (srcImm & 0xFFFFFFFF)) & 0xFFFFFFFF
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)

    // Note: with allow_ptr_leak permission, sub32 can work on ptr-ptr, ptr-imm, imm-ptr, and imm-imm
    ghost method {:axiom} Sub32_REG(dst: RegState, src: RegState)
        requires dst.regNo != R10
        requires enable_org ==> (
                    if allow_ptr_leak
                        then (dst.regType != UNINT && src.regType != UNINT && dst.regType != NULL && src.regType != NULL)
                        else (dst.regType == SCALAR && src.regType == SCALAR)
        )
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR 
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==>
                    dst.regVal == ((old(dst.regVal) & 0xFFFFFFFF) - (old(src.regVal) & 0xFFFFFFFF)) & 0xFFFFFFFF
        ensures NonNULLPtr(old(dst.regType)) || NonNULLPtr(old(src.regType)) ==> unknownBv32(dst.regVal)
        // Note: even either dst or src are zero scalar their result is still unknown

    ghost method {:axiom} Sub32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        requires enable_org ==> (
                    if allow_ptr_leak
                        then (dst.regType != UNINT && dst.regType != NULL)
                        else (dst.regType == SCALAR)
        )
        requires !enable_org ==> beacon_type_check1(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == ((old(dst.regVal) & 0xFFFFFFFF) - (srcImm & 0xFFFFFFFF)) & 0xFFFFFFFF
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Mul32_REG(dst: RegState, src: RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR 
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==>
                    dst.regVal == ((old(dst.regVal) & 0xFFFFFFFF) * (old(src.regVal) & 0xFFFFFFFF)) & 0xFFFFFFFF
        ensures NonNULLPtr(old(dst.regType)) && NonNULLPtr(old(src.regType)) ==> unknownBv32(dst.regVal)
        //        
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && (old(src.regVal) & 0xFFFFFFFF) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && (old(src.regVal) & 0xFFFFFFFF) != 0) ==> unknownBv32(dst.regVal)
        //
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && (old(dst.regVal) & 0xFFFFFFFF) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && (old(dst.regVal) & 0xFFFFFFFF) != 0) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Mul32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == ((old(dst.regVal) & 0xFFFFFFFF) * (srcImm & 0xFFFFFFFF)) & 0xFFFFFFFF
        ensures NonNULLPtr(old(dst.regType)) && (srcImm & 0xFFFFFFFF) != 0 ==> unknownBv32(dst.regVal)
        ensures NonNULLPtr(old(dst.regType)) && (srcImm & 0xFFFFFFFF) == 0 ==> dst.regVal == 0

    //  If BPF program execution would result in division by zero, the destination register is instead set to zero.
    ghost method {:axiom} Div32_REG(dst: RegState, src: RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==>
                    dst.regVal == if old(src.regVal) & 0xFFFFFFFF == 0
                        then 0x0
                        else ((old(dst.regVal) & 0xFFFFFFFF) / (old(src.regVal) & 0xFFFFFFFF)) & 0xFFFFFFFF
        ensures NonNULLPtr(old(dst.regType)) && NonNULLPtr(old(src.regType)) ==> unknownBv32(dst.regVal)
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && (old(src.regVal) & 0xFFFFFFFF) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && (old(src.regVal) & 0xFFFFFFFF) != 0) ==> unknownBv32(dst.regVal)
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && (old(dst.regVal) & 0xFFFFFFFF) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && (old(dst.regVal) & 0xFFFFFFFF) != 0) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Div32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        // Note: If the divisor is immediate and is zero, it violates the safety properties
        requires srcImm != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == if srcImm & 0xFFFFFFFF == 0
                        then 0x0
                        else ((old(dst.regVal) & 0xFFFFFFFF) / (srcImm & 0xFFFFFFFF)) & 0xFFFFFFFF
        ensures NonNULLPtr(old(dst.regType)) && (srcImm & 0xFFFFFFFF) != 0 ==> unknownBv32(dst.regVal)
        ensures NonNULLPtr(old(dst.regType)) && (srcImm & 0xFFFFFFFF) == 0 ==> dst.regVal == 0 


    ghost method {:axiom} SDiv32_REG(dst: RegState, src: RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==>
                    dst.regVal == if twocom2Abs32Bit(old(src.regVal)) == 0 
                        then 0x0
                        else signDiv32Bit((old(dst.regVal) & 0xFFFFFFFF), (old(src.regVal) & 0xFFFFFFFF))
        ensures NonNULLPtr(old(dst.regType)) && NonNULLPtr(old(src.regType)) ==> unknownBv32(dst.regVal)
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && twocom2Abs32Bit(old(src.regVal)) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && twocom2Abs32Bit(old(src.regVal)) != 0) ==> unknownBv32(dst.regVal)
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && twocom2Abs32Bit(old(dst.regVal)) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && twocom2Abs32Bit(old(dst.regVal)) != 0) ==> unknownBv32(dst.regVal)


    ghost method {:axiom} SDiv32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        // Note: If the divisor is immediate and is zero, it violates the safety properties
        requires srcImm != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == if twocom2Abs32Bit(srcImm) == 0 
                        then 0x0
                        else signDiv32Bit((old(dst.regVal) & 0xFFFFFFFF), (srcImm & 0xFFFFFFFF))
        ensures NonNULLPtr(old(dst.regType)) && twocom2Abs32Bit(srcImm) != 0 ==> unknownBv32(dst.regVal)
        ensures NonNULLPtr(old(dst.regType)) && twocom2Abs32Bit(srcImm) == 0 ==> dst.regVal == 0

    // Note: If execution would result in modulo by zero, the upper 32 bits of the destination register are zeroed.
    ghost method {:axiom} Mod32_REG(dst: RegState, src: RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==>
                    dst.regVal == if old(src.regVal) & 0xFFFFFFFF == 0
                        then old(dst.regVal) & 0xFFFFFFFF
                        else ((old(dst.regVal)  & 0xFFFFFFFF) % (old(src.regVal) & 0xFFFFFFFF)) & 0xFFFFFFFF
        ensures NonNULLPtr(old(dst.regType)) || Ptr_or_NULL(old(src.regType)) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Mod32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        // Note: If the divisor is immediate and is zero, it violates the safety properties
        requires srcImm != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == if srcImm & 0xFFFFFFFF == 0
                        then old(dst.regVal) & 0xFFFFFFFF
                        else ((old(dst.regVal)  & 0xFFFFFFFF) % (srcImm & 0xFFFFFFFF)) & 0xFFFFFFFF
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)

    // The signed modulo definition in eBPF ISA: dst % src = dst - src * trunc(dst / src)                                                 
    ghost method {:axiom} SMod32_REG(dst: RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==>
                    dst.regVal == if twocom2Abs32Bit(old(src.regVal)) == 0
                        then old(dst.regVal) & 0xFFFFFFFF
                        else signMod32Bit((old(dst.regVal) & 0xFFFFFFFF), (old(src.regVal) & 0xFFFFFFFF))
        ensures NonNULLPtr(old(dst.regType)) || NonNULLPtr(old(src.regType)) ==> unknownBv32(dst.regVal)

    // Note: If the divisor is immediate and is zero, it violates the safety properties
    ghost method {:axiom} SMod32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        // Note: If the divisor is immediate and is zero, it violates the safety properties
        requires srcImm != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == if twocom2Abs32Bit(srcImm) == 0
                        then old(dst.regVal) & 0xFFFFFFFF
                        else signMod32Bit((old(dst.regVal) & 0xFFFFFFFF), (srcImm & 0xFFFFFFFF))
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Bvor32_REG(dst: RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==>
                    dst.regVal == (old(dst.regVal) & 0xFFFFFFFF) | (old(src.regVal) & 0xFFFFFFFF)
        ensures NonNULLPtr(old(dst.regType)) && NonNULLPtr(old(src.regType)) ==> unknownBv32(dst.regVal)
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && (old(src.regVal) & 0xFFFFFFFF) == 0xFFFFFFFF) ==> dst.regVal == 0xFFFFFFFF
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && (old(src.regVal) & 0xFFFFFFFF) != 0xFFFFFFFF) ==> unknownBv32(dst.regVal)
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && (old(dst.regVal) & 0xFFFFFFFF) == 0xFFFFFFFF) ==> dst.regVal == 0xFFFFFFFF
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && (old(dst.regVal) & 0xFFFFFFFF) != 0xFFFFFFFF) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Bvor32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == (old(dst.regVal) & 0xFFFFFFFF) | (srcImm & 0xFFFFFFFF)
        ensures NonNULLPtr(old(dst.regType)) && ((old(dst.regVal) & 0xFFFFFFFF) == 0xFFFFFFFF) ==> dst.regVal == 0xFFFFFFFF
        ensures NonNULLPtr(old(dst.regType)) && ((old(dst.regVal) & 0xFFFFFFFF) != 0xFFFFFFFF) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Bvand32_REG(dst: RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==>
                    dst.regVal == (old(dst.regVal) & 0xFFFFFFFF) & (old(src.regVal) & 0xFFFFFFFF)
        ensures NonNULLPtr(old(dst.regType)) && Ptr_or_NULL(old(src.regType)) ==> unknownBv32(dst.regVal)
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && (old(src.regVal) & 0xFFFFFFFF) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && (old(src.regVal) & 0xFFFFFFFF) != 0) ==> unknownBv32(dst.regVal)
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && (old(dst.regVal) & 0xFFFFFFFF) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && (old(dst.regVal) & 0xFFFFFFFF) != 0) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Bvand32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == (old(dst.regVal) & 0xFFFFFFFF) & (srcImm & 0xFFFFFFFF)
        ensures NonNULLPtr(old(dst.regType)) && (srcImm & 0xFFFFFFFF) == 0 ==> dst.regVal == 0
        ensures NonNULLPtr(old(dst.regType)) && (srcImm & 0xFFFFFFFF) != 0 ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Bvlshr32_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> (
            if this.allow_ptr_leak
                then (dst.regType != NULL && dst.regType != UNINT && src.regType == SCALAR)
                else (dst.regType == SCALAR && src.regType == SCALAR)
        )
        requires src.regVal < 32
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == (old(dst.regVal) & 0xFFFFFFFF) >> ((old(src.regVal) & 0x1F) as bv5)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Bvlshr32_IMM(dst: RegState, srcImm: bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        requires srcImm < 32
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == (old(dst.regVal) & 0xFFFFFFFF) >> ((srcImm & 0x1F) as bv5)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Bvashr32_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> (
            if this.allow_ptr_leak
                then (dst.regType != NULL && dst.regType != UNINT && src.regType == SCALAR)
                else (dst.regType == SCALAR && src.regType == SCALAR)
        )
        requires src.regVal < 32
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == signShift32Bit((old(dst.regVal) & 0xFFFFFFFF), (old(src.regVal) & 0x1F))
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Bvashr32_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        requires srcImm < 32
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == signShift32Bit((old(dst.regVal) & 0xFFFFFFFF), (srcImm & 0x1F))
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Bvshl32_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> (
            if this.allow_ptr_leak
                then (dst.regType != NULL && dst.regType != UNINT && src.regType == SCALAR)
                else (dst.regType == SCALAR && src.regType == SCALAR)
        )
        requires src.regVal < 32
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == ((old(dst.regVal) & 0xFFFFFFFF) << ((old(src.regVal) & 0x1F) as bv5)) & 0xFFFFFFFF
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)

    ghost method {:axiom} Bvshl32_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        requires srcImm < 32
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == ((old(dst.regVal) & 0xFFFFFFFF) << ((srcImm & 0x1F) as bv5)) & 0xFFFFFFFF
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)


    ghost method {:axiom} Bvxor32_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==> 
                    dst.regVal == (old(dst.regVal) & 0xFFFFFFFF) ^ (old(src.regVal) & 0xFFFFFFFF)
        ensures (NonNULLPtr(old(dst.regType)) || NonNULLPtr(old(src.regType))) && old(dst.regNo) != old(src.regNo) ==> unknownBv32(dst.regVal)
        ensures (NonNULLPtr(old(dst.regType)) || NonNULLPtr(old(src.regType))) && old(dst.regNo) == old(src.regNo) ==> dst.regVal == 0

    ghost method {:axiom} Bvxor32_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == (old(dst.regVal) & 0xFFFFFFFF) ^ (srcImm & 0xFFFFFFFF)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv32(dst.regVal)



    //////////////////////////////// 64-bit Arithmetic Operations ////////////////////////////////



    ghost method {:axiom} Neg64(dst:RegState, src:RegState)
        requires type_check_single_src_operand(dst)
        requires dst.regNo != R10
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == !old(dst.regVal)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv64(dst.regVal)

    ghost method {:axiom} Bv2be64(dst:RegState, src:RegState)
        requires type_check_single_src_operand(dst)
        requires dst.regNo != R10
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == byteswapN(old(dst.regVal), 0, 8)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv64(dst.regVal)

    ghost method {:axiom} Bv2le64(dst:RegState, src:RegState)
        requires type_check_single_src_operand(dst)
        requires dst.regNo != R10
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo) 
        ensures old(dst.regType) == SCALAR ==> dst.regVal == old(dst.regVal)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv64(dst.regVal)

    ghost method {:axiom} Bv2swap64(dst:RegState, src:RegState)
        requires type_check_single_src_operand(dst)
        requires dst.regNo != R10
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == byteswapN(old(dst.regVal), 0, 8)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv64(dst.regVal)

    ghost method {:axiom} Mov64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires src.regType != UNINT
        //
        modifies dst
        ensures dst.regType == old(src.regType)
        ensures dst.mapFd == old(src.mapFd)
        ensures dst.memId == old(src.memId)
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
        requires type_check_single_src_operand(src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(src.regType) == SCALAR ==>
                    dst.regVal == if ((old(src.regVal) & 0x0000000000000080) != 0)
                        then old(src.regVal) | 0xFFFFFFFFFFFFFF00
                        else old(src.regVal) & 0x00000000000000FF
        ensures NonNULLPtr(old(src.regType)) ==> unknownBv64(dst.regVal)

    ghost method {:axiom} Mov64SX16(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires type_check_single_src_operand(src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(src.regType) == SCALAR ==>
                    dst.regVal == if ((old(src.regVal) & 0x0000000000008000) != 0)
                        then old(src.regVal) | 0xFFFFFFFFFFFF0000
                        else old(src.regVal) & 0x000000000000FFFF
        ensures NonNULLPtr(old(src.regType)) ==> unknownBv64(dst.regVal)

    ghost method {:axiom} Mov64SX32(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires type_check_single_src_operand(src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(src.regType) == SCALAR ==>
                    dst.regVal == if ((old(src.regVal) & 0x0000000080000000) != 0)
                        then old(src.regVal) | 0xFFFFFFFF00000000
                        else old(src.regVal) & 0x00000000FFFFFFFF
        ensures NonNULLPtr(old(src.regType)) ==> unknownBv64(dst.regVal)

    // TODO: on other memories: context, map, ...
    // <scalar, scalar> -> scalar
    // <scalar, pointer> -> pointer
    // <pointer, scalar> -> pointer
    // <pointer, pointer> -> scalar
    //
    // TODO: bypass_spec_v1
    // SCALAR+SCALAR
    // STACK+SCALAR || SCALAR+STACK if bypass_spec_v1
    // TODO: other memory types
    ghost method {:axiom} Add64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        //
        requires enable_org ==> (
                    // TODO
                    (dst.regType == SCALAR && src.regType == SCALAR) ||
                    (bypass_spec_v1 && ((dst.regType == STACKMEM && src.regType == SCALAR) || (dst.regType == SCALAR && src.regType == STACKMEM)))
        )
        //
        requires !enable_org ==> (
            dst.regType != NULL && dst.regType != UNINT &&
            src.regType != NULL && src.regType != UNINT
        )
        //
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == if NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR) then old(dst.regType)
                               else if NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR) then old(src.regType)
                               // <pointer, pointer> or <scalar, scalar>
                               else SCALAR
        //
        ensures dst.mapFd == if isMapPtr(old(dst.regType)) then old(dst.mapFd)
                                else if isMapPtr(old(src.regType)) then old(src.mapFd)
                                else -1
        ensures dst.memId == if NonNULLPtr(old(dst.regType)) then old(dst.memId)
                                else if NonNULLPtr(old(src.regType)) then old(src.memId)
                                else -1
        //
        ensures if NonNULLPtr(old(dst.regType)) && NonNULLPtr(old(src.regType))
                    then unknownBv64(dst.regVal)
                    // <ptr, scalar> <scalar, scalar> <scalar, ptr>
                    else dst.regVal == old(dst.regVal) + old(src.regVal)

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
        ensures dst.memId == old(dst.memId)
        ensures dst.regVal == old(dst.regVal) + srcImm

    // TODO: on other memories: context, map, ...
    ghost method {:axiom} Sub64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        // Must exist as below precond uses !=
        // ??? requires dst.regType != UNINT && src.regType != UNINT
        // SCALAR-SCALAR; PTR-PTR; PTR(not stack)-SCALAR
        // Note: (1) STACK-scalar is forbidden as JIT cannot handle it while STACK-STACK is allowed
        //       (2) ptr-scalar is allowed in all priv while ptr-ptr is only allowed with allow_ptr_leak
        //       (3) ptr-ptr can be two different ptr types
        requires enable_org ==> (
            (dst.regType == SCALAR && src.regType == SCALAR)
            ||
            (NonNULLPtr(dst.regType) && src.regType == SCALAR)
            ||
            // Discussion: can two pointer subtraction really leak pointer?
            (allow_ptr_leak && NonNULLPtr(dst.regType) && NonNULLPtr(src.regType))
            // No scalar - pointer, which leads to meaning numbers
        )
        //
        modifies dst
        ensures dst.regNo == old(dst.regNo)
        // The res type is ptr only when ptr-scalar, otherwise (ptr-ptr, scalar-scalar) it's scalar
        ensures dst.regType == if NonNULLPtr(old(dst.regType)) && old(src.regType) == SCALAR then old(dst.regType)
                                else SCALAR
        ensures dst.mapFd == if isMapPtr(old(dst.regType)) && old(src.regType) == SCALAR then old(dst.mapFd)
                                else -1
        ensures dst.memId == if NonNULLPtr(old(dst.regType)) && old(src.regType) == SCALAR then old(dst.memId)
                                else -1
        // Discussion: we cannot subtract between two different pointers, meaningless to subtract their offset
        ensures if (old(dst.regType) == SCALAR) && NonNULLPtr(old(src.regType)) // <scalar, ptr>
                    then unknownBv64(dst.regVal)
                // <ptr-mem1, ptr-mem2>
                else if NonNULLPtr(old(dst.regType)) && NonNULLPtr(old(src.regType)) && !same_mem(dst, src)
                    then unknownBv64(dst.regVal)
                // <ptr, scalar> <ptr-mem1, ptr-mem1> <scalar, scalar>
                else dst.regVal == old(dst.regVal) - old(src.regVal)

    // TODO: on other memories: context, map, ...
    ghost method {:axiom} Sub64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType != UNINT && dst.regType != STACKMEM
        requires !enable_org ==> dst.regType != UNINT && dst.regType != NULL
        //
        modifies dst
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == if NonNULLPtr(old(dst.regType)) then old(dst.regType)
                                else SCALAR
        ensures dst.mapFd == if isMapPtr(old(dst.regType)) then old(dst.mapFd)
                                else -1
        ensures dst.memId == if NonNULLPtr(old(dst.regType)) then old(dst.memId)
                                else -1
        ensures dst.regVal == old(dst.regVal) - srcImm

    ghost method {:axiom} Mul64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==> dst.regVal == old(dst.regVal) * old(src.regVal)
        //
        ensures NonNULLPtr(old(dst.regType)) && NonNULLPtr(old(src.regType)) ==> unknownBv64(dst.regVal)
        //
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && old(src.regVal) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && old(src.regVal) != 0) ==> unknownBv64(dst.regVal)
        //
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && old(dst.regVal) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && old(dst.regVal) != 0) ==> unknownBv64(dst.regVal)

    ghost method {:axiom} Mul64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == old(dst.regVal) * srcImm
        ensures NonNULLPtr(old(dst.regType)) && (srcImm == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(dst.regType)) && (srcImm != 0) ==> unknownBv64(dst.regVal)

    // Note: If BPF program execution would result in division by zero, the destination register is instead set to zero.
    ghost method {:axiom} Div64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org  ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==> 
                    dst.regVal == if old(src.regVal) == 0 then 0x0
                                  else old(dst.regVal) / old(src.regVal)
        //
        ensures NonNULLPtr(old(dst.regType)) && NonNULLPtr(old(src.regType)) ==> unknownBv64(dst.regVal)
        //
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && old(src.regVal) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && old(src.regVal) != 0) ==> unknownBv64(dst.regVal)
        //
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && old(dst.regVal) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && old(dst.regVal) != 0) ==> unknownBv64(dst.regVal)

    // Note: In ALU64 unsigned division, IMM is sign extended from 32 to 64 bits and then interpreted as a 64-bit unsigned value.
    ghost method {:axiom} Div64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        // Note: If the divisor is immediate and is zero, it violates the safety properties
        requires srcImm != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == if signExtend32To64(srcImm) == 0 then 0x0
                                  else old(dst.regVal) / signExtend32To64(srcImm)
        //
        ensures NonNULLPtr(old(dst.regType)) && (signExtend32To64(srcImm) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(dst.regType)) && (signExtend32To64(srcImm) != 0) ==> unknownBv64(dst.regVal)

    ghost method {:axiom} SDiv64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org  ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==>
                    dst.regVal == if twocom2Abs64Bit(old(src.regVal)) == 0 then 0x0
                                  else signDiv64Bit(old(dst.regVal), old(src.regVal))
        //
        ensures NonNULLPtr(old(dst.regType)) && NonNULLPtr(old(src.regType)) ==> unknownBv64(dst.regVal)
        //
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && twocom2Abs64Bit(old(src.regVal)) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && twocom2Abs64Bit(old(src.regVal)) != 0) ==> unknownBv64(dst.regVal)
        //
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && twocom2Abs64Bit(old(dst.regVal)) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && twocom2Abs64Bit(old(dst.regVal)) != 0) ==> unknownBv64(dst.regVal)

    // Note: In ALU64 signed division, IMM is sign extended from 32 to 64 bits and then interpreted as a 64-bit signed value.
    //       If the divisor is immediate and is zero, it violates the safety properties
    ghost method {:axiom} SDiv64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        // Note: If the divisor is immediate and is zero, it violates the safety properties
        requires srcImm != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == if signExtend32To64(srcImm) == 0 then 0x0
                                  else signDiv64Bit(old(dst.regVal), signExtend32To64(srcImm))
        //
        ensures NonNULLPtr(old(dst.regType)) && (signExtend32To64(srcImm) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(dst.regType)) && (signExtend32To64(srcImm) != 0) ==> unknownBv64(dst.regVal)

    // Note: If execution would result in modulo by zero in ALU64, the value of the destination register is unchanged.
    // TODO: prove
    // a % n = a - n * trunc(a / n)
    ghost method {:axiom} Mod64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org  ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==>
                    dst.regVal == if old(src.regVal) == 0x0 then old(dst.regVal)
                                  else old(dst.regVal) % old(src.regVal)
        //
        ensures NonNULLPtr(old(dst.regType)) || NonNULLPtr(old(src.regType)) ==> unknownBv64(dst.regVal)

    // Note: In ALU64 unsigned modulo, IMM is sign extended from 32 to 64 bits and then interpreted as a 64-bit unsigned value.
    //       If the divisor is immediate and is zero, it violates the safety properties
    ghost method {:axiom} Mod64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        // Note: If the divisor is immediate and is zero, it violates the safety properties
        requires srcImm != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == if signExtend32To64(srcImm) == 0x0 then old(dst.regVal)
                                  else old(dst.regVal) % signExtend32To64(srcImm)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv64(dst.regVal)

    // Signed modulo MUST use truncated division： a % n = a - n * trunc(a / n)
    ghost method {:axiom} SMod64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org  ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==>
                    dst.regVal == if twocom2Abs64Bit(old(src.regVal)) == 0 then old(dst.regVal)
                                  else signMod64Bit(old(dst.regVal), old(src.regVal))
        //
        ensures NonNULLPtr(old(dst.regType)) || NonNULLPtr(old(src.regType)) ==> unknownBv64(dst.regVal)


    // Note: In ALU64 signed modulo, IMM is sign extended from 32 to 64 bits and then interpreted as a 64-bit signed value.
    //       If the divisor is immediate and is zero, it violates the safety properties
    ghost method {:axiom} SMod64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        // Note: If the divisor is immediate and is zero, it violates the safety properties
        requires srcImm != 0
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == if signExtend32To64(srcImm) == 0 then old(dst.regVal)
                                  else signMod64Bit(old(dst.regVal), signExtend32To64(srcImm))
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv64(dst.regVal)

    ghost method {:axiom} Bvor64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==>
                    dst.regVal == old(dst.regVal) | old(src.regVal)
        //
        ensures NonNULLPtr(old(dst.regType)) && NonNULLPtr(old(src.regType)) ==> unknownBv64(dst.regVal)
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && old(src.regVal) == 0xFFFF_FFFF_FFFF_FFFF) ==> dst.regVal == 0xFFFF_FFFF_FFFF_FFFF
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && old(src.regVal) != 0xFFFF_FFFF_FFFF_FFFF) ==> unknownBv64(dst.regVal)
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && old(dst.regVal) == 0xFFFF_FFFF_FFFF_FFFF) ==> dst.regVal == 0xFFFF_FFFF_FFFF_FFFF
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && old(dst.regVal) != 0xFFFF_FFFF_FFFF_FFFF) ==> unknownBv64(dst.regVal)

    ghost method {:axiom} Bvor64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == (old(dst.regVal) | srcImm)
        //
        ensures NonNULLPtr(old(dst.regType)) && (srcImm == 0xFFFF_FFFF_FFFF_FFFF) ==> dst.regVal == 0xFFFF_FFFF_FFFF_FFFF
        ensures NonNULLPtr(old(dst.regType)) && (srcImm != 0xFFFF_FFFF_FFFF_FFFF) ==> unknownBv64(dst.regVal)

    ghost method {:axiom} Bvand64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==>
                    dst.regVal == old(dst.regVal) & old(src.regVal)
        //
        ensures NonNULLPtr(old(dst.regType)) && NonNULLPtr(old(src.regType)) ==> unknownBv64(dst.regVal)
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && old(src.regVal) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(dst.regType)) && (old(src.regType) == SCALAR && old(src.regVal) != 0) ==> unknownBv64(dst.regVal)
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && old(dst.regVal) == 0) ==> dst.regVal == 0
        ensures NonNULLPtr(old(src.regType)) && (old(dst.regType) == SCALAR && old(dst.regVal) != 0) ==> unknownBv64(dst.regVal)

    ghost method {:axiom} Bvand64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==> dst.regVal == old(dst.regVal) & srcImm
        ensures NonNULLPtr(old(dst.regType)) && srcImm == 0 ==> dst.regVal == 0
        ensures NonNULLPtr(old(dst.regType)) && srcImm != 0 ==> unknownBv64(dst.regVal)

    ghost method {:axiom} Bvlshr64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> (
            if this.allow_ptr_leak
                then (dst.regType != UNINT && dst.regType != NULL && src.regType == SCALAR)
                else (dst.regType == SCALAR && src.regType == SCALAR)
        )
        requires src.regVal < 64
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == old(dst.regVal) >> ((old(src.regVal) & 0x3F) as bv6)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv64(dst.regVal)

    ghost method {:axiom} Bvlshr64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        requires srcImm < 64
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == old(dst.regVal) >> ((srcImm & 0x3F) as bv6)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv64(dst.regVal)

    ghost method {:axiom} Bvashr64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> (
            if this.allow_ptr_leak
                then (dst.regType != UNINT && dst.regType != NULL && src.regType == SCALAR)
                else (dst.regType == SCALAR && src.regType == SCALAR)
        )
        requires src.regVal < 64
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == signShift64Bit(old(dst.regVal), old(src.regVal))
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv64(dst.regVal)

    ghost method {:axiom} Bvashr64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        requires srcImm < 64
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == signShift64Bit(old(dst.regVal), srcImm)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv64(dst.regVal)

    ghost method {:axiom} Bvshl64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> (
            if this.allow_ptr_leak
                then (dst.regType != UNINT && dst.regType != NULL && src.regType == SCALAR)
                else (dst.regType == SCALAR && src.regType == SCALAR)
        )
        requires src.regVal < 64
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == old(dst.regVal) << ((old(src.regVal) & 0x3F) as bv6)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv64(dst.regVal)
    
    ghost method {:axiom} Bvshl64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        requires srcImm < 64
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == old(dst.regVal) << ((srcImm & 0x3F) as bv6)
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv64(dst.regVal)

    ghost method {:axiom} Bvxor64_REG(dst:RegState, src:RegState)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR && src.regType == SCALAR
        requires !enable_org ==> beacon_type_check2(dst, src)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR && old(src.regType) == SCALAR ==>
                    dst.regVal == old(dst.regVal) ^ old(src.regVal)
        //
        ensures (NonNULLPtr(old(dst.regType)) || NonNULLPtr(old(src.regType))) && old(dst.regNo) != old(src.regNo) ==> unknownBv64(dst.regVal)
        ensures (NonNULLPtr(old(dst.regType)) || NonNULLPtr(old(src.regType))) && old(dst.regNo) == old(src.regNo) ==> dst.regVal == 0

    ghost method {:axiom} Bvxor64_IMM(dst:RegState, srcImm:bv64)
        requires dst.regNo != R10
        requires enable_org ==> dst.regType == SCALAR
        requires !enable_org ==> beacon_type_check1(dst)
        //
        modifies dst
        ensures dst.regType == SCALAR
        ensures dst.regNo == old(dst.regNo)
        ensures old(dst.regType) == SCALAR ==>
                    dst.regVal == old(dst.regVal) ^ srcImm
        ensures NonNULLPtr(old(dst.regType)) ==> unknownBv64(dst.regVal)

    //////////////////////////// Stack memory ///////////////////////////

    ghost predicate stack_writable(memReg: RegState, off: int64, size: int64)
        requires 0 <= memReg.memId < this.stackSlotTypes.Length
        reads this, this.stackSlotTypes, this.stackSlotTypes[memReg.memId]
        reads memReg
        {
            memReg.regType == STACKMEM
            &&
            this.stackSlotTypes[memReg.memId].Length == 512
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
                !allow_ptr_leak && size != 8 ==>
                            var curOff := (bv64ToInt64(memReg.regVal) + off)+512;
                            forall i | curOff <= i < curOff + size :: (ScalarTypes(stackSlotTypes[memReg.memId][i]) ||
                                                                        stackSlotTypes[memReg.memId][i] == UNINT)
                            // (stackSlotTypes[memReg.memId][curOff] == SCALAR || stackSlotTypes[memReg.memId][curOff] == UNINT)
            )
            // TODO cannot overwrite STACK_DYNPTR and STACK_ITERN
        }

    // Note: the stack memory in eBPF VM is little endian
    // *(size *) (dst + offset) = src
    // MEM_STX_B, MEM_STX_H, MEM_STX_W, MEM_STX_DW, MEM_ST_B, MEM_ST_H, MEM_ST_W, MEM_ST_DW
    // 
    ghost method {:axiom} Store_STACKMEM(dst:RegState, src:RegState, off:int64, size:int64)
        requires src.regType != UNINT
        //
        requires 0 <= dst.memId < 8 == this.stacks.Length == this.stackSlotTypes.Length == this.idMetas.Length
        requires 512 == this.stacks[dst.memId].Length == this.stackSlotTypes[dst.memId].Length
        requires 64 == this.idMetas[dst.memId].Length
        requires stack_writable(dst, off, size)
        // cannot store the stack pointer of current frame to the parent stacks
        requires src.regType == STACKMEM ==> src.memId <= r10.memId
        //
        // Original: Check_stack_write_fixed_off:4546 : Cannot partially store a ptr from src reg, 
        // Change: allow partially store a pointer to stack as SCALAR
        requires !allow_ptr_leak && size != 8 ==> src.regType == SCALAR
        // ?? requires size != 8 ==> src.regType == SCALAR
        //
        modifies this.stacks[dst.memId], this.stackSlotTypes[dst.memId], this.idMetas[dst.memId]
        //
        // Update the affected stack values while keeping the unchanged ones
        ensures var start := (bv64ToInt64(dst.regVal) + off + 512);
                (forall i | start <= i < (start + size) :: this.stacks[dst.memId][i] == getRegByteX(src.regVal, i- start))
                &&
                (forall j | ((0 <= j < 512) && !(0 <= start <= j < start + size <= 512)) :: this.stacks[dst.memId][j] == old(this.stacks[dst.memId][j]))
        //
        // Update the affected stack types while keeping the unchanged ones
        ensures var start := (bv64ToInt64(dst.regVal) + off + 512);
                // If partially overwrite a ptr slot, the tyeps of unwritten bytes within the 8-byte slot should be changed as well
                var new_size := if !Ptr_or_NULL(old(this.stackSlotTypes[dst.memId][start])) then size else 8;
                //
                ((isMapPtr(src.regType) && size == 8) ==> this.idMetas[dst.memId][start/8] == src.mapFd)
                &&
                ((Ptr_or_NULL(src.regType) && !isMapPtr(src.regType) && size == 8) ==> this.idMetas[dst.memId][start/8] == src.memId)
                // && TODO: keep other parts of idMeta unchanged
                &&
                (forall j | (0 <= j < start || (start + new_size) <= j < 512) :: (this.stackSlotTypes[dst.memId][j] == old(this.stackSlotTypes[dst.memId][j])))
                &&
                (forall i | (0 <= start <= i < (start + new_size) <= 512) :: (this.stackSlotTypes[dst.memId][i] == if size == 8 then old(src.regType) else SCALAR))
    

    ghost predicate stack_readable(memReg: RegState, off: int64, size: int64)
        requires 0 <= memReg.memId < this.stackSlotTypes.Length
        reads this, this.stackSlotTypes, this.stackSlotTypes[memReg.memId]
        reads memReg
        {
            memReg.regType == STACKMEM                                         
            &&
            this.stackSlotTypes[memReg.memId].Length == 512
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
            // All slots are initialized if no allow_ptr_leak
            (var curOff := bv64ToInt64(memReg.regVal) + off + 512;
                    !this.allow_ptr_leak ==> (forall i | curOff <= i < (curOff + size) :: this.stackSlotTypes[memReg.memId][i] != UNINT))
            &&
            // Partially loading a pointer
            (!allow_ptr_leak && size != 8 ==>
                var curOff := bv64ToInt64(memReg.regVal) + off + 512;
                forall i | curOff <= i < curOff+size :: ScalarTypes(this.stackSlotTypes[memReg.memId][i]))
        }

    // dst = *(unsigned size *) (src + offset)
    // MEM_LDX_B, MEM_LDX_H, MEM_LDX_W, MEM_LDX_DW, MEMSX_LDX_S8, MEMSX_LDX_S16, MEMSX_LDX_S32
    //
    ghost method {:axiom} Load_STACKMEM(dst:RegState, src:RegState, off:int64, size:int64, signExt:bool)
        requires dst.regNo != R10
        //
        requires 0 <= src.memId < 8 == this.stacks.Length == this.stackSlotTypes.Length == this.idMetas.Length
        requires 512 == this.stacks[src.memId].Length == this.stackSlotTypes[src.memId].Length
        requires 64 == this.idMetas[src.memId].Length
        requires stack_readable(src, off, size)
        //
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        //
        ensures var curOff := bv64ToInt64(old(src.regVal))+off+512;
                var stackNo := old(src.memId);
                (
                    dst.regType == if size == 8 && Ptr_or_NULL(this.stackSlotTypes[stackNo][curOff])
                                    then this.stackSlotTypes[stackNo][curOff]
                                    else SCALAR
                )
                &&
                (
                    isMapPtr(this.stackSlotTypes[stackNo][curOff]) && size == 8 ==>
                        dst.mapFd == this.idMetas[stackNo][curOff/8]
                )
                &&
                (
                    (Ptr_or_NULL(this.stackSlotTypes[stackNo][curOff]) && !isMapPtr(this.stackSlotTypes[stackNo][curOff]) && size == 8) ==>
                        dst.memId == this.idMetas[stackNo][curOff/8]
                )
        // Note: Non-64-bit unsigned loads zero out the upper bits, while non-64-bit signed loads extend the sign bit to 64-bit width,
        //       for example, assume the byte at (r10 -8) is 0xff, then:
        //       r2 = *(s8 *)(r10 -8) ==> r2 == -1; 
        //       r2 = *(u8 *)(r10 -8) ==> r2 == 255
        ensures var curOff := bv64ToInt64(old(src.regVal)) + off + 512;
                var stackNo := old(src.memId);
                dst.regVal == if signExt
                            then signExtend64(loadNbytesMem(this.stacks[stackNo], curOff, size), size*8)
                            else loadNbytesMem(this.stacks[stackNo], curOff, size)

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
        /*
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
        */

    ghost method {:axiom} Load_CTXMEM(dst:RegState, src:RegState, off:int64, size:int64, signExt:bool)
        requires dst.regNo != R10
        requires src.regType == CTXMEM
        requires this.context.Length == 65536
        requires var curOff := (bv64ToInt64(src.regVal) + off);
                 0 <= curOff < (curOff +size) <= 65536
        requires context_access_safe(this.progType, (bv64ToInt64(src.regVal) + off), size, READ, this.attachType, this.priv)
        //
        modifies dst, mutableVars
        //
        ensures dst.regNo == old(dst.regNo)
        // ensures dst.regType == context_load_type(this.progType, (bv64ToInt64(old(src.regVal)) + off), size, READ, this.attachType, this.priv)
        ensures context_load_type(dst.regType, this.progType, (bv64ToInt64(old(src.regVal)) + off), size, READ, this.attachType, this.priv)
        // Since context memory does not contain two or more the same ptr types, so just assign memId as 1, even if it's scalar
        // ensures dst.memId == 0 // TODO
        ensures if context_load_type(dst.regType, this.progType, (bv64ToInt64(old(src.regVal)) + off), size, READ, this.attachType, this.priv) &&
                    dst.regType == SCALAR
                    then unknownBv(dst.regVal, size) && dst.memId == 0
                    else dst.regVal == 0         && dst.memId == old(mutableVars.idCounter) && mutableVars.idCounter == old(mutableVars.idCounter) + 1

        // loadNbytesMem(this.context, (bv64ToInt64(old(src.regVal)) + off), size) // TODO

    ghost method {:axiom} AtomicLS_CTXMEM(dst:RegState, src:RegState, off:int64, size:int64, isFetch: bool)
        requires false

    // Load_imm64
    ghost method {:axiom} Load_Imm64(dst:RegState, imm:bv64)
        requires dst.regNo != R10
        //
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == SCALAR
        ensures dst.regVal == imm

    //////////////////////////// PTR_TO_FUNC ///////////////////////////

    // BPF_RAW_INSN(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_2, BPF_PSEUDO_FUNC, 0, 6),
    // Load functions as callback functions
    ghost method {:axiom} Load_PSEUDOFUNC(dst:RegState, imm:bv64)
        // TODO: requires the offset is the entry of a function
        // find_subprog
        // some BTF checks
        requires dst.regNo != R10
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == PTR_TO_FUNC
        ensures dst.regVal == imm // the relative insn offset to the PSEUDOFUNC


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


    ghost method {:axiom} Load_MAPFD(dst:RegState, mapFd:int64) 
        requires dst.regNo != R10
        // Note: src == BPF_PSEUDO_MAP_FD, but we do not check instruction format
        // Note: mapFd should be checked, but it's kernel runtime info,
        //       we cannot check it and thus assume it is correct.
        requires 0 <= mapFd < this.maps.Length
        //
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == MAP_PTR
        // dst.regVal is not used
        ensures dst.mapFd == mapFd
        // Discussion: we assume each map has the unique ID (i.e., mapFd) although mapFd can be duplicated with dup2()
        ensures dst.memId == mapFd

    // Note: we assume all maps used in this program are included in the fd_array, orderred by their fds
    //       so, we can use mapIdx as the mapFd
    ghost method {:axiom} Load_MAPFDIDX(dst:RegState, mapIdx:int64)
        requires dst.regNo != R10
        // src == BPF_PSEUDO_MAP_IDX
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == MAP_PTR
        ensures dst.mapFd == mapIdx
        ensures dst.memId == mapIdx

    // TODO: BTF related
    ghost predicate requires_on_map_ptr_load(memReg: RegState, off: int64, size: int64)
        {
            false
        }
    
    ghost method {:axiom} Load_MAPMEM(dst:RegState, src:RegState, off:int64, size:int64, signExt:bool)
        // check_ptr_to_map_access
        // requires btf_vmlinux configured with CONFIG_DEBUG_INFO_BTF
        // requires allowed on specific map types
        // requires allow_ptr_leak
        // requires read-only
        // requires offset >= 0
        // requires 
        requires bpf_map_btf(off, size)
        // TODO: needs to know the BTF
        // TODO: memid
        requires false
        //
        // ensures dst type == SCALAR or PTR_TO_BTF_ID
        // parse all BTF into predicates

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
        ensures unknownBv(dst.regVal, size)
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
        ensures isFetch  ==> src.regType == SCALAR && unknownBv(src.regVal, size)
    
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
        ensures unknownBv(this.r0.regVal, size)

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
        ensures unknownBv(dst.regVal, size)
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
                 0 <= start < start + size <= upper_bound < 0xffff
        //
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == SCALAR
        ensures unknownBv(dst.regVal, size)
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
                 0 <= start < start + size <= upper_bound < 0xffff
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
        ensures unknownBv(dst.regVal, size)
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
        ensures unknownBv(dst.regVal, size)
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
        ensures unknownBv(dst.regVal, size)
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
    // TODO: translator

    // HARD-TODO: when a ptr_or_null -> null, it becomes scalar ==> replace NULL with SCALAR
    
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
                ||
                (
                    (dst.memId == src.memId)
                    &&
                    (
                        (dst.regType == PTR_TO_MAP_KEY)
                        ||
                        (dst.regType == PTR_TO_MAP_VALUE)
                        ||
                        (dst.regType == PTR_TO_SOCKET)
                        ||
                        (dst.regType == PTR_TO_SOCK_COMMON)
                        ||
                        (dst.regType == PTR_TO_TCP_SOCK)
                        ||
                        (dst.regType == PTR_TO_XDP_SOCK)
                    )
                )
            )
        }

    ghost predicate isPtrWithinBound(reg: RegState)
        reads reg, this, this.maps
        reads if (reg.regType == PTR_TO_MAP_KEY || reg.regType == PTR_TO_MAP_VALUE) then {this.maps[reg.mapFd]} else {}
        requires reg.regType == PTR_TO_MAP_KEY || reg.regType == PTR_TO_MAP_VALUE ==> 0 <= reg.mapFd < this.maps.Length
        {
            var cur_off := bv64ToInt64(reg.regVal);
            match reg.regType {
                case STACKMEM   => -512 <= cur_off <= -1
                // TODO:
                // case CTXMEM     => 
                // case MAP_PTR    => 
                case PTR_TO_MAP_KEY => 0 <= cur_off < this.maps[reg.mapFd].keySize
                case PTR_TO_MAP_VALUE   => 0 <= cur_off < this.maps[reg.mapFd].valSize
                case PTR_TO_PACKET      => 0 <= cur_off < packet_data_range
                case PTR_TO_PACKET_META => 0 <= cur_off < packet_meta_range
                case PTR_TO_PACKET_END  => cur_off == 0
                case PTR_TO_FLOW_KEYS   => 0 <= cur_off < 56
                case PTR_TO_SOCKET      => 0 <= cur_off < 80
                case PTR_TO_SOCK_COMMON => 0 <= cur_off < 80
                case PTR_TO_TCP_SOCK    => 0 <= cur_off < 112
                case PTR_TO_XDP_SOCK    => 0 <= cur_off < 4
                case PTR_TO_TP_BUFFER   => false
                case _ => false
            }
        }

    ghost method {:axiom} EXIT()
        // TODO: check_reference_leak, prepare_func_exit
        // TODO: mark_verifier_state_scratched, update_branch_counts, pop_stack 
        // TODO: Requires on R10 according to function type, program type, and attach type
        //
        // Main function return requirements
        requires r10.memId == 0 ==> r0.regType != UNINT
        requires r10.memId == 0 ==> return_value_correct(r0, this.priv, this.progType, this.attachType)
        // Psuedo functions can return anything except its stack pointer
        requires r10.memId  > 0 ==> if r0.regType == STACKMEM then r0.memId < r10.memId else true
        //
        requires r10.memId > 0 ==>
                    var off := (r10.memId - 1) * 4;
                    0 <= off < off + 4 < regSaver.Length
        //
        // modifies regSaver
        modifies r1, r2, r3, r4, r5, r6, r7, r8, r9, r10
        //
        // Change stack frame
        ensures old(r10.memId) > 0 ==>
                r10.regNo == R10                &&
                r10.regVal == 0                 &&
                r10.regType == STACKMEM         &&
                r10.memId == old(r10.memId) - 1
        //
        // Pop out R6-R9 from the tmp RegState array if its not the main function exit
        ensures old(r10.memId) > 0 ==>
                    var off := (old(r10.memId) - 1) * 4;
                    r6.regNo == regSaver[off].regNo     &&
                    r6.regType == regSaver[off].regType &&
                    r6.regVal == regSaver[off].regVal   &&
                    r6.memId == regSaver[off].memId     &&
                    //
                    r7.regNo == regSaver[off+1].regNo       &&
                    r7.regType == regSaver[off+1].regType   &&
                    r7.regVal == regSaver[off+1].regVal     &&
                    r7.memId == regSaver[off+1].memId       &&
                    //
                    r8.regNo == regSaver[off+2].regNo       &&
                    r8.regType == regSaver[off+2].regType   &&
                    r8.regVal == regSaver[off+2].regVal     &&
                    r8.memId == regSaver[off+2].memId       &&
                    //
                    r9.regNo == regSaver[off+3].regNo       &&
                    r9.regType == regSaver[off+3].regType   &&
                    r9.regVal == regSaver[off+3].regVal     &&
                    r9.memId == regSaver[off+3].memId
        // Reset R1-R5
        ensures old(r10.memId) > 0 ==>
                    r1.regType == UNINT && r2.regType == UNINT && r3.regType == UNINT && r4.regType == UNINT && r5.regType == UNINT &&
                    r1.regNo == R1 && r2.regNo == R2 && r3.regNo == R3 && r4.regNo == R4 && r5.regNo == R5
        // Return the current R0


    // assume (isPtr(dst.regType) && isNonNULLPtr(src.regType)) ==> dst.regType != NULL
    // assume (isNonNULLPtr(dst.regType) && isPtr(src.regType)) ==> src.regType != NULL
    //
    ghost function JEQ64_REG(dst:RegState, src:RegState) :bool
        reads dst, src, this, this.maps
        reads if (dst.regType == PTR_TO_MAP_KEY || dst.regType == PTR_TO_MAP_VALUE) then {this.maps[dst.mapFd]} else {}
        reads if (src.regType == PTR_TO_MAP_KEY || src.regType == PTR_TO_MAP_VALUE) then {this.maps[src.mapFd]} else {}
        //
        requires dst.regType != UNINT
        requires src.regType != UNINT
        requires !allow_ptr_leak ==> (
            (dst.regType == SCALAR && src.regType == SCALAR)
            ||
            (Ptr_or_NULL(dst.regType) && Ptr_or_NULL(src.regType))
        )
        requires dst.regType == PTR_TO_MAP_KEY || dst.regType == PTR_TO_MAP_VALUE ==> 0 <= dst.mapFd < this.maps.Length
        requires src.regType == PTR_TO_MAP_KEY || src.regType == PTR_TO_MAP_VALUE ==> 0 <= src.mapFd < this.maps.Length
        {
            // scalar == scalar
            if dst.regType == SCALAR && src.regType == SCALAR
                then dst.regVal == src.regVal
            // ptr == 0
            else if (Ptr_or_NULL(dst.regType) && src.regType == SCALAR && src.regVal == 0)
                then dst.regType == NULL
                // TODO: Assume dst.regType == SCALAR
            // 0 == ptr
            else if (dst.regType == SCALAR && dst.regVal == 0  && Ptr_or_NULL(src.regType))
                then src.regType == NULL
                // TODO: Assume dst.regType == SCALAR
            
            // ptr == ptr pointing to the same memory, ptr might be null
            else if (Ptr_or_NULL(dst.regType) && Ptr_or_NULL(src.regType) && same_mem(dst, src)) // TODO: same_mem: ptr_or_null.type == ptr.type
                then dst.regVal == src.regVal && dst.regType == src.regType
            
            // ptrs with different types and within their range => not equal
            else if (isPtrWithinBound(dst) && isPtrWithinBound(src))
                then false

            // ptr == ptr pointing to different memory
            // ptr == scalar
            else unknown_bool()

            /*
            // if(ptr == non_null_ptr) ==> if(ptr != NULL)
            else if (isPtr(dst.regType) && isNonNULLPtr(src.regType))
                then dst.regType != NULL
            // if(non_null_ptr == ptr) ==> if(ptr != NULL)
            else if (isNonNULLPtr(dst.regType) && isPtr(src.regType))
                then src.regType != NULL
            // ptr == ptr pointing to different memory
            // ptr == scalar
            else unknown_bool()
            */
        }
    
    ghost function JEQ32_REG(dst:RegState, src:RegState) :bool
        reads this, dst, src
        requires dst.regType != UNINT
        requires src.regType != UNINT
        requires !allow_ptr_leak ==> (
            (dst.regType == SCALAR && src.regType == SCALAR)
            ||
            (Ptr_or_NULL(dst.regType) && Ptr_or_NULL(src.regType))
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
            else if Ptr_or_NULL(dst.regType) && srcImm == 0
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
        reads dst, src, this, this.maps
        reads if (dst.regType == PTR_TO_MAP_KEY || dst.regType == PTR_TO_MAP_VALUE) then {this.maps[dst.mapFd]} else {}
        reads if (src.regType == PTR_TO_MAP_KEY || src.regType == PTR_TO_MAP_VALUE) then {this.maps[src.mapFd]} else {}
        //
        requires dst.regType != UNINT
        requires src.regType != UNINT
        requires !allow_ptr_leak ==> (
            (dst.regType == SCALAR && src.regType == SCALAR)
            ||
            (Ptr_or_NULL(dst.regType) && Ptr_or_NULL(src.regType))
        )
        requires dst.regType == PTR_TO_MAP_KEY || dst.regType == PTR_TO_MAP_VALUE ==> 0 <= dst.mapFd < this.maps.Length
        requires src.regType == PTR_TO_MAP_KEY || src.regType == PTR_TO_MAP_VALUE ==> 0 <= src.mapFd < this.maps.Length
        {
            // scalar == scalar
            if dst.regType == SCALAR && src.regType == SCALAR
                then dst.regVal != src.regVal
            // ptr == 0
            else if (Ptr_or_NULL(dst.regType) && src.regType == SCALAR && src.regVal == 0)
                then dst.regType != NULL
            // 0 == ptr
            else if (dst.regType == SCALAR && dst.regVal == 0  && Ptr_or_NULL(src.regType))
                then src.regType != NULL
            // ptr == ptr pointing to the same memory
            else if (Ptr_or_NULL(dst.regType) && Ptr_or_NULL(src.regType) && same_mem(dst, src))
                then dst.regVal != src.regVal
            
            else if (Ptr_or_NULL(dst.regType) && Ptr_or_NULL(src.regType) && !same_mem(dst, src))
                then (dst.regType != src.regType) || (dst.regType == src.regType && dst.regVal != src.regVal)

            // different pointer types within their bounds -> not equal
            else if (isPtrWithinBound(dst) && isPtrWithinBound(src))
                then true

            /*
            // if(ptr != non_null_ptr) ==> if(ptr == NULL || ptr == ptr_or_null)
            else if (isPtr(dst.regType) && isNonNULLPtr(src.regType))
                then !(dst.regType == NULL) // dst.regType == NULL || isNonNULLPtr(dst.regType)
            // if(non_null_ptr != ptr) ==> if(ptr == NULL || ptr == ptr_or_null)
            else if (isNonNULLPtr(dst.regType) && isPtr(src.regType))
                then src.regType == NULL || isNonNULLPtr(src.regType)
            */

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
            (Ptr_or_NULL(dst.regType) && Ptr_or_NULL(src.regType))
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
            else if Ptr_or_NULL(dst.regType) && srcImm == 0
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
            (Ptr_or_NULL(dst.regType) && Ptr_or_NULL(src.regType))
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
            (Ptr_or_NULL(dst.regType) && Ptr_or_NULL(src.regType))
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
            (Ptr_or_NULL(dst.regType) && Ptr_or_NULL(src.regType))
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
                        // Note: when we know packet_meta_range < x, when checking packet meta access
                        // 0 <= off < of + size <= packet_meta_range, then we cannot know if this condition hold or not,
                        // as we don't know what the lower-bound of packet_meta_range
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
            else if ((dst.regType == SCALAR && src.regType == SCALAR) ||
                     (Ptr_or_NULL(dst.regType) && Ptr_or_NULL(src.regType) && same_mem(dst, src))) then (
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
                    // 32-bit signed imm is sign-extended to 64-bit signed imm
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
        // requires dst.regVal & 0xFFFF_FFFF_0000_0000 == 0
        // requires src.regVal & 0xFFFF_FFFF_0000_0000 == 0
        requires dst.regType != UNINT && src.regType != UNINT
        requires !allow_ptr_leak ==> (
            (dst.regType == SCALAR && src.regType == SCALAR)
            ||
            (Ptr_or_NULL(dst.regType) && Ptr_or_NULL(src.regType))
        )
        {
            if (
                (dst.regType == SCALAR && src.regType == SCALAR)
                ||
                (Ptr_or_NULL(dst.regType) && Ptr_or_NULL(src.regType) && same_mem(dst, src)) //TODO: memid // if (isPtr() && isPtr() && .memid == .memid)
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
        // requires dst.regVal & 0xFFFF_FFFF_0000_0000 == 0
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

    //////////////////////////// Helper calls ///////////////////////////

    // TODO: global pseudo call
    ghost method {:axiom} pseudo_local_call(unknownBv8:bv8)
        // Cap
        requires this.priv
        // Max function depth 8
        requires 0 <= r10.memId < 7
        requires 0 <= r10.memId*4 < r10.memId*4 + 4 <= this.regSaver.Length
        //
        requires 8 == this.stacks.Length == this.stackSlotTypes.Length == this.idMetas.Length
        requires 512 == this.stacks[r10.memId+1].Length == this.stackSlotTypes[r10.memId+1].Length
        // Args are in R1-R5
        modifies r0, r6, r7, r8, r9, r10
        modifies this.regSaver, this.stacks[r10.memId+1]
        // Change stack frame
        ensures r10.regNo == R10        &&
                r10.regType == STACKMEM &&
                r10.regVal == 0         &&
                r10.memId == old(r10.memId) + 1
        // Push the R6-R9 to the tmp RegState array
        ensures var off := old(r10.memId)*4;
                regSaver[off].regNo     == old(r6.regNo) &&
                regSaver[off].regType   == old(r6.regType) &&
                regSaver[off].regVal    == old(r6.regVal) &&
                regSaver[off].memId     == old(r6.memId) &&
                //
                regSaver[off+1].regNo     == old(r7.regNo) &&
                regSaver[off+1].regType   == old(r7.regType) &&
                regSaver[off+1].regVal    == old(r7.regVal) &&
                regSaver[off+1].memId     == old(r7.memId) &&
                //
                regSaver[off+2].regNo     == old(r8.regNo) &&
                regSaver[off+2].regType   == old(r8.regType) &&
                regSaver[off+2].regVal    == old(r8.regVal) &&
                regSaver[off+2].memId     == old(r8.memId) &&
                //
                regSaver[off+3].regNo     == old(r9.regNo) &&
                regSaver[off+3].regType   == old(r9.regType) &&
                regSaver[off+3].regVal    == old(r9.regVal) &&
                regSaver[off+3].memId     == old(r9.memId)
        //
        // Keep other regSaver element unchanged
        ensures forall i |  0 <= i < old(r10.memId)*4 && (old(r10.memId)*4+3) < this.regSaver.Length
                            ::
                            regSaver[i].regNo     == old(regSaver[i].regNo)     &&
                            regSaver[i].regType   == old(regSaver[i].regType)   &&
                            regSaver[i].regVal    == old(regSaver[i].regVal)    &&
                            regSaver[i].memId     == old(regSaver[i].memId)
        // Reset R0 and R6 - R9
        ensures this.r0.regType == UNINT && this.r0.regNo == R0 &&
            this.r6.regType == UNINT && this.r6.regNo == R6 &&
            this.r7.regType == UNINT && this.r7.regNo == R7 &&
            this.r8.regType == UNINT && this.r8.regNo == R8 &&
            this.r9.regType == UNINT && this.r9.regNo == R9
        
        // Reset the value (unknownBv8) and type of callee stack slots
        ensures var stackNo := old(r10.memId)+1;
                forall i | 0 <= i < 512 :: (this.stackSlotTypes[stackNo][i] == (if allow_ptr_leak then SCALAR else UNINT) &&
                                            this.stacks[stackNo][i] == unknownBv8)


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
        reads this, this.maps
        reads this.stacks, this.stackSlotTypes, this.idMetas
        reads if reg.regType == STACKMEM then {this.stackSlotTypes[reg.memId]} else {}
        requires reg.regType == STACKMEM ==> 0 <= reg.memId < this.stackSlotTypes.Length
        //
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
        //
        reads reg
        reads this, this.maps, this.stacks, this.stackSlotTypes, this.idMetas
        reads if reg.regType == STACKMEM then {this.stackSlotTypes[reg.memId]} else {}
        requires reg.regType == STACKMEM ==> 0 <= reg.memId < this.stackSlotTypes.Length
        //
        //
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

    ghost method {:axiom} map_lookup_elem()
        requires bpf_map_lookup_elem_progType(progType)
        // r1 = map
        requires r1.regType == MAP_PTR
        requires 0 <= r1.mapFd < this.maps.Length
        requires bpf_map_lookup_elem_mapType(this.maps[r1.mapFd].mapType)
        // r2 = key
        requires r2.regType == PTR_TO_MAP_VALUE ==> 0 <= r2.mapFd < this.maps.Length
        requires r2.regType == STACKMEM ==> 0 <= r2.memId < this.stackSlotTypes.Length
        //
        requires isReadableMem(r2, this.maps[r1.mapFd].keySize)
        //
        modifies this.r0, this.mutableVars
        //
        ensures r0.regNo == old(r0.regNo)
        ensures r0.regType == PTR_TO_MAP_VALUE || r0.regType == NULL
        // Note: r0.regVal is unknow so don't update it explicitly
        ensures r0.mapFd == r1.mapFd
        ensures r0.memId == old(mutableVars.idCounter)
        ensures mutableVars.idCounter == old(mutableVars.idCounter) + 1

    // Note: get PTR_TO_MAP_VALUE pointing to the offset from the map specified by the mapFd
    ghost method {:axiom} Load_MAPVALUE_BYFD(dst:RegState, mapFd:int64, off:bv64)
        requires 0 <= mapFd < this.maps.Length
        requires maps[mapFd].mapType == BPF_MAP_TYPE_ARRAY
        // TODO: any checks needed on program type?
        // Note: this instruction can be used on BPF_MAP_TYPE_ARENA, but it is out of our scope
        // Note: functions for validating access: arena_map_direct_value_addr and array_map_direct_value_addr
        requires 0 <= bv64ToInt64(off) < maps[mapFd].valSize
        requires maps[mapFd].maxEntries > 0
        //
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == PTR_TO_MAP_VALUE
        ensures dst.regVal == off
        ensures dst.mapFd == mapFd


    ghost method {:axiom} Load_MAPVALUE_BYFDIDX(dst:RegState, mapFdIdx:int64, off:bv64)
        requires 0 <= mapFdIdx < this.maps.Length
        requires maps[mapFdIdx].mapType == BPF_MAP_TYPE_ARRAY
        // Note: this instruction can be used on BPF_MAP_TYPE_ARENA, but it is out of our scope
        // Note: functions for validating access: arena_map_direct_value_addr and array_map_direct_value_addr
        requires 0 <= bv64ToInt64(off) < maps[mapFdIdx].valSize
        requires maps[mapFdIdx].maxEntries > 0
        //
        modifies dst
        //
        ensures dst.regNo == old(dst.regNo)
        ensures dst.regType == PTR_TO_MAP_VALUE
        ensures dst.regVal == off
        ensures dst.mapFd == mapFdIdx

    ghost method {:axiom} map_update_elem()
        requires bpf_map_update_elem_progType(progType)
        // r1 = map, r2 = key, r3 = value, r4 = flags,
        requires r1.regType == MAP_PTR
        requires 0 <= r1.mapFd < this.maps.Length
        requires bpf_map_update_elem_mapType(this.maps[r1.mapFd].mapType)
        // r2 = key
        requires r2.regType == PTR_TO_MAP_VALUE ==> 0 <= r2.mapFd < this.maps.Length
        requires r2.regType == STACKMEM ==> 0 <= r2.memId < this.stackSlotTypes.Length
        requires isReadableMem(r2, this.maps[r1.mapFd].keySize)
        // r3 = value
        requires r3.regType == PTR_TO_MAP_VALUE ==> 0 <= r3.mapFd < this.maps.Length
        requires r3.regType == STACKMEM ==> 0 <= r3.memId < this.stackSlotTypes.Length
        requires isReadableMem(r3, this.maps[r1.mapFd].valSize)
        requires r4.regType == SCALAR
        //
        modifies this.r0
        //
        ensures r0.regNo == old(r0.regNo)
        ensures r0.regType == SCALAR
        // Note: r0.regVal is unknow so don't update it explicitly

    ghost method {:axiom} map_delete_elem()
        requires bpf_map_delete_elem_progType(progType)
        // r1 = map, r2 = key
        requires r1.regType == MAP_PTR
        requires 0 <= r1.mapFd < this.maps.Length
        requires bpf_map_delete_elem_mapType(this.maps[r1.mapFd].mapType)
        // r2 = key
        requires r2.regType == PTR_TO_MAP_VALUE ==> 0 <= r2.mapFd < this.maps.Length
        requires r2.regType == STACKMEM ==> 0 <= r2.memId < this.stackSlotTypes.Length
        requires isReadableMem(r2, this.maps[r1.mapFd].keySize)
        //
        modifies this.r0
        //
        ensures r0.regNo == old(r0.regNo)
        ensures r0.regType == SCALAR

    ghost method {:axiom} map_push_elem()
        requires bpf_map_push_elem_progType(progType)
        // r1 = map, r2 = value, r3 = flag
        requires r1.regType == MAP_PTR
        requires 0 <= r1.mapFd < this.maps.Length
        requires bpf_map_push_elem_mapType(this.maps[r1.mapFd].mapType)
        // r2 = value
        requires r2.regType == PTR_TO_MAP_VALUE ==> 0 <= r2.mapFd < this.maps.Length
        requires r2.regType == STACKMEM ==> 0 <= r2.memId < this.stackSlotTypes.Length
        requires isReadableMem(r2, this.maps[r1.mapFd].valSize)
        requires r3.regType == SCALAR // need to constraint the flags to be more precise?
        //
        modifies this.r0
        //
        ensures r0.regNo == old(r0.regNo)
        ensures r0.regType == SCALAR

    ghost method {:axiom} map_pop_elem()
        requires bpf_map_pop_elem_progType(progType)
        // r1 = map, r2 = value
        requires r1.regType == MAP_PTR
        requires 0 <= r1.mapFd < this.maps.Length
        requires bpf_map_pop_elem_mapType(this.maps[r1.mapFd].mapType)
        //
        requires r2.regType == PTR_TO_MAP_VALUE ==> 0 <= r2.mapFd < this.maps.Length
        requires r2.regType == STACKMEM ==> 0 <= r2.memId < this.stackSlotTypes.Length
        requires isWritableMem(r2, this.maps[r1.mapFd].valSize) // ARG_PTR_TO_MAP_VALUE | MEM_UNINIT,
        //
        modifies this.r0
        //
        ensures r0.regNo == old(r0.regNo)
        ensures r0.regType == SCALAR   

    ghost method {:axiom} map_peek_elem()
        requires bpf_map_peek_elem_progType(progType)
        // r1 = map, r2 = value
        requires r1.regType == MAP_PTR
        requires 0 <= r1.mapFd < this.maps.Length
        requires bpf_map_peek_elem_mapType(this.maps[r1.mapFd].mapType)
        //
        requires r2.regType == PTR_TO_MAP_VALUE ==> 0 <= r2.mapFd < this.maps.Length
        requires r2.regType == STACKMEM ==> 0 <= r2.memId < this.stackSlotTypes.Length
        requires isWritableMem(r2, this.maps[r1.mapFd].valSize) // ARG_PTR_TO_MAP_VALUE | MEM_UNINIT,
        //
        modifies this.r0
        //
        ensures r0.regNo == old(r0.regNo)
        ensures r0.regType == SCALAR

    ghost method {:axiom} map_lookup_percpu_elem()
        requires bpf_map_lookup_percpu_elem_progType(progType)
        // r1 = map, r2 = key, r3 = cpu
        requires r1.regType == MAP_PTR
        requires 0 <= r1.mapFd < this.maps.Length
        requires bpf_map_lookup_percpu_elem_mapType(this.maps[r1.mapFd].mapType)
        // r2 = key
        requires r2.regType == PTR_TO_MAP_VALUE ==> 0 <= r2.mapFd < this.maps.Length
        requires r2.regType == STACKMEM ==> 0 <= r2.memId < this.stackSlotTypes.Length
        requires isReadableMem(r2, this.maps[r1.mapFd].keySize)
        //
        requires r3.regType == SCALAR
        //
        modifies this.r0
        //
        ensures r0.regNo == old(r0.regNo)
        ensures r0.regType == PTR_TO_MAP_VALUE || r0.regType == NULL
        // Note: r0.regVal is unknow so don't update it explicitly
        ensures r0.mapFd == r1.mapFd
        ensures r0.memId == old(mutableVars.idCounter)
        ensures mutableVars.idCounter == old(mutableVars.idCounter) + 1

    /////////////////////////////////////////////////////////////////////////////////////

    // TODO: adjust arithmetic on pointers with relaxed and conservative behaviors

    // TODO: re-organize the memory load/store/atomic dafny code

    // TODO: is readable and writable on all types of pointers




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
    ghost method {:axiom} tcp_sock()
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


    //////////////////

    ghost predicate reset_6_reg()
        reads this, this.r0, this.r1, this.r2, this.r3, this.r4, this.r5
        {
            this.r0.regType == UNINT && this.r0.regNo == R0 &&
            this.r1.regType == UNINT && this.r1.regNo == R1 &&
            this.r2.regType == UNINT && this.r2.regNo == R2 &&
            this.r3.regType == UNINT && this.r3.regNo == R3 &&
            this.r4.regType == UNINT && this.r4.regNo == R4 &&
            this.r5.regType == UNINT && this.r5.regNo == R5
        }
    
    ghost predicate reset_5_reg()
        reads this, this.r1, this.r2, this.r3, this.r4, this.r5
        {
            this.r1.regType == UNINT && this.r1.regNo == R1 &&
            this.r2.regType == UNINT && this.r2.regNo == R2 &&
            this.r3.regType == UNINT && this.r3.regNo == R3 &&
            this.r4.regType == UNINT && this.r4.regNo == R4 &&
            this.r5.regType == UNINT && this.r5.regNo == R5
        }

    // https://lore.kernel.org/bpf/20221111202719.982118-1-memxor@gmail.com/
    ghost method {:axiom} spin_lock()
        // r1 = struct bpf_spin_lock *lock
        /*
            type check:
                - PTR_TO_MAP_VALUE which has struct bpf_spin_lock field
                - PTR_TO_BTF_ID | MEM_ALLOC
            check the ptr with its offset points to the exact bpf_spin_lock struct
            TODO: we assume the programs all can pass the above checks.
        */
        requires spin_lock_meta.isLocked == false
        //
        modifies spin_lock_meta
        modifies r0, r1, r2, r3, r4, r5
        //
        ensures spin_lock_meta.isLocked == true
        ensures spin_lock_meta.memId == this.r1.memId
        ensures spin_lock_meta.ptrType == this.r1.regType
        //
        ensures reset_6_reg()

    ghost method {:axiom} spin_unlock()
        // TODO: the same as bpf_spin_lock
        requires spin_lock_meta.isLocked == true
        requires spin_lock_meta.memId == this.r1.memId
        requires spin_lock_meta.ptrType == this.r1.regType
        //
        modifies spin_lock_meta
        modifies r0, r1, r2, r3, r4, r5
        //
        ensures spin_lock_meta.isLocked == false
        ensures spin_lock_meta.memId == -1
        ensures spin_lock_meta.ptrType == UNINT
        //
        ensures reset_6_reg()

    // https://lore.kernel.org/bpf/CA+vRuzPChFNXmouzGG+wsy=6eMcfr1mFG0F3g7rbg-sedGKW3w@mail.gmail.com/
    ghost method {:axiom} loop()
        // (bpf_loop, u32, nr_loops, void *, callback_fn, void *, callback_ctx, u64, flags)
        // r1 = nr_loops, r2 = callback_fn, r3 = callback_ctx, r4 = flags
        /*
            .ret_type   = RET_INTEGER,
            .arg1_type  = ARG_ANYTHING,
            .arg2_type  = ARG_PTR_TO_FUNC,
            .arg3_type  = ARG_PTR_TO_STACK_OR_NULL,
            .arg4_type  = ARG_ANYTHING,
         */
        // requires r1.regType == 
        requires r2.regType == PTR_TO_FUNC
        requires r3.regType == STACKMEM || r3.regType == NULL
        // requires r4.regType == 
        //
        ensures reset_5_reg()

    // global iter states
    // Iter struct can only be stack pointers, and stack slots are marked with STACK_ITER
    // TODO: stack slots whose type are STACK_ITER or STACK_DYNPTR cannot be overwritten
    

    ///////////////////////////////// BPF Number Iter kfunc ///////////////////////////////////////
    // struct bpf_iter_num is 8-byte (start (4 bytes), end (4 bytes)) and stored on the stack

    ghost method {:axiom} bpf_iter_num_new()
        // r1 = iter (stack_ptr), r2 = start, r3 = end
        //
        // Check R1
        // Potential BUG: didn't check the ptr type of arg1, assume it is stack
        requires r1.regType == STACKMEM
        //
        requires 0 <= r1.memId < 8 == this.stacks.Length == this.stackSlotTypes.Length == this.idMetas.Length
        requires 512 == this.stacks[r1.memId].Length == this.stackSlotTypes[r1.memId].Length
        requires 64 == this.idMetas[r1.memId].Length
        //
        requires stack_writable(r1, 0, 8) // TODO: should overwritten STACK_ITER with STACK_ITER allowed
        //
        // Check R2 and R3 : TODO： r2 & r3 must be constants
        requires bv32ToInt32(r2.regVal) < bv32ToInt32(r3.regVal)
        //
        modifies r0, r1, r2, r3, r4, r5
        modifies this.stacks[r1.memId], this.stackSlotTypes[r1.memId], this.idMetas[r1.memId]
        modifies mutableVars
        // Stack value, type, idMeta
        ensures var start_off := (bv64ToInt64(old(r1.regVal)) + 512);
                var end_off := start_off + 4;
                var stackNo := old(r1.memId);
                // Stack value
                (forall i | start_off <= i < (start_off + 4) :: stacks[stackNo][i] == getRegByteX(old(r2.regVal), i - start_off))
                &&
                (forall i | end_off <= i < (end_off + 4) :: stacks[stackNo][i] == getRegByteX(old(r3.regVal), i - end_off))
                &&
                (forall j | ((0 <= j < 512) && !(0 <= start_off <= j < start_off + 16 <= 512)) :: stacks[stackNo][j] == old(stacks[stackNo][j]))
                // Slot types
                &&
                (forall i | (0 <= start_off <= i < (start_off + 8) <= 512) :: (stackSlotTypes[stackNo][i] == STACK_ITER))
                &&
                (forall j | (0 <= j < start_off || (start_off + 8) <= j < 512) :: (stackSlotTypes[stackNo][j] == old(stackSlotTypes[stackNo][j])))
                // idMetas
                &&
                idMetas[stackNo][start_off/8] == old(mutableVars.idCounter)
                &&
                (forall m | (0 <= m < (start_off/8) || ((start_off + 8)/8) <= m < 64) :: idMetas[stackNo][m] == old(idMetas[stackNo][m]))    
        //
        // Increase ID
        ensures mutableVars.idCounter == (old(mutableVars.idCounter) + 1)
        // Return value
        ensures r0.regNo == R0
        ensures r0.regType == SCALAR
        // R0 regVal is unknow, which can be zero or error numbers
        // R0-R5
        ensures r1.regType == UNINT && r2.regType == UNINT && r3.regType == UNINT && r4.regType == UNINT && r5.regType == UNINT
        ensures r1.regNo == R1 && r2.regNo == R2 && r3.regNo == R3 && r4.regNo == R4 && r5.regNo == R5


    ghost method {:axiom} bpf_iter_num_next()
        // r1 = iter
        // Check R1
        // Potential BUG: didn't check the ptr type of arg1, assume it is stack
        requires r1.regType == STACKMEM
        //
        requires 0 <= r1.memId < 8 == this.stacks.Length == this.stackSlotTypes.Length == this.idMetas.Length
        requires 512 == this.stacks[r1.memId].Length == this.stackSlotTypes[r1.memId].Length
        requires 64 == this.idMetas[r1.memId].Length
        //
        requires stack_writable(r1, 0, 8) // TODO: should overwritten STACK_ITER with STACK_ITER allowed
        //
        requires var enum_start_off := (bv64ToInt64(r1.regVal) + 512);
                 forall i | 0 <= enum_start_off <= i < (enum_start_off + 8) < 512 :: stackSlotTypes[r1.memId][i] == STACK_ITER
        //
        modifies r0, r1, r2, r3, r4, r5
        modifies this.stacks[r1.memId]
        //
        ensures var stackNo := old(r1.memId);
                var start_off := (bv64ToInt64(old(r1.regVal)) + 512);
                var end_off := start_off + 4;
                //
                var mem := this.stacks[stackNo];
                // Note: cannot use loadNbytesMem() because it is for unmodified memory
                var iter_start :=   (old(mem[start_off]) as bv64)                   |
                                    (((old(mem[start_off+1]) as bv64) & 0xff) << 8) |
                                    (((old(mem[start_off+2]) as bv64) & 0xff) << 16)|
                                    (((old(mem[start_off+3]) as bv64) & 0xff) << 24);
                var iter_end :=     (old(mem[end_off]) as bv64)                     |
                                    (((old(mem[end_off+1]) as bv64) & 0xff) << 8)   |
                                    (((old(mem[end_off+2]) as bv64) & 0xff) << 16)  |
                                    (((old(mem[end_off+3]) as bv64) & 0xff) << 24);
                //
                var new_iter_start := iter_start + 1;
                //
                if iter_start + 1 < iter_end
                    then
                        // Stack value
                        (forall i | 0 <= start_off <= i < (start_off + 4) <= 512 :: this.stacks[stackNo][i] == getRegByteX(new_iter_start, i - start_off))
                        &&
                        (forall j | ((0 <= j < 512) && !(0 <= start_off <= j < start_off + 4 <= 512)) :: this.stacks[stackNo][j] == old(this.stacks[stackNo][j]))
                        &&
                        // Return value
                        r0.regNo == R0 && r0.regType == STACKMEM && r0.regVal == old(r1.regVal)
                    else
                        // Stack value
                        (forall i | 0 <= start_off <= i < (start_off + 4) <= 512 :: this.stacks[stackNo][i] == 0)
                        &&
                        (forall i | 0 <= end_off <= i < (end_off + 4) <= 512 :: this.stacks[stackNo][i] == 0)
                        &&
                        (forall j | ((0 <= j < 512) && !(0 <= start_off <= j < start_off + 16 <= 512)) :: this.stacks[stackNo][j] == old(this.stacks[stackNo][j]))
                        &&
                        // Return value
                        r0.regNo == R0 && r0.regType == SCALAR && r0.regVal == 0
        //
        ensures r1.regType == UNINT && r2.regType == UNINT && r3.regType == UNINT && r4.regType == UNINT && r5.regType == UNINT
        ensures r1.regNo == R1 && r2.regNo == R2 && r3.regNo == R3 && r4.regNo == R4 && r5.regNo == R5

    ghost method {:axiom} bpf_iter_num_destroy()
        // r1 = iter
        requires r1.regType == STACKMEM
        //
        requires 0 <= r1.memId < 8 == this.stacks.Length == this.stackSlotTypes.Length == this.idMetas.Length
        requires 512 == this.stacks[r1.memId].Length == this.stackSlotTypes[r1.memId].Length
        requires 64 == this.idMetas[r1.memId].Length
        //
        requires stack_writable(r1, 0, 8) // TODO: should overwritten STACK_ITER with STACK_ITER allowed
        //
        requires var enum_start_off := (bv64ToInt64(r1.regVal) + 512);
                 forall i | 0 <= enum_start_off <= i < (enum_start_off + 8) < 512 :: stackSlotTypes[r1.memId][i] == STACK_ITER
        //
        modifies r0, r1, r2, r3, r4, r5
        modifies this.stacks[r1.memId], this.stackSlotTypes[r1.memId]
        //
        ensures var start_off := (bv64ToInt64(old(r1.regVal)) + 512);
                var stackNo := old(r1.memId);
                (forall i | start_off <= i < (start_off + 8) :: this.stacks[stackNo][i] == 0 && this.stackSlotTypes[stackNo][i] == SCALAR)
                &&
                (forall j | ((0 <= j < 512) && !(0 <= start_off <= j < start_off + 16 <= 512))
                    :: this.stacks[stackNo][j] == old(this.stacks[stackNo][j]) && this.stackSlotTypes[stackNo][j] == old(this.stackSlotTypes[stackNo][j])
                )
        //
        ensures r0.regType == UNINT && r1.regType == UNINT && r2.regType == UNINT && r3.regType == UNINT && r4.regType == UNINT && r5.regType == UNINT
        ensures r0.regNo == R0 && r1.regNo == R1 && r2.regNo == R2 && r3.regNo == R3 && r4.regNo == R4 && r5.regNo == R5

    ///////////////////////////////// BPF tail call ///////////////////////////////////////

    ghost method {:axiom} tail_call()
        // r1 = ctx?, r2 = prog_table_map (must be BPF_MAP_TYPE_PROG_ARRAY), r3 = idx?
        requires r1.regType == CTXMEM
        requires 0 <= r2.mapFd < maps.Length
        requires maps[r2.mapFd].mapType == BPF_MAP_TYPE_PROG_ARRAY
        requires r3.regType == SCALAR
        requires 0 <= bv64ToUInt64(r3.regVal) < maps[r2.mapFd].maxEntries
        // TODO: check stack size
        // tal_call == goto: but the stack and rgisters are not shared.
        // Programs are verified seperately, so acess to the uninitilized but might already initialized by another program still requires priv.
        // like other helper calls, R1-R5 registers are scratched. No return value so R0 is scracted as well.
        ensures reset_6_reg()


    ///////////////////////// BPF Dynmic pointer kfunc and helper call ////////////////////


    // PTR_TO_DYNPTR type mark, 
    // what is CONST_PTR_TO_DYNPTR?

    /*
    ghost method {:axiom} bpf_dynptr_from_mem()
        // r1 = map_value, r2 = size within the bound, r3 = flag, r4 = dynptr (must on stack)
        // return zero or error number
        // TODO: should size be a constant???
        requires r1.regType == PTR_TO_MAP_VALUE
        requires r2.regType == SCALAR
        requires r3.regType == SCALAR
        requires r4.regType == STACKMEM
        //
        requires this.stack.Length == 512 && this.stackSlotType.Length == 512 && this.idMeta.Length == 64
        //
        requires 0 <= r1.mapFd < maps.Length
        requires 0 <= bv64ToInt64(r1.regVal) < bv64ToInt64(r1.regVal) + bv64ToInt64(r2.regVal) <= maps[r1.mapFd].valSize 
        requires var dynptr_start := bv64ToInt64(r4.regVal) + 512;
                 0 <= dynptr_start < dynptr_start + 16  <= 512
        // any requires on the stack slot types of dynptr
        //
        modifies this.stack, this.stackSlotType, this.idMeta
        //
        ensures var data_start_off := (bv64ToInt64(old(r4.regVal)) + 512);
                var offset_off := data_start_off + 8;
                var size_off := data_start_off + 12;
                var end := data_start_off + 16;
                // record data, off, size in the struct bpf_dynptr_kern
                // data is the pointer of the map_value, which is unknown, so leave it
                // offset
                (forall i | 0 <= offset_off <= i < size_off <= 512 :: stack[i] == 0)
                &&
                // size
                (forall i | 0 <= size_off <= i < end <= 512 :: stack[i] == getRegByteX(r2.regVal, i - size_off))
                &&
                // Stack slot
                (forall i | 0 <= data_start_off <= i < end <= 512 :: stackSlotType[i] == STACK_DYNPTR)
                &&
                (forall j | 0 <= j < data_start_off < 512 || size_off + 4 <= j < 512
                    :: stack[j] == old(stack[j]) && stackSlotType[j] == old(stackSlotType[j])
                )
        // r0 and r1-r5
        ensures r0.regNo == R0 && r0.regType == SCALAR
        ensures r1.regType == UNINT && r2.regType == UNINT && r3.regType == UNINT && r4.regType == UNINT && r5.regType == UNINT
        ensures r1.regNo == R1 && r2.regNo == R2 && r3.regNo == R3 && r4.regNo == R4 && r5.regNo == R5
    */

    // ghost method {:axiom} bpf_dynptr_from_skb()
    // ghost method {:axiom} bpf_dynptr_from_xdp()

    ghost method {:axiom} bpf_dynptr_data()

    ghost method {:axiom} bpf_dynptr_slice()
    // const struct bpf_dynptr_kern *ptr, u32 offset, void *buffer__opt, u32 buffer__szk
    // Obtain a read-only pointer

    // https://lore.kernel.org/bpf/20230306071006.73t5vtmxrsykw4zu@apollo/
    // it should not allow use stack as the dynptr slice buffer!!!
    ghost method {:axiom} bpf_dynptr_slice_rdwr()
    // const struct bpf_dynptr_kern *ptr, u32 offset, void *buffer__opt, u32 buffer__szk    
    // readable-writeable

    ghost method {:axiom} bpf_dynptr_read()

    ghost method {:axiom} bpf_dynptr_write()
    // r1 = const struct bpf_dynptr_kern dst, r2 = offset, r3 = src, r4 = len, r5 = flags


    ghost method {:axiom} get_prandom_u32()
        modifies r0, r1, r2, r3, r4, r5
        ensures unknownBv32(r0.regVal)
        ensures r0.regType == SCALAR && r1.regType == UNINT && r2.regType == UNINT && r3.regType == UNINT && r4.regType == UNINT && r5.regType == UNINT
        ensures r0.regNo == R0 && r1.regNo == R1 && r2.regNo == R2 && r3.regNo == R3 && r4.regNo == R4 && r5.regNo == R5

    ghost method {:axiom} get_cgroup_classid()
        // r1 = PTR_TO_CTX, ret = SCALAR
        requires r1.regType == CTXMEM
        //
        modifies r0, r1, r2, r3, r4, r5
        ensures unknownBv64(r0.regVal)
        ensures r0.regType == SCALAR && r1.regType == UNINT && r2.regType == UNINT && r3.regType == UNINT && r4.regType == UNINT && r5.regType == UNINT
        ensures r0.regNo == R0 && r1.regNo == R1 && r2.regNo == R2 && r3.regNo == R3 && r4.regNo == R4 && r5.regNo == R5


    ghost method {:axiom} get_cgroup_id()
        modifies r0, r1, r2, r3, r4, r5
        ensures unknownBv64(r0.regVal)
        ensures r0.regType == SCALAR && r1.regType == UNINT && r2.regType == UNINT && r3.regType == UNINT && r4.regType == UNINT && r5.regType == UNINT
        ensures r0.regNo == R0 && r1.regNo == R1 && r2.regNo == R2 && r3.regNo == R3 && r4.regNo == R4 && r5.regNo == R5

    //////////////// Utility functions //////////////////////////

    // TODO: stack value update, type update, memid update, mapfd update, and differnt stack mems

    ghost method {:axiom} update_stack_value(stackN:int64, pos:int64, value:bv8)
        requires 0 <= stackN < 8 == this.stacks.Length == this.stackSlotTypes.Length == this.idMetas.Length
        requires 512 == this.stacks[stackN].Length == this.stackSlotTypes[stackN].Length
        requires 64 == this.idMetas[stackN].Length
        requires 0 <= pos < 512
        //
        modifies this.stacks[stackN]
        //
        ensures forall i | 0 <= i < 512 :: (
            ((i == pos) ==> stacks[stackN][i] == value)
            &&
            ((i != pos) ==> stacks[stackN][i] == old(stacks[stackN][i]))
        )

    // inclusive at both sides: [start, end]
    ghost method {:axiom} update_stack_type(stackN:int64, start:int64, end:int64, slotType:REGTYPE)
        requires 0 <= stackN < 8 == this.stacks.Length == this.stackSlotTypes.Length == this.idMetas.Length
        requires 512 == this.stacks[stackN].Length == this.stackSlotTypes[stackN].Length
        requires 64 == this.idMetas[stackN].Length
        requires 0 <= start <= end < 512
        //
        modifies this.stackSlotTypes[stackN]
        //
        ensures forall i | 0 <= i < 512 :: (
            (start <= i <= end ==> stackSlotTypes[stackN][i] == slotType)
            &&
            (!(start <= i <= end) ==> stackSlotTypes[stackN][i] == old(stackSlotTypes[stackN][i]))
        )

}