include "utils.dfy"
include "invs.dfy"

module eBPFCtrlFlowSpec {

    import opened Terms
    import opened DataTypes
    import opened States
    import opened Utils
    import opened InvsForFasterChecker
// ----------------------------------------------------------------
    //                          Call (opaque)
    // ----------------------------------------------------------------
    //
    // Calls (BPF_CALL and BPF_PSEUDO_CALL) are modelled as a single
    // opaque semantic step. We do not inline the callee into the
    // caller's CFG; instead, we abstract its effect on the caller
    // state. For now the abstraction is a no-op — the function
    // returns the input state unchanged. This is sound as a
    // placeholder while keeping mem_inv across the call, and can
    // later be refined to clobber R0..R5, mark R0's value as
    // unknown, etc.

    ghost predicate call_precond(s: State, insn: Instruction)
    {
        insn == CALL
        &&
        mem_inv(s)
    }

    ghost function call_step(s: State, insn: Instruction) : (res: State)
        requires call_precond(s, insn)
        ensures  res == s.(R0 := Scalar(Normal, s.rand))
        ensures  mem_inv(res)
    {
        s.(R0 := Scalar(Normal, s.rand))
    }

    // ----------------------------------------------------------------
    //          Conditional jump by comparisons on two regs
    // ----------------------------------------------------------------

    ghost predicate cond_jump_reg_precond(s: State, insn: Instruction)
    {
        exists dst, src, op :: (
            insn == CONDJMPREG(dst, src, op)
            &&
            var dst_tv := get_reg_typeval(s, dst);
            var src_tv := get_reg_typeval(s, src);
            dst_tv != Uninit && src_tv != Uninit
            &&
            (
                match op {
                    case JEQ64 | JNE64 => (
                        !s.cfg.allow_ptr_leak ==>
                        (
                            (is_scalar(dst_tv) && is_scalar(src_tv))
                            ||
                            (ptr_or_ptrornull(dst_tv) && ptr_or_ptrornull(src_tv))
                            ||
                            (ptr_or_ptrornull(dst_tv) && is_scalar_zero(src_tv))
                            ||
                            (is_scalar_zero(dst_tv) && ptr_or_ptrornull(src_tv))
                        )
                    )
                    // JMP great or less than:
                    // Allow both scalar cmp and pointer cmp.
                    // It is fine to leak pointer relative relation
                    case JGT64 | JGE64 | JSGT64 | JSGE64 |
                        JLT64 | JLE64 | JSLT64 | JSLE64
                        =>
                        !s.cfg.allow_ptr_leak ==> (
                            (is_scalar(dst_tv) && is_scalar(src_tv))
                            ||
                            (ptr_or_ptrornull(dst_tv) && ptr_or_ptrornull(src_tv))
                        )
                    // 32-bit, JSET64: only allow scalar comparison if no privilege
                    case _ => (
                        !s.cfg.allow_ptr_leak ==>
                            (is_scalar(dst_tv) && is_scalar(src_tv))
                    )
                }
            )
            &&
            (
                (ptrornull(src_tv) ==> src != R10)
                &&
                (ptrornull(dst_tv) ==> dst != R10)
            )
            &&
            mem_inv(s)
        )
    }


    ghost function cond_jump_reg(s: State, insn: Instruction) : (res: State)
    requires cond_jump_reg_precond(s, insn)
    ensures s.mems == res.mems
    ensures preserve_regs_except_dst_src(s, res, insn.dst, insn.src)
    {
        var (dst, src, jmpop) := (insn.dst, insn.src, insn.jmpop);

        var dst_tv := get_reg_typeval(s, dst);
        var src_tv := get_reg_typeval(s, src);

        var dst_arithv := get_arith_val(s, dst_tv);
        var src_arithv := get_arith_val(s, src_tv);

        var jmp_res := compute_jmp_res(jmpop, dst_arithv, src_arithv);

        var s' := s.(jmp_res := jmp_res);

        // special case: JNE64 and JEQ64
        adjust_regtv_for_nullness_reg(s', jmpop, dst, src)
    }


    // ----------------------------------------------------------------
    //        Conditional jump by comparison on a reg and an imm
    // ----------------------------------------------------------------

    ghost predicate cond_jump_imm_precond(s: State, insn: Instruction)
    {
        exists dst, src_imm, op :: (
            insn == CONDJMPIMM(dst, src_imm, op)
            &&
            var dst_tv := get_reg_typeval(s, dst);
            dst_tv != Uninit
            &&
            (
                match op {
                    case JEQ64 | JNE64 => (
                        !s.cfg.allow_ptr_leak ==> (
                            is_scalar(dst_tv)
                            ||
                            (ptr_or_ptrornull(dst_tv) && src_imm == 0)
                        )
                    )
                    // 32-bit, JSET64, JLG64
                    case _ => (
                        !s.cfg.allow_ptr_leak ==> is_scalar(dst_tv)
                    )
                }
            )
            &&
            (
                (ptrornull(dst_tv) ==> dst != R10)
            )
            &&
            mem_inv(s)
        )
    }


    ghost function cond_jump_imm(s: State, insn: Instruction) : (res: State)
    requires cond_jump_imm_precond(s, insn)
    ensures s.mems == res.mems
    ensures preserve_regs_except_dst(s, res, insn.dst)
    {
        var (dst, src_imm, jmpop) := (insn.dst, insn.src_imm, insn.jmpop);

        var dst_tv := get_reg_typeval(s, dst);
        var dst_arithv := get_arith_val(s, dst_tv);

        var jmp_res := compute_jmp_res(jmpop, dst_arithv, src_imm);

        var s' := s.(jmp_res := jmp_res);

        // special case: JNE64 and JEQ64
        adjust_regtv_for_nullness_imm(s', jmpop, dst, src_imm)
    }


    // ----------------------------------------------------------------
    //          Helper functions for repeated jmp comparisons
    // ----------------------------------------------------------------
    
    ghost function compute_jmp_res(
        jmpop: JMPOP, dst_arithv: bv64, src_arithv: bv64
    ) : bool
    {
        var dst_arithv_u32 := low32(dst_arithv);
        var src_arithv_u32 := low32(src_arithv);

        match jmpop {
            case JEQ32  => bv_eq(dst_arithv_u32, src_arithv_u32)
            
            case JNE32  => bv_neq(dst_arithv_u32, src_arithv_u32)

            case JSET32 => not_32bit_zero(bvand32(dst_arithv, src_arithv))
            
            case JGT32 | JGE32 | JSGT32 | JSGE32 |
                 JLT32 | JLE32 | JSLT32 | JSLE32 =>
                    lgjmp32(jmpop, dst_arithv, src_arithv)
            //
            case JEQ64      => bv_eq(dst_arithv, src_arithv)
                                // jeq64(s, dst_tv, src_tv)
            case JNE64      => bv_neq(dst_arithv, src_arithv)
                                // jne64(s, dst_tv, src_tv)
            case JSET64     => not_64bit_zero(bvand64(dst_arithv, src_arithv))
            
            case JGT64 | JGE64 | JSGT64 | JSGE64 | JLT64 | JLE64 |
                 JSLT64 | JSLE64 => lgjmp64(jmpop, dst_arithv, src_arithv)
        }
    }

    predicate lgjmp32(jmpop:JMPOP, dst_val: bv64, src_val: bv64)
    requires jmpop in {
        JGT32, JGE32, JSGT32, JSGE32, JLT32, JLE32, JSLT32, JSLE32
    }
    {
        var dst_arithv_u32 := low32(dst_val);
        var src_arithv_u32 := low32(src_val);

        var dst_arithv_s32 := bv32ToInt32(dst_val); 
        var src_arithv_s32 := bv32ToInt32(src_val);

        match jmpop {

            case JGT32  => dst_arithv_u32 >  src_arithv_u32

            case JGE32  => dst_arithv_u32 >= src_arithv_u32

            case JSGT32 => dst_arithv_s32 >  src_arithv_s32

            case JSGE32 => dst_arithv_s32 >= src_arithv_s32

            case JLT32  => dst_arithv_u32 <  src_arithv_u32

            case JLE32  => dst_arithv_u32 <= src_arithv_u32

            case JSLT32 => dst_arithv_s32 <  src_arithv_s32

            case JSLE32 => dst_arithv_s32 <= src_arithv_s32

            case _ => (
                assert false;
                false
            )
        }
    }

    predicate lgjmp64(jmpop:JMPOP, dst_arithv: bv64, src_arithv: bv64)
    requires jmpop in {
        JGT64, JGE64, JSGT64, JSGE64, JLT64, JLE64, JSLT64, JSLE64
    }
    {
        var dst_arithv_s64 := bv64ToInt64(dst_arithv);
        var src_arithv_s64 := bv64ToInt64(src_arithv);
            
        match jmpop {
            case JGT64  => dst_arithv > src_arithv
            case JGE64  => dst_arithv >= src_arithv
            case JSGT64 => dst_arithv_s64 >  src_arithv_s64
            case JSGE64 => dst_arithv_s64 >= src_arithv_s64
            case JLT64  => dst_arithv < src_arithv
            case JLE64  => dst_arithv <= src_arithv
            case JSLT64 => dst_arithv_s64 <  src_arithv_s64
            case JSLE64 => dst_arithv_s64 <= src_arithv_s64
            case _ => (
                assert false;
                false
            )
        }
    }


    ghost function adjust_regtv_for_nullness_reg(
        s:State, jmpop: JMPOP, dst:REG, src:REG
    ) : (res: State)
    requires var dst_tv := get_reg_typeval(s, dst);
             var src_tv := get_reg_typeval(s, src);
             (ptrornull(dst_tv) ==> dst != R10)
             &&
             (ptrornull(src_tv) ==> src != R10)
    {
        var dst_tv := get_reg_typeval(s, dst);
        var src_tv := get_reg_typeval(s, src);

        match jmpop {
            case JEQ64 =>
                // ptr_or_null == 0
                if (ptrornull(dst_tv) && is_scalar_zero(src_tv))
                then (
                    if (s.jmp_res)
                    then new_state_regonly(s, dst, Scalar(Normal, 0))
                    else new_state_regonly(s, dst, ptrnull_to_ptr(dst_tv))
                )
                //
                // 0 == ptr_or_null
                else if (is_scalar_zero(dst_tv) && ptrornull(src_tv))
                then (
                    if s.jmp_res
                    then new_state_regonly(s, src, Scalar(Normal, 0))
                    else new_state_regonly(s, src, ptrnull_to_ptr(src_tv))
                )
                //
                else s

            case JNE64 =>
                // ptr_or_null != 0
                if (ptrornull(dst_tv) && is_scalar_zero(src_tv))
                then (
                    if (s.jmp_res)
                    then new_state_regonly(s, dst, ptrnull_to_ptr(dst_tv))
                    else new_state_regonly(s, dst, Scalar(Normal, 0))
                )
                //
                // 0 != ptr_or_null
                else if (is_scalar_zero(dst_tv) && ptrornull(src_tv))
                then (
                    if s.jmp_res
                    then new_state_regonly(s, src, ptrnull_to_ptr(src_tv))
                    else new_state_regonly(s, src, Scalar(Normal, 0))
                )
                //
                else s

            case _ => s
        }
    }
    
    ghost function adjust_regtv_for_nullness_imm(
        s:State, jmpop: JMPOP, dst:REG, src_imm:bv64
    ) : (res: State)
    requires var dst_tv := get_reg_typeval(s, dst);
             (ptrornull(dst_tv) ==> dst != R10)
    ensures s.mems == res.mems
    ensures forall r | r != dst :: get_reg_typeval(s, r) == get_reg_typeval(res, r)
    {
        var dst_tv := get_reg_typeval(s, dst);

        match jmpop {
            case JEQ64 =>
                // ptr_or_null == 0
                if (ptrornull(dst_tv) && is_64bit_zero(src_imm))
                then (
                    if (s.jmp_res)
                    then new_state_regonly(s, dst, Scalar(Normal, 0))
                    else new_state_regonly(s, dst, ptrnull_to_ptr(dst_tv))
                )
                else s

            case JNE64 =>
                // ptr_or_null != 0
                if (ptrornull(dst_tv) && is_64bit_zero(src_imm))
                then (
                    if (s.jmp_res)
                    then new_state_regonly(s, dst, ptrnull_to_ptr(dst_tv))
                    else new_state_regonly(s, dst, Scalar(Normal, 0))
                )
                //
                else s

            case _ => s
        }   
    }

    ghost function Exit(s: State) : State
    requires s.R0 != Uninit // complete later
    {s}
}
