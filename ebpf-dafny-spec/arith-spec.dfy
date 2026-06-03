include "utils.dfy"
include "invs.dfy"

module eBPFArithSpec {

    import opened Terms
    import opened DataTypes
    import opened States
    import opened Utils
    import opened InvsForFasterChecker

    // ----------------------------------------------------------------
    // Unary arithmetic instructions operate only on the dst register
    // ----------------------------------------------------------------

    ghost predicate unary_precond(s: State, insn: Instruction)
    {
        exists dst, uop :: (
            insn == ARITHUNARY(dst, uop)
            &&
            sp2_datasafe(s, dst)
            &&
            sp4_vm_integrity(dst)
            &&
            mem_inv(s)
        )
    }
    //
    ghost function arith_unary(s: State, insn: Instruction) : (res: State)
    requires unary_precond(s, insn)
    ensures s.mems == res.mems
    ensures preserve_regs_except_dst(s, res, insn.dst)
    {
        var (dst, uop) := (insn.dst, insn.uop);
        var dst_val := get_reg_arith_val(s, dst);
        
        var new_val := compute_unary(s.cfg.host_le, dst_val, uop);

        var new_reg_tv := Scalar(Normal, new_val);
        new_state_regonly(s, dst, new_reg_tv)
    }


    ghost function compute_unary(
        host_le: bool, dst_val: bv64, uop: ARITHUNARYOP
    ) : bv64
    {
        match uop {
            case NEG32      =>  bvnot32(dst_val)
            case NEG64      =>  bvnot64(dst_val)
            
            case BV2LE16    =>  if host_le
                                then low16(dst_val)
                                else nbytes_wap(dst_val, 2)
            
            case BV2LE32    =>  if host_le
                                then low32(dst_val)
                                else nbytes_wap(dst_val, 4)
            
            case BV2LE64    =>  if host_le
                                then dst_val
                                else nbytes_wap(dst_val, 8)
            
            case BV2BE16    =>  if host_le
                                then nbytes_wap(dst_val, 2)
                                else low16(dst_val)
            
            case BV2BE32    =>  if host_le
                                then nbytes_wap(dst_val, 4)
                                else low32(dst_val)
            
            case BV2BE64    =>  if host_le
                                then nbytes_wap(dst_val, 8)
                                else dst_val
            
            case BV2SWAP16  => nbytes_wap(dst_val, 2)
            case BV2SWAP32  => nbytes_wap(dst_val, 4)
            case BV2SWAP64  => nbytes_wap(dst_val, 8)
        }
    }

    // -----------------------------------------------------------------------
    // Binary arithmetic instructions operate on two registers: src and dst
    // -----------------------------------------------------------------------

    ghost predicate common_binop_reg_precond(s: State, insn: Instruction) : (res: bool)
    {
        exists dst, src, binop :: (
            insn == ARITHBINREG(dst, src, binop)
            &&
            (binop != ADD64 && binop != SUB64)
            &&
            sp4_vm_integrity(dst)
            &&
            mem_inv(s)
            &&
            sp2_datasafe(s, dst)
            &&
            match binop {
                case BVLSHR32 | BVASHR32 | BVSHL32 =>
                    is_scalar(get_reg_typeval(s, src))
                    &&
                    0 <= low32(get_reg_arith_val(s, src)) < 32
                //
                case BVLSHR64 | BVASHR64 | BVSHL64 =>
                    is_scalar(get_reg_typeval(s, src))
                    &&
                    0 <= get_reg_arith_val(s, src) < 64
                //
                case ADD64 | SUB64 => false
                case _ => sp2_datasafe(s, src)
            }
        )
    }

    ghost function arith_binop_reg(s:State, insn: Instruction) : (res: State)
    requires common_binop_reg_precond(s, insn)
    ensures s.mems == res.mems
    ensures preserve_regs_except_dst(s, res, insn.dst)
    {
        var (dst, src, binop) := (insn.dst, insn.src, insn.binop);
        var dst_val := get_reg_arith_val(s, dst);
        var src_val := get_reg_arith_val(s, src);

        var new_val := compute_bin_arith(binop, dst_val, src_val);

        var new_reg_tv := Scalar(Normal, new_val);
        new_state_regonly(s, dst, new_reg_tv)
    }

    // -----------------------------------------------------------------------
    // Binary arithmetic instructions operate on a register and a immidiate
    // -----------------------------------------------------------------------

    ghost predicate common_binop_imm_precond(s: State, insn: Instruction)
    {
        exists dst, src_imm, binop :: (
            insn == ARITHBINIMM(dst, src_imm, binop)
            &&
            (binop != ADD64 && binop != SUB64)
            &&
            var (dst, src_imm, binop) := (insn.dst, insn.src_imm, insn.binop);
            //
            sp4_vm_integrity(dst)
            &&
            sp2_datasafe(s, dst)
            &&
            mem_inv(s)
            &&
            match binop { 
                
                case DIV32 | SDIV32 | MOD32 | SMOD32 =>
                    low32(src_imm) != 0 && twocom2Abs32Bit(src_imm) != 0
               
                case DIV64  | SDIV64 | MOD64 | SMOD64 =>
                    src_imm != 0 && twocom2Abs64Bit(src_imm) != 0
                //
                case BVLSHR32 | BVASHR32 | BVSHL32 =>   0 <= src_imm < 32
                case BVLSHR64 | BVASHR64 | BVSHL64 =>   0 <= src_imm < 64
                //
                case ADD64 | SUB64 => false
                case _ => true
            }
        )
    }
    //
    ghost function arith_binop_imm(s:State, insn: Instruction) : (res: State)
    requires common_binop_imm_precond(s, insn)
    ensures s.mems == res.mems
    ensures preserve_regs_except_dst(s, res, insn.dst)
    {
        var (dst, src_imm, binop) := (insn.dst, insn.src_imm, insn.binop);
        var dst_val := get_reg_arith_val(s, dst);

        var new_val := compute_bin_arith(binop, dst_val, src_imm);

        var new_reg_tv := Scalar(Normal, new_val);
        new_state_regonly(s, dst, new_reg_tv)
    }

    ghost function compute_bin_arith(
        binop: ARITHBINOP, dst_val: bv64, src_val: bv64
    ) : bv64
    requires binop != ADD64 && binop != SUB64
    {
        match binop {
            case ADD32      =>  bvadd32(dst_val, src_val)
            case SUB32      =>  bvsub32(dst_val, src_val)
            case MUL32      =>  bvmul32(dst_val, src_val)
            
            case DIV32      =>  if is_32bit_zero(src_val)
                                then 0x0
                                else bvdiv32(dst_val, src_val)
            
            case SDIV32     =>  if twocom2Abs32Bit(src_val) == 0
                                then 0x0
                                else bvsdiv32(dst_val, src_val)
            
            case MOD32      =>  if is_32bit_zero(src_val)
                                then low32(dst_val)
                                else bvmod32(dst_val, src_val)

            case SMOD32     =>  if twocom2Abs32Bit(src_val) == 0
                                then low32(dst_val)
                                else bvsmod32(dst_val, src_val)
            
            case BVOR32     =>  bvor32(dst_val, src_val)
            case BVAND32    =>  bvand32(dst_val, src_val)
            case BVXOR32    =>  bvxor32(dst_val, src_val)
            case BVLSHR32   =>  bvlshr32(dst_val, src_val)
            case BVASHR32   =>  bvashr32(dst_val, src_val)
            case BVSHL32    =>  bvshl32(dst_val, src_val)

            case MUL64      =>  bvmul64(dst_val, src_val)
            
            case DIV64      =>  if is_64bit_zero(src_val)
                                then 0x0
                                else bvdiv64(dst_val, src_val)
            
            case SDIV64     =>  if twocom2Abs64Bit(src_val) == 0
                                then 0x0
                                else bvsdiv64(dst_val, src_val)
            
            case MOD64      =>  if is_64bit_zero(src_val)
                                then dst_val
                                else bvmod64(dst_val, src_val)
            
            case SMOD64     =>  if twocom2Abs64Bit(src_val) == 0
                                then dst_val
                                else bvsmod64(dst_val, src_val)
            
            case BVOR64     =>  bvor64(dst_val, src_val)
            case BVAND64    =>  bvand64(dst_val, src_val)
            case BVXOR64    =>  bvxor64(dst_val, src_val)
            case BVLSHR64   =>  bvlshr64(dst_val, src_val)
            case BVASHR64   =>  bvashr64(dst_val, src_val)
            case BVSHL64    =>  bvshl64(dst_val, src_val)

            case _          => (
                assert false;
                -1 // unreachable
            )
        }
    }

    // -------------------------------------------------------------------------
    // Special binary arithmetic instructions because of pointers:
    //      ADD64 and SUB64 on (dst, src) or (dst, src_imm)
    // -------------------------------------------------------------------------

    ghost predicate add64_reg_precond(s: State, insn: Instruction)
    {
        exists dst, src :: (
            insn == ARITHBINREG(dst, src, ADD64)
            &&
            sp4_vm_integrity(dst)
            &&
            (
                var dst_tv := get_reg_typeval(s, dst);
                var src_tv := get_reg_typeval(s, src);

                if s.cfg.allow_ptr_leak
                then (
                    dst_tv != Uninit && src_tv != Uninit
                )
                else (
                    (is_ptr(dst_tv) && is_scalar(src_tv))
                    ||
                    (is_scalar(dst_tv) && is_ptr(src_tv))
                    ||
                    (is_scalar(dst_tv) && is_scalar(src_tv))
                )
            )
            &&
            mem_inv(s)
        )
    }
    ghost function add64_reg(s: State, insn: Instruction) : (res: State)
    requires add64_reg_precond(s, insn)
    ensures s.mems == res.mems
    ensures preserve_regs_except_dst(s, res, insn.dst)
    {
        var (dst, src) := (insn.dst, insn.src);
        var dst_tv := get_reg_typeval(s, dst);
        var src_tv := get_reg_typeval(s, src);

        var dst_arith_val := get_reg_arith_val(s, dst);
        var src_arith_val := get_reg_arith_val(s, src);
    
        var new_reg_tv := 
            match (dst_tv, src_tv) {
                case (Scalar(_, val), PtrType(r, memid, off))  => PtrType(
                    r,
                    memid,
                    bvadd64(val, off)
                )
                case (PtrType(r, memid, off), Scalar(_, val))  => PtrType(
                    r,
                    memid,
                    bvadd64(off, val)
                )
                case _ => Scalar(
                    Normal,
                    bvadd64(dst_arith_val, src_arith_val)
                )
            };

        new_state_regonly(s, dst, new_reg_tv)
    }


    ghost predicate add64_imm_precond(s: State, insn: Instruction)
    {
        exists dst, src_imm :: (
            insn == ARITHBINIMM(dst, src_imm, ADD64)
            &&
            sp4_vm_integrity(dst)
            &&
            (
                var dst_tv := get_reg_typeval(s, dst);

                if s.cfg.allow_ptr_leak
                then dst_tv != Uninit
                else is_ptr(dst_tv) || is_scalar(dst_tv)
            )
            &&
            mem_inv(s)
        )
    }
    ghost function add64_imm(s: State, insn: Instruction) : (res: State)
    requires add64_imm_precond(s, insn)
    ensures s.mems == res.mems
    ensures preserve_regs_except_dst(s, res, insn.dst)
    {
        var (dst, src_imm) := (insn.dst, insn.src_imm);
        var dst_tv := get_reg_typeval(s, dst);
        var dst_arith_val := get_reg_arith_val(s, dst);

        var new_reg_tv :=
            match dst_tv {
                case PtrType(r, memid, off) => PtrType(
                    r,
                    memid,
                    bvadd64(off, src_imm)
                )
                case _ => Scalar(Normal, bvadd64(dst_arith_val, src_imm))
            };

        new_state_regonly(s, dst, new_reg_tv)
    }

    
    ghost predicate sub64_reg_precond(s: State, insn: Instruction)
    {
        exists dst, src :: (
            insn == ARITHBINREG(dst, src, SUB64)
            &&
            (
                var src_tv := get_reg_typeval(s, src);
                var dst_tv := get_reg_typeval(s, dst);

                sp4_vm_integrity(dst)
                &&
                (
                    if s.cfg.allow_ptr_leak
                    then (dst_tv != Uninit && src_tv != Uninit)
                    else (
                        (is_ptr(dst_tv) && is_scalar(src_tv))
                        ||
                        (is_scalar(dst_tv) && is_scalar(src_tv))
                        ||
                        (
                            is_ptr(dst_tv) &&
                            is_ptr(src_tv) &&
                            same_mem_region(s, dst, src)
                        )
                    )
                )
            )
            &&
            mem_inv(s)
        )
    }
    ghost function sub64_reg(s: State, insn: Instruction) : (res: State)
    requires sub64_reg_precond(s, insn)
    ensures s.mems == res.mems
    ensures preserve_regs_except_dst(s, res, insn.dst)
    {
        var (dst, src) := (insn.dst, insn.src);

        var dst_arith_val := get_reg_arith_val(s, dst);
        var src_arith_val := get_reg_arith_val(s, src);

        var dst_tv := get_reg_typeval(s, dst);
        var src_tv := get_reg_typeval(s, src);

        var new_reg_tv :=
            match (dst_tv, src_tv) {
                case (PtrType(r, memid, off), Scalar(Normal, val)) => PtrType(
                    r,
                    memid,
                    bvsub64(off, val)
                )
                case _ => Scalar(Normal, bvsub64(dst_arith_val, src_arith_val))
            };
        
        new_state_regonly(s, dst, new_reg_tv)
    }


    ghost predicate sub64_imm_precond(s: State, insn: Instruction)
    {
        exists dst, src_imm :: (
            insn == ARITHBINIMM(dst, src_imm, SUB64)
            &&
            sp4_vm_integrity(dst)
            &&
            (
                var dst_tv := get_reg_typeval(s, dst);

                if s.cfg.allow_ptr_leak
                then dst_tv != Uninit
                else is_ptr(dst_tv) || is_scalar(dst_tv)
            )
            &&
            mem_inv(s)
        )
    }
    ghost function sub64_imm(s: State, insn: Instruction) : (res: State)
    requires sub64_imm_precond(s, insn)
    ensures s.mems == res.mems
    ensures preserve_regs_except_dst(s, res, insn.dst)
    {
        var (dst, src_imm) := (insn.dst, insn.src_imm);
        var dst_tv := get_reg_typeval(s, dst);
        var dst_arith_val := get_reg_arith_val(s, dst);

        var new_reg_tv :=
            match dst_tv {
                case PtrType(r, memid, off) => PtrType(
                    r,
                    memid,
                    bvsub64(off, src_imm)
                )
                case _ => Scalar(Normal, bvsub64(dst_arith_val, src_imm))
            };

        new_state_regonly(s, dst, new_reg_tv)
    }
}
