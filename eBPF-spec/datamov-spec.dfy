include "utils.dfy"
include "invs.dfy"

module eBPFDataMoveSpec {

    import opened Terms
    import opened DataTypes
    import opened States
    import opened Utils
    import opened InvsForFasterChecker

    ghost predicate datamov_reg_precond(s: State, insn: Instruction)
    {
        exists dst, src, movrop :: (
            insn == DATAMOVREG(dst, src, movrop)
            &&
            sp4_vm_integrity(dst)
            &&
            (
                if movrop == MOV64
                then get_reg_typeval(s, src) != Uninit
                else sp2_datasafe(s, src)
            )
            &&
            mem_inv(s)
        )
    }
    ghost function datamov_reg(s: State, insn: Instruction) : (res: State)
    requires datamov_reg_precond(s, insn)
    ensures s.mems == res.mems
    ensures preserve_regs_except_dst(s, res, insn.dst)
    {
        var (dst, src, movrop) := (insn.dst, insn.src, insn.movrop);
        var src_arith_val := get_reg_arith_val(s, src);

        var new_val := compute_new_dstval(movrop, src_arith_val);

        var new_reg_tv :=
            if movrop == MOV64
            then get_reg_typeval(s, src)
            else Scalar(Normal, new_val);

        new_state_regonly(s, dst, new_reg_tv)
    }

    ghost function compute_new_dstval(movrop: MOVREGOP, arith_val: bv64) : bv64
    {
        match movrop {
            case MOV32       => low32(arith_val)
            
            case MOVSX8TO32  => signext_bits_n2m(arith_val, 8, 32)
    
            case MOVSX16TO32 => signext_bits_n2m(arith_val, 16, 32)
            
            case MOV64       => arith_val
            
            case MOVSX8TO64  => signext_bits_n2m(arith_val, 8, 64)
            
            case MOVSX16TO64 => signext_bits_n2m(arith_val, 16, 64)
                
            case MOVSX32TO64 => signext_bits_n2m(arith_val, 32, 64)
                
        }
    }


    ghost predicate datamov_imm_precond(s: State, insn: Instruction)
    {
        exists dst, src_imm, moviop :: (
            insn == DATAMOVIMM(dst, src_imm, moviop)
            &&
            sp4_vm_integrity(dst)
            &&
            (
                var mapfd := bv64ToInt64(src_imm);
                moviop == LOADMAPFD ==> 0 <= mapfd < |s.maps_meta|
            )
            &&
            (
                var mapfd_idx := bv64ToInt64(src_imm);

                moviop == LOADMAPIDX ==> (
                    0 <= mapfd_idx < |s.cfg.map_fd_arr|
                    &&
                    0 <= s.cfg.map_fd_arr[mapfd_idx] < |s.maps_meta|
                )
            )
        )
    }
    ghost function datamov_imm(s: State, insn: Instruction) : (res: State)
    requires datamov_imm_precond(s, insn)
    ensures s.mems == res.mems
    ensures preserve_regs_except_dst(s, res, insn.dst)
    {
        var (dst, src_imm, moviop) := (insn.dst, insn.src_imm, insn.moviop);
        var src_imm_int64 := bv64ToInt64(src_imm);
        var mapfd := bv64ToInt64(src_imm);
        var mapfd_idx := bv64ToInt64(src_imm);

        var new_reg_tv :=
            match moviop {
                case MOVIMM32       => Scalar(Normal, low32(src_imm))
                case MOVIMM64       => Scalar(Normal, src_imm)
                case LOADIMM64      => Scalar(Normal, src_imm)
                case LOADMAPFD      => PtrType(PTR_TO_MAP_META, mapfd, 0)
                case LOADMAPIDX     => (
                    var memid := s.cfg.map_fd_arr[mapfd_idx];
                    PtrType(PTR_TO_MAP_META, memid, 0)
                )
            };

        new_state_regonly(s, dst, new_reg_tv)
    }
}
