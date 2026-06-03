include "utils.dfy"

module InvsForFasterChecker {

    import opened Terms
    import opened DataTypes
    import opened States
    import opened Utils

    ghost predicate {:expand} mem_write_preserve_same_field_perm(s: State, s': State)
    {
        forall r, memid, i |
            0 <= r2id(r) < |s.mems|
            &&
            0 <= memid < |s.mems[r2id(r)]|
            &&
            0 <= i < |s.mems[r2id(r)][memid].data|
            ::
            |s.mems| == |s'.mems|
            &&
            |s.mems[r2id(r)]| == |s'.mems[r2id(r)]|
            &&
            |s.mems[r2id(r)][memid].data| == |s'.mems[r2id(r)][memid].data|
            &&
            s.mems[r2id(r)][memid].data[i].field_perm ==
            s'.mems[r2id(r)][memid].data[i].field_perm
    }

    ghost predicate {:expand} preserve_regs(s: State, s': State)
    {
        forall reg :: get_reg_typeval(s, reg) == get_reg_typeval(s', reg)
    }

    ghost predicate mem_write_results_init_slots(
        s': State, addr_tv: ETYPEV, ioff: s16, size: SIZE
    )
    {
        (
            is_ptr(addr_tv) && valid_etypev_if_ptr(s', addr_tv)
        )
        &&
        (
            var (rid, memid, cur_off) := get_ptr_info(addr_tv, ioff);
            var data := s'.mems[rid][memid].data;
            //
            0 < cur_off + size_to_nat(size) <= |data|
            &&
            forall i | 0 <= cur_off <= i < cur_off + size_to_nat(size)
            ::
            data[i].etypev != Uninit
        )
    }

    ghost predicate {:inline} preserve_regs_except_dst(
        s: State, s': State, dst: REG
    )
    {
        forall reg | reg != dst
        :: get_reg_typeval(s, reg) == get_reg_typeval(s', reg)
    }


    ghost predicate {:inline} preserve_regs_except_dst_src(
        s: State, s': State, dst: REG, src: REG
    )
    {
        forall reg | reg != dst && reg != src
        :: get_reg_typeval(s, reg) == get_reg_typeval(s', reg)
    }
}
