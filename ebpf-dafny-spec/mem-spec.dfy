include "utils.dfy"
include "invs.dfy"

module eBPFMemSpec {

    import opened Terms
    import opened DataTypes
    import opened States
    import opened Utils
    import opened InvsForFasterChecker

    // ----------------------------------------------------------------
    //                          Memory Load
    // ----------------------------------------------------------------

    ghost predicate mem_load_precond(s: State, insn: Instruction)
    {
        // (
        //     exists dst, src, ioff, size, sign_ext :: (
        //         insn == MEMLD(dst, src, ioff, size, sign_ext)
        //     )
        // )
        (
            match insn {
                case MEMLD(_, _, _, _, _) => true
                case _ => false
            }
        )
        &&
        var (dst, src, ioff, size, sign_ext) :=
            (insn.dst, insn.src, insn.ioff, insn.size, insn.sign_ext);
        //
        sp4_vm_integrity(dst)
        &&
        var src_tv := get_reg_typeval(s, src);
        is_ptr(src_tv)
        &&
        mem_inv(s)
        &&
        var (rid, memid, cur_off) := get_ptr_info(src_tv, ioff);
        var sizen := size_to_nat(size);

        var mem_type := s.mems[rid][memid].mem_type;

        // range
        0 <= rid < |s.mems|
        &&
        0 <= memid < |s.mems[rid]|
        &&
        (0 <= cur_off < cur_off + sizen <= |s.mems[rid][memid].data|)
        &&
        // Access within field for structured memory
        (sizen <= s.mems[rid][memid].data[cur_off].field_size)
        &&
        // Alignment
        (
            if mem_type == RAW
            then (s.cfg.strict_alignment ==> (cur_off % sizen) == 0)
            else (cur_off % sizen) == 0
        )
        &&
        // Permission
        (
            // s.mems[rid][memid].mem_perm != NOACCESS
            // &&
            forall i | cur_off <= i < cur_off + sizen ::
                s.mems[rid][memid].data[i].field_perm != NOACCESS
        )
        &&
        // Memory slot type validation
        (
            // Initialized memory slots
            (forall i | cur_off <= i < cur_off + sizen ::
                s.mems[rid][memid].data[i].etypev != Uninit)
            &&
            // No partial read of pointers if without priviledge
            (
                !s.cfg.allow_ptr_leak && size != DW ==> 
                    forall i | cur_off <= i < cur_off + sizen
                    ::
                    is_scalar(s.mems[rid][memid].data[i].etypev)
            )
        )
        &&
        // All accessed slots are in valid types
        access_mem_slots_valid(s, src_tv, ioff, size)
    }

    ghost function {:timeLimit 5} mem_load(
        s: State, insn: Instruction
    ) : (res: State)
    //
    requires mem_load_precond(s, insn)
    ensures s.mems == res.mems
    ensures forall reg | reg != insn.dst
            :: get_reg_typeval(s, reg) == get_reg_typeval(res, reg)
    ensures mem_inv(res)
    ensures var (dst, src, off, size, sign_ext) :=
            (insn.dst, insn.src, insn.ioff, insn.size, insn.sign_ext);
            var src_tv := get_reg_typeval(s, insn.src);
            access_mem_slots_valid(res, src_tv, off, size)
    {
        var (dst, src, off, size, sign_ext) :=
            (insn.dst, insn.src, insn.ioff, insn.size, insn.sign_ext);

        var src_tv := get_reg_typeval(s, src);
        var rid := r2id(src_tv.r);
        var memid := src_tv.memid;
        
        assert {:split_here} true;
        var new_reg_tv :=
            read_n_byte_etypev(s, src_tv, off, size, sign_ext);

        assert {:split_here} true;
        var new_reg_tv' :=
            if s.mems[rid][memid].is_concur
            then sim_concur_mem_val(s, src, size)
            else new_reg_tv;

        assert {:split_here} true;
        new_state_regonly(s, dst, new_reg_tv')
    }

    // ----------------------------------------------------------------
    //                          Memory Store
    // ----------------------------------------------------------------

    ghost predicate mem_store_precond(s: State, insn: Instruction, is_reg: bool)
    {
        (
            if is_reg
            then exists dst, src, ioff, size
                    :: insn == MEMSTX(dst, src, ioff, size)
            else exists dst, src_imm, ioff, size
                    :: insn == MEMST(dst, src_imm, ioff, size)
        )
        &&
        var (dst, ioff, size) := (insn.dst, insn.ioff, insn.size);
        var dst_tv := get_reg_typeval(s, dst);
        is_ptr(dst_tv)
        &&
        mem_inv(s)
        &&
        var (rid, memid, cur_off) := get_ptr_info(dst_tv, ioff);
        var sizen := size_to_nat(size);
        var mem_type := s.mems[rid][memid].mem_type;
        //
        0 <= rid < |s.mems|
        &&
        0 <= memid < |s.mems[rid]|
        &&
        // range
        (0 <= cur_off < cur_off + sizen <= |s.mems[rid][memid].data|)
        && 
        // Access within field for structured memory
        (sizen <= s.mems[rid][memid].data[cur_off].field_size)
        &&
        // Alignment
        (
            match mem_type {
                case GENERAL | STRUCT =>
                    cur_off % size_to_nat(size) == 0
                case RAW => (s.cfg.strict_alignment ==>
                    cur_off % size_to_nat(size) == 0)
            }
        )
        &&
        // Permission
        (
            // s.mems[rid][memid].mem_perm == RDWR
            // &&
            forall i | cur_off <= i < cur_off + sizen ::
                s.mems[rid][memid].data[i].field_perm == RDWR
        )
        &&
        // Src value must be initalized
        (is_reg ==> get_reg_typeval(s, insn.src) != Uninit)
        //
        &&
        // Mem slots and src value type check
        // Purpose: no ptr corruption, and no ptr leakage if without unpriv
        (
            var src_tv :=
                if is_reg
                then get_reg_typeval(s, insn.src)
                else Scalar(Normal, insn.src_imm);

            match mem_type {
                // Cannot partially store a pointer without priv
                // Cannot partially overwrite a pointer without priv
                case GENERAL => (
                    (!s.cfg.allow_ptr_leak && size != DW) ==> (
                        is_scalar(src_tv)
                        &&
                        forall i | cur_off <= i < cur_off + sizen ::
                        !ptr_or_ptrornull(s.mems[rid][memid].data[i].etypev)
                    )   
                )
                /*
                    Types are fixed. Thus,
                    1) pointers can only be overwritten by pointers.
                    2) Scalars can be overwritten by scalars
                    3) Scalars can be overwritten by pointers with priv.
                    4) The modifiability of ptr are decided by perm.
                */
                case STRUCT => (
                    var slot_tv :=
                        s.mems[rid][memid].data[cur_off].etypev;
                    var slots :=
                        s.mems[rid][memid].data[cur_off..(cur_off+sizen)];
                    //
                    // STRUCT doesn't have uninit slots
                    (
                        ptr_or_ptrornull(slot_tv)
                        ||
                        all_slots_scalars(slots)
                    )
                    &&
                    if ptr_or_ptrornull(slot_tv)
                    then size == DW && same_type(slot_tv, src_tv)
                    else (!s.cfg.allow_ptr_leak ==> is_scalar(src_tv))
                )
                // No complete/partial store of ptrs into RAW without priv
                case RAW => (
                    forall i | cur_off <= i < cur_off + sizen
                    ::
                    is_scalar(s.mems[rid][memid].data[i].etypev)
                    &&
                    (!s.cfg.allow_ptr_leak ==> is_scalar(src_tv))
                )
            }
        )
        &&
        access_mem_slots_valid(s, dst_tv, ioff, size)
    }

    ghost predicate mem_store_reg_precond(s: State, insn: Instruction)
    {
        mem_store_precond(s, insn, true)
    }
    ghost predicate mem_store_imm_precond(s: State, insn: Instruction)
    {
        mem_store_precond(s, insn, false)
    }

    ghost function {:timeLimit 5} mem_store_reg(
        s: State, insn: Instruction
    ) : (res: State)
    requires mem_store_reg_precond(s, insn)
    ensures mem_write_preserve_same_field_perm(s, res)
    // ensures mem_write_preserve_regs(s, res)
    // TODO: somehower, use the predicate fails mem_inv(res)
    ensures forall reg
            :: get_reg_typeval(s, reg) == get_reg_typeval(res, reg)
    ensures mem_inv(res)
    ensures mem_write_results_init_slots(
                res, get_reg_typeval(res, insn.dst),
                insn.ioff, insn.size
            )
    {
        var (dst, src, ioff, size) :=
            (insn.dst, insn.src, insn.ioff, insn.size);

        var dst_tv := get_reg_typeval(s, dst);
        var src_tv := get_reg_typeval(s, src);

        assert {:split_here} true;
        update_mem(s, dst_tv, ioff, size, src_tv)
    }

    ghost function {:timeLimit 10} mem_store_imm(
        s: State, insn: Instruction
    ) : (res: State)
    requires mem_store_imm_precond(s, insn)
    ensures forall reg
            :: get_reg_typeval(s, reg) == get_reg_typeval(res, reg)
    ensures mem_inv(res)
    ensures mem_write_preserve_same_field_perm(s, res)
    ensures mem_write_results_init_slots(
                res, get_reg_typeval(res, insn.dst),
                insn.ioff, insn.size
            )
    {
        var (dst, src_imm, ioff, size) :=
            (insn.dst, insn.src_imm, insn.ioff, insn.size);

        var dst_tv := get_reg_typeval(s, dst);

        update_mem(s, dst_tv, ioff, size, Scalar(Normal, src_imm))
    }


    // ----------------------------------------------------------------
    //                     Atomic Memory Load/Store
    // ----------------------------------------------------------------

    ghost predicate mem_atomic_precond(s: State, insn: Instruction)
    {
        exists dst, src, ioff, atsize, op :: (
            insn == ATOMICLS(dst, src, ioff, atsize, op)
            &&
            (atsize == W || atsize == DW)
            &&
            // Cannot overwrite R10
            (
                match op {
                    case ATOMIC_ADD | ATOMIC_AND | ATOMIC_OR |
                         ATOMIC_XOR | ATOMIC_CMPXCHG => true
                    case _ => sp4_vm_integrity(src)
                }
            )
            &&
            var dst_tv := get_reg_typeval(s, dst);
            var src_tv := get_reg_typeval(s, src);
            is_ptr(dst_tv)
            &&
            mem_inv(s)
            &&
            var (rid, memid, cur_off) := get_ptr_info(dst_tv, ioff);
            var sizen := size_to_nat(atsize);
            var mem_type := s.mems[rid][memid].mem_type;
            //
            // Only allow atomic ops on concurrently accessed memory regions
            s.mems[rid][memid].is_concur
            &&
            mem_type == RAW
            &&
            // range
            (0 <= cur_off < cur_off + sizen <= |s.mems[rid][memid].data|)
            && 
            // Access within field for structured memory
            (sizen <= s.mems[rid][memid].data[cur_off].field_size)
            &&
            // alignment
            ((cur_off % sizen) == 0)
            &&
            // Permission
            (
                // s.mems[rid][memid].mem_perm == RDWR
                // &&
                forall i | cur_off <= i < cur_off + sizen ::
                    s.mems[rid][memid].data[i].field_perm == RDWR
            )
            // src reg must be intialized
            &&
            (
                src_tv != Uninit
                &&
                (op == ATOMIC_CMPXCHG ==> s.R0 != Uninit)
            )
            &&
            // Memory slot type validation
            (
                // Initialized memory slots
                (
                    forall i | cur_off <= i < cur_off + sizen
                    ::
                    s.mems[rid][memid].data[i].etypev != Uninit
                )
                &&
                var slot_1st_tv :=
                    s.mems[rid][memid].data[cur_off].etypev;
                var slots :=
                    s.mems[rid][memid].data[cur_off..cur_off+sizen];
                
                match mem_type {
                    
                    case GENERAL =>
                    !s.cfg.allow_ptr_leak ==>
                    (
                        if atsize == DW then
                        (
                            match op {
                                case ATOMIC_ADD | ATOMIC_FETCH_ADD => (
                                    (
                                        is_scalar(src_tv)
                                        &&
                                        all_slots_scalars(slots)
                                    )
                                    ||
                                    (is_scalar(src_tv) && is_ptr(slot_1st_tv))
                                    ||
                                    (is_ptr(src_tv) && all_slots_scalars(slots))
                                )

                                case ATOMIC_CMPXCHG => (
                                    (
                                        is_scalar(src_tv)
                                        &&
                                        all_slots_scalars(slots)
                                    )
                                    ||
                                    (is_ptr(src_tv) && is_ptr(slot_1st_tv))
                                )

                                case ATOMIC_XCHG => true 

                                case _ => (
                                    is_scalar(src_tv)
                                    &&
                                    forall i | cur_off <= i < cur_off + sizen
                                    ::
                                    is_scalar(s.mems[rid][memid].data[i].etypev)
                                )
                            }
                        // No partial read/overwrite of pointers if without priv
                        // No partial store of a pointer if without priv
                        ) else (
                            is_scalar(src_tv) && all_slots_scalars(slots)
                        )
                    )

                    case STRUCT =>
                    (
                        if ptr_or_ptrornull(slot_1st_tv)
                        then
                            // No partial read/overwrite of ptr without priv
                            // No partial store of a ptr if without priv
                            // TODO: Q: why even remove atsize == DW,
                            //  the non-leak proof still succeeds
                            (atsize == DW)
                            &&
                            match op {
                                case ATOMIC_ADD | ATOMIC_FETCH_ADD => 
                                    is_scalar(src_tv)
                                
                                case ATOMIC_XCHG | ATOMIC_CMPXCHG =>
                                    same_type(slot_1st_tv, src_tv)
                                
                                case _ => false
                            }
                        // No partial store of a pointer if without priv
                        else !s.cfg.allow_ptr_leak ==> is_scalar(src_tv)
                    )

                    case RAW =>
                    (
                        all_slots_scalars(slots)
                        &&
                        // No partial store of a pointer if without priv
                        (!s.cfg.allow_ptr_leak ==> is_scalar(src_tv))
                    )
                }
                &&
                // R0: cannot compare a ptr (R0) without priv
                (
                    (
                        op == ATOMIC_CMPXCHG
                        &&
                        ptr_or_ptrornull(slot_1st_tv)
                    ) ==> is_scalar(s.R0)
                )
                //
                // case GENERAL => (
                //     // no priv => (
                //     //     if size == DW then ..
                //     //     else
                //     //         load scalar
                //     //         store scalar
                //     // )
                //     // with priv => whatever
                // )
                // case STRUCT => (
                //     // slot ptr -> add scalar, XCHG/CMPXCHG ptr
                //     // scalar ptr -> no priv: src, scalar
                // )
                // case RAW => (
                //     // load scalar
                //     // store scalar
                // )
                //
                &&
                access_mem_slots_valid(s, dst_tv, ioff, atsize)
            )
        )
    }

    ghost function {:timeLimit 3} mem_atomic(
        s: State, insn: Instruction
    ) : (res: State)
    requires mem_atomic_precond(s, insn)
    /*
    ensures match insn.op {
                case ATOMIC_ADD | ATOMIC_AND |
                        ATOMIC_OR | ATOMIC_XOR =>
                        forall reg
                        :: get_reg_typeval(s, reg) == get_reg_typeval(res, reg)

                case ATOMIC_FETCH_ADD | ATOMIC_FETCH_AND | 
                        ATOMIC_FETCH_OR | ATOMIC_FETCH_XOR  |
                        ATOMIC_XCHG =>
                        forall reg | reg != insn.src
                        :: get_reg_typeval(s, reg) == get_reg_typeval(res, reg)

                case ATOMIC_CMPXCHG =>
                    forall reg | reg != R0
                    :: get_reg_typeval(s, reg) == get_reg_typeval(res, reg)
            }
    */
    // ensures forall reg | reg != R0 && reg != insn.src
    //             :: get_reg_typeval(s, reg) == get_reg_typeval(res, reg)
    // ensures mem_inv(res)
    // ensures mem_write_preserve_same_field_perm(s, res)
    // ensures mem_write_results_init_slots(
    //             res, get_reg_typeval(s, insn.dst),
    //             insn.ioff, insn.size
    //         )
    {
        var (dst, src, ioff, size, op) :=
            (insn.dst, insn.src, insn.ioff, insn.size, insn.op);

        var dst_tv := get_reg_typeval(s, dst);
        
        assert {:split_here} true;
        // Atomic accesses are only on concurrent memory
        // as required in the precond
        var sim_slot_tv := sim_concur_mem_val(s, dst, size);

        assert {:split_here} true;
        var store_val_tv :=
            cal_atomic_store_tv(s, op, size, src, sim_slot_tv);

        assert {:split_here} true;
        var s' := update_mem(s, dst_tv, ioff, size, store_val_tv);

        // Load slot data to reg
        match op {
            
            case ATOMIC_FETCH_ADD | ATOMIC_FETCH_OR | ATOMIC_FETCH_AND |
                 ATOMIC_FETCH_XOR | ATOMIC_XCHG =>
                 new_state_regonly(s', src, sim_slot_tv)
            
            case ATOMIC_CMPXCHG =>
                s'.(R0 := sim_slot_tv)
            
            case _ => s'
        }
    }

    // ----------------------------------------------------------------
    //                          Memory Operation Helper
    // ----------------------------------------------------------------

    ghost function {:timeLimit 3} cal_atomic_store_tv(
        s: State, op: ATOMICOP, size: SIZE,
        src: REG, sim_slot_tv: ETYPEV
    ) : (res: ETYPEV)
    //
    requires var src_tv := get_reg_typeval(s, src);
             src_tv != Uninit && valid_etypev_if_ptr(s, src_tv)
    //
    requires sim_slot_tv != Uninit
    requires valid_etypev_if_ptr(s, sim_slot_tv)
    //
    ensures res != Uninit
    ensures valid_etypev_if_ptr(s, res)
    {
        var src_tv := get_reg_typeval(s, src);

        assert {:split_here} true;
        var src_arith_val := get_reg_arith_val(s, src);
        assert {:split_here} true;
        var sim_arith_val := get_arith_val(s, sim_slot_tv);

        assert {:split_here} true;
        var kind := 
            match (sim_slot_tv, src_tv) {
                case (Scalar(k1, _), Scalar(k2, _)) =>
                    if k1 == k2 then k1 else Normal
            case _ => Normal
        };

        assert {:split_here} true;

        match op {
            case ATOMIC_ADD | ATOMIC_FETCH_ADD =>
                match (size, sim_slot_tv, src_tv) {
                    
                    case (DW, Scalar(k1, v1), Scalar(k2, v2)) =>
                        var new_tv :=
                            if k1==k2
                            then Scalar(
                                k1,
                                bvadd64(sim_arith_val, src_arith_val)
                            )
                            else Scalar(
                                Normal,
                                bvadd64(sim_arith_val, src_arith_val)
                            );
                        //
                        assert {:split_here} new_tv != Uninit;
                        assert {:split_here} valid_etypev_if_ptr(s, new_tv);
                        new_tv
                    
                    case (DW, Scalar(k3, v3), PtrType(r3, memid3, off3)) =>
                        var new_tv := PtrType(r3, memid3, bvadd64(off3, v3));
                        //
                        assert {:split_here} new_tv != Uninit;
                        assert {:split_here} new_tv != Uninit;
                        assert {:split_here} is_ptr(src_tv) && valid_etypev_if_ptr(s, src_tv);
                        assert {:split_here} 0 <= r2id(new_tv.r) < |s.mems|;
                        assert {:split_here} 0 <= new_tv.memid < |s.mems[r2id(new_tv.r)]|;
                        assert {:split_here} valid_etypev_if_ptr(s, new_tv);
                        new_tv
                    
                    case (DW, PtrType(r4, memid4, off4), Scalar(k4, v4)) =>
                        var new_tv := PtrType(r4, memid4, bvadd64(off4, v4));
                        //
                        assert {:split_here} new_tv != Uninit;
                        assert {:split_here} is_ptr(sim_slot_tv) && valid_etypev_if_ptr(s, sim_slot_tv);
                        assert {:split_here} 0 <= r2id(new_tv.r) < |s.mems|;
                        assert {:split_here} 0 <= new_tv.memid < |s.mems[r2id(new_tv.r)]|;
                        assert {:split_here} valid_etypev_if_ptr(s, new_tv);
                        new_tv
                    
                    case (_, _, _) =>
                        var new_tv := Scalar(
                            Normal,
                            bvadd64(sim_arith_val, src_arith_val)
                        );
                        //
                        assert {:split_here} new_tv != Uninit;
                        assert {:split_here} valid_etypev_if_ptr(s, new_tv);
                        new_tv
                }
                
            case ATOMIC_OR  | ATOMIC_FETCH_OR  =>
                var new_tv := Scalar(
                    kind,
                    bvor64(sim_arith_val, src_arith_val)
                );
                //
                assert {:split_here} new_tv != Uninit;
                assert {:split_here} valid_etypev_if_ptr(s, new_tv);
                new_tv
            
            case ATOMIC_AND | ATOMIC_FETCH_AND =>
                var new_tv := Scalar(
                    kind,
                    bvand64(sim_arith_val, src_arith_val)
                );
                //
                assert {:split_here} new_tv != Uninit;
                assert {:split_here} valid_etypev_if_ptr(s, new_tv);
                new_tv
            
            case ATOMIC_XOR | ATOMIC_FETCH_XOR =>
                var new_tv := Scalar(
                    kind,
                    bvxor64(sim_arith_val, src_arith_val)
                );
                //
                assert {:split_here} new_tv != Uninit;
                assert {:split_here} valid_etypev_if_ptr(s, new_tv);
                new_tv
            
            case ATOMIC_XCHG | ATOMIC_CMPXCHG    =>  src_tv
        }
    }

    ghost function {:timeLimit 5} update_mem(
        s: State, addr_tv: ETYPEV,
        ioff: s16, size:SIZE, src_tv: ETYPEV
    ) : (res: State)
    // reg
    requires src_tv != Uninit
    requires valid_etypev_if_ptr(s, src_tv)
    //
    // memory
    requires is_ptr(addr_tv) && valid_etypev_if_ptr(s, addr_tv)
    requires access_mem_slots_valid(s, addr_tv, ioff, size)
    //
    requires var (rid, memid, cur_off) := get_ptr_info(addr_tv, ioff);
             forall i | cur_off <= i < cur_off + size_to_nat(size)
             :: s.mems[rid][memid].data[i].field_perm == RDWR
    //
    ensures is_ptr(addr_tv) && valid_etypev_if_ptr(res, addr_tv)
    ensures access_mem_slots_valid(res, addr_tv, ioff, size)
    //
    // ensures var (rid, memid, cur_off) := get_ptr_info(addr_tv, ioff);
    //         forall i | cur_off <= i < cur_off + size_to_nat(size)
    //         :: res.mems[rid][memid].data[i].etypev != Uninit
    {
        var (rid, memid, cur_off) := get_ptr_info(addr_tv, ioff);

        var data := s.mems[rid][memid].data;
        var mem_type := s.mems[rid][memid].mem_type;
        var slot_tv := data[cur_off].etypev;
        var sizen := size_to_nat(size);

        var src_arith_val := get_arith_val(s, src_tv);
        var new_slot_kind := if is_scalar(src_tv) then src_tv.kind else Normal;
        
        var old_slot_kind := if is_scalar(slot_tv) then slot_tv.kind else Normal;

        assert {:split_here} true;

        var new_data :=
        // 8-byte (scalar/ptr) write on GENERAL or STRUCT memory
        // Specifically deal with 8-byte pointers
        if size == DW && mem_type != RAW then
        (
            assert {:split_here} true;
            var new_slots_tv := reg_to_8byte_data(s, src_tv);
            assert {:split_here} |new_slots_tv| == size_to_nat(size);
            
            // assert {:split_here}
            //     access_slots_valid(s, addr_tv, off, size);

            assert {:split_here} valid_ptr_etypvs(s, new_slots_tv, size);

            assert {:split_here} true;
            update_mem_slots(s, mem_type, data, cur_off, size, new_slots_tv)
        )
        // GENERAL or STRUCT
        // Partially overwrites pointer slots
        else if ptr_or_ptrornull(slot_tv) && mem_type != RAW then
        (
            assert {:split_here} true;

            // | scalar -> slot type | reg -> slots  | scalar -> slot type  |
            // | [0, ...             | [off % 8, ... | [off % 8 + sizen, 8] |
            var alg_off := cur_off - (cur_off % 8);

            assert {:split_here} (
                0 <= alg_off < alg_off + 8 <= |data|
                &&
                ptr_slots_same_type_perm(data, cur_off, size)
                &&
                forall i | alg_off <= i < alg_off + 8
                ::
                ptr_or_ptrornull(data[i].etypev)
            ) by {
                valid_ptr_slots_implies_8_bytes(s, addr_tv, ioff, size);
            }

            var val_8b := read_8_byte_data(data, alg_off);
            var ptr_val := s.mems[rid][memid].base + val_8b;

            assert {:split_here} true;

            var new_slots_tv :=
                scalar_etypev_to_seq(
                    Scalar(Normal, ptr_val),
                    cur_off - alg_off, 0
                )
                +
                scalar_etypev_to_seq(
                    Scalar(new_slot_kind, src_arith_val),
                    sizen, 0
                )
                +
                scalar_etypev_to_seq(
                    Scalar(Normal, ptr_val),
                    (8 - (cur_off - alg_off) - sizen),
                    (cur_off % 8 + sizen)
                );
            assert {:split_here} true;

            assert {:split_here} valid_ptr_etypvs(s, new_slots_tv, DW);

            assert {:split_here} forall i | 0 <= i < 8
                    :: is_scalar(new_slots_tv[i]);
            
            update_mem_slots(s, mem_type, data, alg_off, DW, new_slots_tv)
        )
        // GENERAL, STRUCT: Non-eight bytes writes at non-pointer slots
        // RAW: All writes
        else
        (
            assert {:split_here} true;
            var kind :=
                if mem_type == STRUCT then old_slot_kind else new_slot_kind;
            
            var new_slots_tv := scalar_etypev_to_seq(
                Scalar(kind, src_arith_val),
                sizen, 0
            );
            
            assert {:split_here} valid_ptr_etypvs(s, new_slots_tv, size);

            assert {:split_here} true;
            update_mem_slots(s, mem_type, data, cur_off, size, new_slots_tv)
        );
        
        update_a_mem_in_state(s, addr_tv, new_data)
    }
}
