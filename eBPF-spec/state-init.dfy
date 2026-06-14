include "utils.dfy"

/*
    State initialization helpers.

    Used by the C++ emitter (itm_state_2_dafny_new) to reconstruct a
    verifier state at an intermediate checkpoint.  These functions are
    intentionally lighter on preconditions than the runtime memory‐spec
    functions because during initialization the full mem_inv may not
    yet hold.
*/
module StateInit {

    import opened DataTypes
    import opened States
    import opened Utils

    // ----------------------------------------------------------------
    //  Byte decomposition of an ETYPEV — same semantics as
    //  reg_to_8byte_data but does NOT require valid_etypev_if_ptr,
    //  so it is safe to call during state initialisation when the
    //  memory regions may not be fully populated yet.
    // ----------------------------------------------------------------
    ghost function init_spill_bytes(reg_tv: ETYPEV) : (res: seq<ETYPEV>)
        requires reg_tv != Uninit
        ensures  |res| == 8
    {
        match reg_tv {

            case Scalar(k, v) => [
                Scalar(k, get_nth_byte(v, 0)),
                Scalar(k, get_nth_byte(v, 1)),
                Scalar(k, get_nth_byte(v, 2)),
                Scalar(k, get_nth_byte(v, 3)),
                Scalar(k, get_nth_byte(v, 4)),
                Scalar(k, get_nth_byte(v, 5)),
                Scalar(k, get_nth_byte(v, 6)),
                Scalar(k, get_nth_byte(v, 7))
            ]

            case PtrType(r, memid, off) => [
                PtrType(r, memid, get_nth_byte(off, 0)),
                PtrType(r, memid, get_nth_byte(off, 1)),
                PtrType(r, memid, get_nth_byte(off, 2)),
                PtrType(r, memid, get_nth_byte(off, 3)),
                PtrType(r, memid, get_nth_byte(off, 4)),
                PtrType(r, memid, get_nth_byte(off, 5)),
                PtrType(r, memid, get_nth_byte(off, 6)),
                PtrType(r, memid, get_nth_byte(off, 7))
            ]

            case PtrOrNullType(r, memid, off) => [
                PtrOrNullType(r, memid, get_nth_byte(off, 0)),
                PtrOrNullType(r, memid, get_nth_byte(off, 1)),
                PtrOrNullType(r, memid, get_nth_byte(off, 2)),
                PtrOrNullType(r, memid, get_nth_byte(off, 3)),
                PtrOrNullType(r, memid, get_nth_byte(off, 4)),
                PtrOrNullType(r, memid, get_nth_byte(off, 5)),
                PtrOrNullType(r, memid, get_nth_byte(off, 6)),
                PtrOrNullType(r, memid, get_nth_byte(off, 7))
            ]

            case _ => (
                assert false;   // Uninit already excluded by requires
                []
            )
        }
    }

    // ----------------------------------------------------------------
    //  Spill a full 8‐byte register to consecutive stack slots.
    //  Writes base_slot .. base_slot+7 in mems[rid][stackIdx].data.
    // ----------------------------------------------------------------
    ghost function init_spill_to_stack(
        s: State, stackIdx: nat, base_slot: nat, reg_tv: ETYPEV
    ) : (res: State)
        requires reg_tv != Uninit
        requires r2id(PTR_TO_STACK) < |s.mems|
        requires stackIdx < |s.mems[r2id(PTR_TO_STACK)]|
        requires base_slot + 8 <= |s.mems[r2id(PTR_TO_STACK)][stackIdx].data|
        //
        ensures  |res.mems| == |s.mems|
    {
        var rid  := r2id(PTR_TO_STACK);
        var mem  := s.mems[rid][stackIdx];
        var data := mem.data;
        var bytes := init_spill_bytes(reg_tv);

        var new_data :=
            data
            [base_slot + 0 := data[base_slot + 0].(etypev := bytes[0])]
            [base_slot + 1 := data[base_slot + 1].(etypev := bytes[1])]
            [base_slot + 2 := data[base_slot + 2].(etypev := bytes[2])]
            [base_slot + 3 := data[base_slot + 3].(etypev := bytes[3])]
            [base_slot + 4 := data[base_slot + 4].(etypev := bytes[4])]
            [base_slot + 5 := data[base_slot + 5].(etypev := bytes[5])]
            [base_slot + 6 := data[base_slot + 6].(etypev := bytes[6])]
            [base_slot + 7 := data[base_slot + 7].(etypev := bytes[7])];

        s.(mems := s.mems[rid :=
                       s.mems[rid][stackIdx :=
                           mem.(data := new_data)
                       ]
                   ])
    }

    // ----------------------------------------------------------------
    //  Set a single stack byte's ETYPEV.
    // ----------------------------------------------------------------
    ghost function init_set_stack_byte(
        s: State, stackIdx: nat, slot_off: nat, tv: ETYPEV
    ) : (res: State)
        requires r2id(PTR_TO_STACK) < |s.mems|
        requires stackIdx < |s.mems[r2id(PTR_TO_STACK)]|
        requires slot_off < |s.mems[r2id(PTR_TO_STACK)][stackIdx].data|
        //
        ensures  |res.mems| == |s.mems|
    {
        var rid  := r2id(PTR_TO_STACK);
        var mem  := s.mems[rid][stackIdx];
        var new_data := mem.data[slot_off := mem.data[slot_off].(etypev := tv)];

        s.(mems := s.mems[rid :=
                       s.mems[rid][stackIdx :=
                           mem.(data := new_data)
                       ]
                   ])
    }
}
