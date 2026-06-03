include "states.dfy"
include "ctxmem-init.dfy"

module MemInit {

    import opened DataTypes
    import opened States
    import opened CTXMemInit

    ghost function init_state(cfg: ConfigState, rand: bv64) : (res: State)
    {
        State(
            R0       := Uninit,
            R1       := PtrType(PTR_TO_CTX, 0, 0),
            R2       := Uninit,
            R3       := Uninit,
            R4       := Uninit,
            R5       := Uninit,
            R6       := Uninit,
            R7       := Uninit,
            R8       := Uninit,
            R9       := Uninit,
            R10      := PtrType(PTR_TO_STACK, 0, 0),

            cfg      := cfg,
            jmp_res  := false,
            maps_meta:= [],

            mems     := seq(18, i => init_a_mem(cfg.progType, cfg.attachType, cfg.priv, i)),

            rand     := rand
        )
    }

    ghost function init_a_mem(
        progType: ProgTypes, attachType: AttachTypes, priv: bool, memrid: int
    ) : seq<Mem>
    {
        var (stack_base, ctx_base) := init_base_addr(512, 0);

        if memrid == r2id(PTR_TO_STACK) then
        [
            Mem(
                mem_type := GENERAL,
                // mem_perm := RDWR,
                is_concur := false,
                base := stack_base,
                data := seq(512, i => MemSlot(RDWR, Uninit, 512-i))
            )
        ]
        else if memrid == r2id(PTR_TO_CTX) then
        [
            Mem(
                mem_type := STRUCT,
                is_concur := false,
                base := ctx_base,
                data := initialize_ctx_mem(progType, attachType, priv)
            )
        ]
        // TODO
        else if memrid == r2id(PTR_TO_PACKET_META) then
        [
            Mem(
                mem_type := RAW,
                is_concur := false,
                base := 1, // or a fresh/base axiom later
                data := []
            )
        ]
        else if memrid == r2id(PTR_TO_PACKET_DATA) then
        [
            Mem(
                mem_type := RAW,
                is_concur := false,
                base := 2,
                data := []
            )
        ]
        else if memrid == r2id(PTR_TO_PACKET_END) then
        [
            Mem(
                mem_type := RAW,
                is_concur := false,
                base := 3,
                data := []
            )
        ]
        else []
    }

    function {:axiom} init_base_addr(
        stack_sz: bv64, ctx_sz: bv64
    ) : (res: (bv64,bv64))
    //
    ensures res.0 != 0 // stack_base
    ensures res.1 != 0 // ctx_base
    ensures var stack_base := res.0;
            var ctx_base := res.1;
            //
            // Non-overlapped memory regions
            stack_base != ctx_base
            &&
            (
                stack_base + stack_sz <= ctx_base
                ||
                ctx_base + ctx_sz <= stack_base
            )
}
