include "types.dfy"

module States {

    import opened DataTypes

    datatype State = State (
        R0:  ETYPEV,
        R1:  ETYPEV,
        R2:  ETYPEV,
        R3:  ETYPEV,
        R4:  ETYPEV,
        R5:  ETYPEV,
        R6:  ETYPEV,
        R7:  ETYPEV,
        R8:  ETYPEV,
        R9:  ETYPEV,
        R10: ETYPEV,
        // TODO: keep it or remove it ????
        // Rn:  ETYPEV,

        cfg: ConfigState,
        jmp_res: bool,
        maps_meta: seq<MapState>,

        mems: seq<seq<Mem>>,

        // TODO: keep it or remove?
        rand: bv64
    )

    datatype MemSlot = MemSlot(
        field_perm: ACCESSPERM, // depends on prog types
        etypev: ETYPEV,
        field_size: int
    )

    datatype Mem = Mem(
        mem_type: MEMTYPE,
        // mem_perm: ACCESSPERM,
        is_concur: bool,
        // PTR_TO_MAP_VALUE | PTR_TO_MEM | PTR_TO_BUF
        base: bv64,
        data: seq<MemSlot>
    )

    datatype ConfigState = ConfigState(
        // Env setting
        allow_ptr_leak: bool,
        bypass_spec_v1: bool,
        priv: bool,
        strict_alignment: bool,

        // Prog info
        attachType: AttachTypes,
        progType: ProgTypes,

        // Uploaded map fd array
        map_fd_arr: seq<int64>,

        // endiness
        host_le: bool
    )

    datatype MapState = MapState(
        map_type: MapTypes,
        key_size: int64,
        val_size: int64,
        max_entries: int64,
        map_flag: int64,
        // (map->map_flags & BPF_F_RDONLY_PROG)
        inner_map_fd: int64
    )
}
