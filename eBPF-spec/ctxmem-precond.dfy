include "types.dfy"

predicate context_access_safe(progType: ProgTypes, off1: int64, size1: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // Access check 1: size is correct
        (size1 == 1 || size1 == 2 || size1 == 4 || size1 == 8)
        &&
        // Access check 2: access is aligned
        (off1 % size1 == 0)
        &&
        // Access check 3: access the bounded field, which is checked checked per program type below
        match progType {
            case BPF_PROG_TYPE_SOCKET_FILTER                => sk_filter_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_SCHED_CLS                    => tc_cls_act_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_SCHED_ACT                    => tc_cls_act_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_XDP                          => xdp_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_CGROUP_SKB                   => cg_skb_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_CGROUP_SOCK                  => sock_filter_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_CGROUP_SOCK_ADDR             => sock_addr_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_LWT_IN                       => lwt_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_LWT_OUT                      => lwt_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_LWT_XMIT                     => lwt_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_LWT_SEG6LOCAL                => lwt_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_SOCK_OPS                     => sock_ops_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_SK_SKB                       => sk_skb_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_SK_MSG                       => sk_msg_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_FLOW_DISSECTOR               => flow_dissector_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_KPROBE                       => kprobe_prog_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_TRACEPOINT                   => tp_prog_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_PERF_EVENT                   => pe_prog_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_RAW_TRACEPOINT               => raw_tp_prog_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE      => raw_tp_writable_prog_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_TRACING                      => tracing_prog_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_CGROUP_DEVICE                => cgroup_dev_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_CGROUP_SYSCTL                => sysctl_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_CGROUP_SOCKOPT               => cg_sockopt_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_LIRC_MODE2                   => lirc_mode2_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_SK_REUSEPORT                 => sk_reusepor_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_SK_LOOKUP                    => sk_lookup_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_STRUCT_OPS                   => false // No ctx memory
            case BPF_PROG_TYPE_EXT                          => false // No ctx memory
            case BPF_PROG_TYPE_LSM                          => btf_ctx_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_SYSCALL                      => syscall_prog_CTX(off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_NETFILTER                    => nf_CTX(off1, size1, acct, attachType, priv)
        }
    }

function context_load_type(dstRegType: REGTYPE, progType: ProgTypes, off1: int64, size1: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        // Access check 3: access the bounded field, which is checked checked per program type below
        match progType {
            case BPF_PROG_TYPE_SOCKET_FILTER                => sk_filter_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_SCHED_CLS                    => tc_cls_act_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_SCHED_ACT                    => tc_cls_act_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_XDP                          => xdp_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_CGROUP_SKB                   => cg_skb_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_CGROUP_SOCK                  => cg_skb_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_CGROUP_SOCK_ADDR             => sock_addr_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_LWT_IN                       => lwt_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_LWT_OUT                      => lwt_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_LWT_XMIT                     => lwt_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_LWT_SEG6LOCAL                => lwt_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_SOCK_OPS                     => sock_ops_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_SK_SKB                       => sk_skb_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_SK_MSG                       => sk_msg_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_FLOW_DISSECTOR               => flow_dissector_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_KPROBE                       => kprobe_prog_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_TRACEPOINT                   => tp_prog_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_PERF_EVENT                   => pe_prog_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_RAW_TRACEPOINT               => raw_tp_prog_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE      => raw_tp_writable_prog_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_TRACING                      => tracing_prog_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_CGROUP_DEVICE                => cgroup_dev_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_CGROUP_SYSCTL                => sysctl_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_CGROUP_SOCKOPT               => cg_sockopt_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_LIRC_MODE2                   => lirc_mode2_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_SK_REUSEPORT                 => sk_reusepor_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_SK_LOOKUP                    => sk_lookup_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_STRUCT_OPS                   => dstRegType == SCALAR // No ctx memory, just placeholder
            case BPF_PROG_TYPE_EXT                          => dstRegType == SCALAR // No ctx memory, just placeholder
            case BPF_PROG_TYPE_LSM                          => btf_ctx_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_SYSCALL                      => syscall_prog_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
            case BPF_PROG_TYPE_NETFILTER                    => nf_retval_CTX(dstRegType, off1, size1, acct, attachType, priv)
        }
    }

predicate narrow_4_read_from_off(off1: int64, size1: int64, off: int64, acct: ACCESSTYPE)
    {
        (size1 == 1 || size1 == 2 || size1 == 4) &&
        (off == off1 < off1 + size1 <= (off + 4)) &&
        acct == READ
    }

// [off, off+4): access bounded memory with size 1,2,4
predicate narrow_4_read(off1: int64, size1: int64, off: int64, acct: ACCESSTYPE)
    {
        (size1 == 1 || size1 == 2 || size1 == 4) &&
        (off <= off1 < off1 + size1 <= (off + 4)) &&
        // (off1 % size1 == 0)                      && 
        acct == READ
    }

// [off, off+4): access bounded memory with size 4
predicate exact_4_read(off1: int64, size1: int64, off: int64, acct: ACCESSTYPE)
    {
        (off1 == off && size1 == 4 && acct == READ)
    }

// [off, off+4): access bounded memory with size 8
predicate exact_8_read(off1: int64, size1: int64, off: int64, acct: ACCESSTYPE)
    {
        (off1 == off && size1 == 8 && acct == READ)
    }

predicate exact_N_read(off1: int64, size1: int64, off: int64, acct: ACCESSTYPE, size:int64)
    {
        (off1 == off && size1 == size && acct == READ)
    }

// [off, off+8): access bounded memory with size 1,2,4
predicate narrow_8_read(off1: int64, size1: int64, off: int64, acct: ACCESSTYPE)
    {
        (size1 == 1 || size1 == 2 || size1 == 4 || size1 == 8) &&
        (off <= off1 < off1 + size1 <= (off + 8)) &&
        // (off1 % size1 == 0)                      &&
        (acct == READ)
    }

predicate exact_4_write(off1: int64, size1: int64, off: int64, acct: ACCESSTYPE)
    {
        (off1 == off && size1 == 4 && acct == WRITE)
    }

predicate exact_8_write(off1: int64, size1: int64, off: int64, acct: ACCESSTYPE)
    {
        (off1 == off && size1 == 8 && acct == WRITE)
    }

predicate narrow4R_exact4W(off1: int64, size1: int64, off: int64, acct: ACCESSTYPE)
    {
        narrow_4_read(off1, size1, off, acct) || exact_4_write(off1, size1, off, acct)
    }

predicate exact4R_exact4W(off1: int64, size1: int64, off: int64, acct: ACCESSTYPE)
    {
        exact_4_read(off1, size1, off, acct) || exact_4_write(off1, size1, off, acct)
    }

predicate narrow8R_exact8W(off1: int64, size1: int64, off: int64, acct: ACCESSTYPE)
    {
        narrow_8_read(off1, size1, off, acct) || exact_8_write(off1, size1, off, acct)
    }

predicate exact8R_exact8W(off1: int64, size1: int64, off: int64, acct: ACCESSTYPE)
    {
        exact_8_read(off1, size1, off, acct) || exact_8_write(off1, size1, off, acct)
    }

// read range [start, end)
predicate range_read(off1: int64, size1: int64, start: int64, end: int64, acct: ACCESSTYPE)
    {
        (start <= off1 < off1 + size1 <= end) && (acct == READ) // && (size1 == 1 || size1 == 2 || size1 == 4 || size1 == 8)
    }

predicate range_read_write(off1: int64, size1: int64, start: int64, end: int64, acct: ACCESSTYPE)
    {
        (start <= off1 < off1 + size1 <= end) && (acct == READ || acct == WRITE) // && (size1 == 1 || size1 == 2 || size1 == 4 || size1 == 8)
    }

///////////////////////////// Constraints of context access in different program types ////////////////////////////////

predicate sk_filter_CTX (off: int64, size: int64, acct:ACCESSTYPE, attachType: AttachTypes, priv: bool)
    // requires 0 <= off <= 180
    {
        // struct __sk_buff
        
        // len
        narrow_4_read(off, size, 0, acct)  ||
        
        // ptk_type
        narrow_4_read(off, size, 4, acct)  ||
        
        // mark
        narrow_4_read(off, size, 8, acct)  ||
        
        // queue_mapping
        narrow_4_read(off, size, 12, acct) ||
        
        // protocol
        narrow_4_read(off, size, 16, acct) ||
        
        // vlan_present
        narrow_4_read(off, size, 20, acct) ||
        
        // vlan_tci
        narrow_4_read(off, size, 24, acct) ||
        
        // vlan_proto
        narrow_4_read(off, size, 28, acct) ||
        
        // priority
        narrow_4_read(off, size, 32, acct) ||
        
        // ingress_ifindex
        narrow_4_read(off, size, 36, acct) ||
        
        // ifindex
        narrow_4_read(off, size, 40, acct) ||
        
        // tc_index
        narrow_4_read(off, size, 44, acct) ||
        
        // cb[5]
        // Any algined read/write size (1,2,4,8) as long as within the bound
        range_read_write(off, size, 48, 68, acct) ||
        
        // hash
        narrow_4_read(off, size, 68, acct) ||
        
        // tc_classid, data, data_end are forbidden
        //

        // napi_id
        narrow_4_read(off, size, 84, acct) ||
        
        // TODO: check which fields are skipped ???
        
        // gso_segs
        narrow_4_read(off, size, 164, acct) ||
        
        // sk
        exact_8_read(off, size, 168, acct) ||
        
        // gso_size
        narrow_4_read(off, size, 176, acct)
    }

function sk_filter_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct:ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        if exact_8_read(off, size, 168, acct) then dstRegType == PTR_TO_SOCK_COMMON || dstRegType == NULL
        else dstRegType == SCALAR
    }


predicate tc_cls_act_CTX (off: int64, size: int64, acct:ACCESSTYPE, attachType: AttachTypes, priv: bool)
    // requires 0 <= off <= 192
    {
        // struct __sk_buff
        // len
        narrow_4_read(off, size, 0, acct) ||
        
        // pkt_type
        narrow_4_read(off, size, 4, acct) ||
        
        // mark
        narrow4R_exact4W(off, size, 8, acct) ||
        
        // queue_mapping
        narrow4R_exact4W(off, size, 12, acct) ||
        
        // protocol
        narrow_4_read(off, size, 16, acct) ||
        
        // vlan_present
        narrow_4_read(off, size, 20, acct) ||
        
        // vlan_tci
        narrow_4_read(off, size, 24, acct) ||
        
        // vlan_proto
        narrow_4_read(off, size, 28, acct) ||
        
        // priority
        narrow4R_exact4W(off, size, 32, acct) ||
        
        // ingress_ifindex
        narrow_4_read(off, size, 36, acct) ||
        
        // 40 4 ifindex
        narrow_4_read(off, size, 40, acct) ||
        
        // 44 4 tc_index
        narrow4R_exact4W(off, size, 44, acct) ||
        
        // 48 20 cb[5]
        // Any algined read/write size (1,2,4,8) as long as within the bound
        range_read_write(off, size, 48, 68, acct) ||
        
        // 68 4 hash
        narrow_4_read(off, size, 68, acct) ||
        
        // 72 4 tc_classid
        narrow4R_exact4W(off, size, 72, acct) ||
        
        // 76 4 data
        exact_4_read(off, size, 76, acct) ||
        
        // 80 4 data_end
        exact_4_read(off, size, 80, acct) ||
        
        // 88 4  napi_id
        narrow_4_read(off, size, 84, acct) ||
        
        //
        // 88 4 family
        // 92 4 remote_ip4
        // 96 4 local_ip4
        // 100 16 remote_ip6[4]
        // 116 16 local_ip6[4]
        // 132 4 remote_port
        // 136 4 local_port
        //
        
        // 140 4 data_meta
        exact_4_read(off, size, 140, acct) ||
        
        // 144 8 flow_keys
        
        // 152 8 tstamp
        exact8R_exact8W(off, size, 152, acct) ||
        
        // 160 4 wire_len
        narrow_4_read(off, size, 160, acct) ||
        
        // 164 gso_segs
        narrow_4_read(off, size, 164, acct) ||
        
        // 168 8 sk
        exact_8_read(off, size, 168, acct) ||
        
        // 176 4 gso_size
        narrow_4_read(off, size, 176, acct) ||
        
        // 180 1 tstamp_type
        exact_N_read(off, size, 180, acct, 1) ||
        
        // padding 24bit
        
        // 184 8 hwtstamp
        exact_8_read(off, size, 184, acct)
    }

function tc_cls_act_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct:ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        // 76 4 data
        if exact_4_read(off, size, 76, acct) then dstRegType == PTR_TO_PACKET
        
        // 80 4 data_end
        else if exact_4_read(off, size, 80, acct) then dstRegType == PTR_TO_PACKET_END

        // 140 4 data_meta
        else if exact_4_read(off, size, 140, acct) then dstRegType == PTR_TO_PACKET_META

        // 168 8 sk
        else if exact_8_read(off, size, 168, acct) then dstRegType == PTR_TO_SOCK_COMMON || dstRegType == NULL

        else dstRegType == SCALAR
    }

predicate xdp_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // 0 4 data
        exact_4_read(off, size, 0, acct)
        ||

        // 4 4 data_end
        exact_4_read(off, size, 4, acct)
        ||

        // 8 4 data_meta
        exact_4_read(off, size, 8, acct)
        ||

        // 12 4 ingress_ifindex
        exact_4_read(off, size, 12, acct)
        ||

        // 16 4 rx_queue_index
        // TODO

        // 20 4 egress_ifindex
        (exact_4_read(off, size, 20, acct) && attachType == BPF_XDP_DEVMAP)
    }

function xdp_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        // 0 4 data
        if exact_4_read(off, size, 0, acct) then dstRegType == PTR_TO_PACKET
        // 4 4 data_end
        else if exact_4_read(off, size, 4, acct) then dstRegType == PTR_TO_PACKET_END
        // 8 4 data_meta
        else if exact_4_read(off, size, 8, acct) then dstRegType == PTR_TO_PACKET_META
        //
        else dstRegType == SCALAR
    }

predicate cg_skb_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // __sk_buff
        
        // 0 4 len
        narrow_4_read(off, size, 0, acct) ||
        
        // 4 4 pkt_type
        narrow_4_read(off, size, 4, acct) ||
        
        // 8 4 mark
        narrow4R_exact4W(off, size, 8, acct) ||
        
        // 12 4 queue_mapping
        narrow_4_read(off, size, 12, acct) ||
        
        // 16 4 protocol
        narrow_4_read(off, size, 16, acct) ||
        
        // 20 4 vlan_present
        narrow_4_read(off, size, 20, acct) ||
        
        // 24 4 vlan_tci
        narrow_4_read(off, size, 24, acct) ||
        
        // 28 4 vlan_proto
        narrow_4_read(off, size, 28, acct) ||

        // 32 4 priority
        narrow4R_exact4W(off, size, 32, acct) ||

        // 36 4 ingress_ifindex
        narrow_4_read(off, size, 36, acct) ||

        // 40 4 ifindex
        narrow_4_read(off, size, 40, acct) ||

        // 44 4 tc_index
        narrow_4_read(off, size, 44, acct) ||

        // 48 20 cb[5]
        // Any algined read/write size (1,2,4,8) as long as within the bound
        range_read_write(off, size, 48, 68, acct) ||

        // 68 4 hash
        narrow_4_read(off, size, 68, acct) ||
    
        // 72 4 tc_classid

        // 76 4 data
        (exact_4_read(off, size, 76, acct) && priv ) ||

        // 80 4 data_end
        (exact_4_read(off, size, 80, acct) && priv) ||

        // 84 4 napi_id
        narrow_4_read(off, size, 84, acct) ||

        // 88 4 family
        narrow_4_read(off, size, 88, acct) ||

        // 92 4 remote_ip4
        exact_4_read(off, size, 92, acct) ||

        // 96 4 local_ip4
        exact_4_read(off, size, 96, acct) ||

        // 100 16 remote_ip6[4]
        exact_4_read(off, size, 100, acct) ||
        exact_4_read(off, size, 104, acct) ||
        exact_4_read(off, size, 108, acct) ||
        exact_4_read(off, size, 112, acct) ||

        // 116 16 local_ip6[4]
        exact_4_read(off, size, 116, acct) ||
        exact_4_read(off, size, 120, acct) ||
        exact_4_read(off, size, 124, acct) ||
        exact_4_read(off, size, 128, acct) ||

        // 132 4 remote_port
        narrow_4_read(off, size, 132, acct) ||

        // 136 4 local_port
        narrow_4_read(off, size, 136, acct) ||

        // 140 4 data_meta

        // 144 8 flow_keys

        // 152 8 tstamp
        exact_8_read(off, size, 152, acct) ||
        (exact_8_write(off, size, 152, acct) && priv) ||

        // 160 4 wire_len

        // 164 gso_segs
        narrow_4_read(off, size, 164, acct) ||

        // 168 8 sk
        exact_8_read(off, size, 168, acct) ||

        // 176 4 gso_size
        narrow_4_read(off, size, 176, acct) ||

        // 180 1 tstamp_type

        // padding 24bit

        // 184 8 hwtstamp
        exact_8_read(off, size, 184, acct)
    }

function cg_skb_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        // 76 4 data
        if (exact_4_read(off, size, 76, acct) && priv ) then dstRegType == PTR_TO_PACKET

        // 80 4 data_end
        else if (exact_4_read(off, size, 80, acct) && priv) then dstRegType == PTR_TO_PACKET_END

        // 168 8 sk
        else if exact_8_read(off, size, 168, acct) then dstRegType == PTR_TO_SOCK_COMMON || dstRegType == NULL
        
        else dstRegType == SCALAR
    }


predicate sock_filter_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // struct bpf_sock

        // 0 4 bound_dev_if
        (exact_4_read(off, size, 0, acct) && (
            attachType == BPF_CGROUP_INET_SOCK_CREATE ||
            attachType == BPF_CGROUP_INET_SOCK_RELEASE)
        )
        ||
        (exact_4_write(off, size, 0, acct) && (
            attachType == BPF_CGROUP_INET_SOCK_CREATE ||
            attachType == BPF_CGROUP_INET_SOCK_RELEASE)
        )
        ||

        // 4 4 family
        narrow_4_read_from_off(off, size, 4, acct) ||

        // 8 4 type
        narrow_4_read_from_off(off, size, 8, acct) ||

        // 12 4 protocol
        narrow_4_read_from_off(off, size, 12, acct) ||

        // 16 4 mark
        (exact_4_read(off, size, 16, acct) && (
            attachType == BPF_CGROUP_INET_SOCK_CREATE ||
            attachType == BPF_CGROUP_INET_SOCK_RELEASE)
        )
        ||
        (exact_4_write(off, size, 16, acct) && (
            attachType == BPF_CGROUP_INET_SOCK_CREATE ||
            attachType == BPF_CGROUP_INET_SOCK_RELEASE)
        )
        ||

        // 20 4 priority
        (exact_4_read(off, size, 20, acct) && (
            attachType == BPF_CGROUP_INET_SOCK_CREATE ||
            attachType == BPF_CGROUP_INET_SOCK_RELEASE)
        )
        ||
        (exact_4_write(off, size, 20, acct) && (
            attachType == BPF_CGROUP_INET_SOCK_CREATE ||
            attachType == BPF_CGROUP_INET_SOCK_RELEASE)
        )
        ||

        // 24 4 src_ip4
        (narrow_4_read(off, size, 24, acct) && (attachType == BPF_CGROUP_INET4_POST_BIND)) ||

        // 28 16 src_ip6[4]
        (narrow_4_read(off, size, 28, acct) && (attachType == BPF_CGROUP_INET6_POST_BIND)) ||
        (narrow_4_read(off, size, 32, acct) && (attachType == BPF_CGROUP_INET6_POST_BIND)) ||
        (narrow_4_read(off, size, 36, acct) && (attachType == BPF_CGROUP_INET6_POST_BIND)) ||
        (narrow_4_read(off, size, 40, acct) && (attachType == BPF_CGROUP_INET6_POST_BIND)) ||

        // 44 4 src_port
        (narrow_4_read_from_off(off, size, 44, acct) && (attachType == BPF_CGROUP_INET4_POST_BIND || attachType == BPF_CGROUP_INET6_POST_BIND)) ||

        // 48 2 dst_port
        (off == 48 && (size == 4 || size == 2) && acct == READ)
        ||

        // 52 4 dst_ip4
        narrow_4_read(off, size, 52, acct) ||

        // 56 16 dst_ip6[4]
        narrow_4_read(off, size, 56, acct) ||
        narrow_4_read(off, size, 60, acct) ||
        narrow_4_read(off, size, 64, acct) ||
        narrow_4_read(off, size, 68, acct) ||

        // 72 4 state
        narrow_4_read_from_off(off, size, 72, acct) ||

        // 76 4 rx_queue_mapping
        narrow_4_read_from_off(off, size, 76, acct)
    }

function sock_filter_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        dstRegType == SCALAR
    }

predicate sock_addr_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // struct bpf_sock_addr

        // 0 4 user_family
        exact_4_read(off, size, 0, acct)
        ||

        // 4 4 user_ip4
        (
            (
                narrow_4_read(off, size, 4, acct)   ||  exact_4_write(off, size, 4, acct)
            )
            &&
            (
                (attachType == BPF_CGROUP_INET4_BIND)         ||
                (attachType == BPF_CGROUP_INET4_CONNECT)      ||
                (attachType == BPF_CGROUP_INET4_GETPEERNAME)  ||
                (attachType == BPF_CGROUP_INET4_GETSOCKNAME)  ||
                (attachType == BPF_CGROUP_UDP4_SENDMSG)       ||
                (attachType == BPF_CGROUP_UDP4_RECVMSG)
            )
        )
        ||

        // 8 16 user_ip6[4]
        // READ
        (
            (
                narrow4R_exact4W(off, size, 8, acct)    ||  exact8R_exact8W(off, size, 8, acct) ||
                narrow4R_exact4W(off, size, 12, acct)   ||
                narrow4R_exact4W(off, size, 16, acct)   ||  exact8R_exact8W(off, size, 16, acct) ||
                narrow4R_exact4W(off, size, 20, acct)
            )
            &&
            (
                (attachType == BPF_CGROUP_INET6_BIND)          ||
                (attachType == BPF_CGROUP_INET6_CONNECT)       ||
                (attachType == BPF_CGROUP_INET6_GETPEERNAME)   ||
                (attachType == BPF_CGROUP_INET6_GETSOCKNAME)   ||
                (attachType == BPF_CGROUP_UDP6_SENDMSG)        ||
                (attachType == BPF_CGROUP_UDP6_RECVMSG)
            )
        )
        ||

        // 24 4 user_port
        narrow_4_read(off, size, 24, acct)
        ||
        exact_4_write(off, size, 24, acct)
        ||

        // 28 4 family
        exact_4_read(off, size, 28, acct)
        ||

        // 32 4 type
        exact_4_read(off, size, 32, acct)
        ||

        // 36 4 protocol
        exact_4_read(off, size, 36, acct)
        ||

        // 40 4 msg_src_ip4
        (narrow4R_exact4W(off, size, 40, acct) && (attachType == BPF_CGROUP_UDP4_SENDMSG))
        ||

        // 44 16 msg_src_ip6[4]
        (
            (
                narrow4R_exact4W(off, size, 44, acct)   ||  exact8R_exact8W(off, size, 44, acct)    ||
                narrow4R_exact4W(off, size, 48, acct)   ||
                narrow4R_exact4W(off, size, 52, acct)   ||  exact8R_exact8W(off, size, 52, acct)    ||
                narrow4R_exact4W(off, size, 56, acct)
                
            )
            &&
            (attachType == BPF_CGROUP_UDP6_SENDMSG)
        )
        ||

        // 60 8 sk
        exact_8_read(off, size, 60, acct)
    }

function sock_addr_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        // 60 8 sk
        if exact_8_read(off, size, 60, acct) then dstRegType == PTR_TO_SOCKET
        else dstRegType == SCALAR
    }

predicate lwt_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // struct __sk_buff
        // 0 4 len
        narrow_4_read(off, size, 0, acct)
        ||

        // 4 4 pkt_type
        narrow_4_read(off, size, 4, acct)
        ||

        // 8 4 mark
        narrow4R_exact4W(off, size, 8, acct)
        ||

        // 12 4 queue_mapping
        narrow_4_read(off, size, 12, acct)
        ||

        // 16 4 protocol
        narrow_4_read(off, size, 16, acct)
        ||

        // 20 4 vlan_present
        narrow_4_read(off, size, 20, acct)
        ||

        // 24 4 vlan_tci
        narrow_4_read(off, size, 24, acct)
        ||

        // 28 4 vlan_proto
        narrow_4_read(off, size, 28, acct)
        ||

        // 32 4 priority
        narrow4R_exact4W(off, size, 32, acct)
        ||

        // 36 4 ingress_ifindex
        narrow_4_read(off, size, 36, acct)
        ||

        // 40 4 ifindex
        narrow_4_read(off, size, 40, acct)
        ||

        // 44 4 tc_index
        narrow_4_read(off, size, 44, acct)
        ||

        // 48 20 cb[5]
        // Any algined read/write size (1,2,4,8) as long as within the bound
        range_read_write(off, size, 48, 68, acct)
        ||

        // 68 4 hash
        narrow_4_read(off, size, 68, acct)
        ||

        // 72 4 tc_classid

        // 76 4 data
        exact_4_read(off, size, 76, acct)
        ||

        // 80 4 data_end
        exact_4_read(off, size, 80, acct)
        ||

        // 84 4 napi_id
        narrow_4_read(off, size, 84, acct)
        ||

        // 88 4 family
        // 92 4 remote_ip4
        // 96 4 local_ip4
        // 100 16 remote_ip6[4]
        // 116 16 local_ip6[4]
        // 132 4 remote_port
        // 136 4 local_port
        // 140 4 data_meta
        // 144 8 flow_keys
        // 152 8 tstamp
        // 160 4 wire_len
        
        // 164 gso_segs
        narrow_4_read(off, size, 164, acct)
        ||

        // 168 8 sk
        exact_8_read(off, size, 168, acct)
        ||

        // 176 4 gso_size
        narrow_4_read(off, size, 176, acct)

        // 180 1 tstamp_type
        // padding 24bit
        // 184 8 hwtstamp
    }

function lwt_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        // 76 4 data
        if exact_4_read(off, size, 76, acct) then dstRegType == PTR_TO_PACKET
        
        // 80 4 data_end
        else if exact_4_read(off, size, 80, acct) then dstRegType == PTR_TO_PACKET_END

        // 168 8 sk
        else if exact_8_read(off, size, 168, acct) then dstRegType == PTR_TO_SOCK_COMMON || dstRegType == NULL

        else dstRegType == SCALAR
    }

predicate sock_ops_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // struct bpf_sock_ops

        // 0 4 op
        exact_4_read(off, size, 0, acct)
        ||

        // 4 16 union
        exact4R_exact4W(off, size, 4, acct)
        ||
        exact_4_read(off, size, 8, acct)
        ||
        exact_4_read(off, size, 12, acct)
        ||
        exact_4_read(off, size, 16, acct)
        ||

        // 20 4 family
        exact_4_read(off, size, 20, acct)
        ||

        // 24 4 remote_ip4
        exact_4_read(off, size, 24, acct)
        ||

        // 28 4 local_ip4
        exact_4_read(off, size, 28, acct)
        ||

        // 32 16 remote_ip6[4]
        exact_4_read(off, size, 32, acct)
        ||
        exact_4_read(off, size, 36, acct)
        ||
        exact_4_read(off, size, 40, acct)
        ||
        exact_4_read(off, size, 44, acct)
        ||

        // 48 16 local_ip6[4]
        exact_4_read(off, size, 48, acct)
        ||
        exact_4_read(off, size, 52, acct)
        ||
        exact_4_read(off, size, 56, acct)
        ||
        exact_4_read(off, size, 60, acct)
        ||

        // 64 4 remote_port
        exact_4_read(off, size, 64, acct)
        ||

        // 68 4 local_port
        exact_4_read(off, size, 68, acct)
        ||

        // 72 4 is_fullsock
        exact_4_read(off, size, 72, acct)
        ||

        // 76 4 snd_cwnd
        exact_4_read(off, size, 76, acct)
        ||

        // 80 4 srtt_us
        exact_4_read(off, size, 80, acct)
        ||

        // 84 4 bpf_sock_ops_cb_flags
        exact_4_read(off, size, 84, acct)
        ||

        // 88 4 state
        exact_4_read(off, size, 88, acct)
        ||

        // 92 4 rtt_min
        exact_4_read(off, size, 92, acct)
        ||

        // 96 4 snd_ssthresh
        exact_4_read(off, size, 96, acct)
        ||

        // 100 4 rcv_nxt
        exact_4_read(off, size, 100, acct)
        ||

        // 104 4 snd_nxt;
        exact_4_read(off, size, 104, acct)
        ||

        // 108 4 snd_una
        exact_4_read(off, size, 108, acct)
        ||

        // 112 4 mss_cache
        exact_4_read(off, size, 112, acct)
        ||

        // 116 4 ecn_flags
        exact_4_read(off, size, 116, acct)
        ||

        // 120 4 rate_delivered
        exact_4_read(off, size, 120, acct)
        ||

        // 124 4 rate_interval_us
        exact_4_read(off, size, 124, acct)
        ||

        // 128 4 packets_out
        exact_4_read(off, size, 128, acct)
        ||

        // 132 4 retrans_out
        exact_4_read(off, size, 132, acct)
        ||

        // 136 4 total_retrans
        exact_4_read(off, size, 136, acct)
        ||

        // 140 4 segs_in
        exact_4_read(off, size, 140, acct)
        ||

        // 144 4 data_segs_in
        exact_4_read(off, size, 144, acct)
        ||

        // 148 4 segs_out
        exact_4_read(off, size, 148, acct)
        ||

        // 152 4 data_segs_out
        exact_4_read(off, size, 152, acct)
        ||

        // 156 4 lost_out
        exact_4_read(off, size, 156, acct)
        ||

        // 160 4 sacked_out
        exact_4_read(off, size, 160, acct)
        ||

        // 164 4 sk_txhash
        exact4R_exact4W(off, size, 164, acct)
        ||

        // 168 8 bytes_received
        exact_8_read(off, size, 168, acct)
        ||

        // 176 8 bytes_acked
        exact_8_read(off, size, 176, acct)
        ||

        // 184 8 sk
        exact_8_read(off, size, 184, acct)
        ||

        // 192 8 skb_data
        exact_8_read(off, size, 192, acct)
        ||

        // 200 8 skb_data_end
        exact_8_read(off, size, 200, acct)
        ||

        // 208 4 skb_len
        exact_4_read(off, size, 208, acct)
        ||

        // 212 4 skb_tcp_flags
        narrow_4_read(off, size, 212, acct)
        ||

        // 216 8 skb_hwtstamp
        exact_8_read(off, size, 216, acct)
    }

function sock_ops_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        // 184 8 sk
        if exact_8_read(off, size, 184, acct) then dstRegType == PTR_TO_SOCKET || dstRegType == NULL

        // 192 8 skb_data
        else if exact_8_read(off, size, 192, acct) then dstRegType == PTR_TO_PACKET

        // 200 8 skb_data_end
        else if exact_8_read(off, size, 200, acct) then dstRegType == PTR_TO_PACKET_END
        
        else dstRegType == SCALAR
    }

predicate sk_skb_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // struct __sk_buff
        // 0 4 len
        narrow_4_read(off, size, 0, acct)
        ||

        // 4 4 pkt_type
        narrow_4_read(off, size, 4, acct)
        ||

        // 8 4 mark

        // 12 4 queue_mapping
        narrow_4_read(off, size, 12, acct)
        ||

        // 16 4 protocol
        narrow_4_read(off, size, 16, acct)
        ||

        // 20 4 vlan_present
        narrow_4_read(off, size, 20, acct)
        ||

        // 24 4 vlan_tci
        narrow_4_read(off, size, 24, acct)
        ||

        // 28 4 vlan_proto
        narrow_4_read(off, size, 28, acct)
        ||

        // 32 4 priority
        narrow4R_exact4W(off, size, 32, acct)
        ||

        // 36 4 ingress_ifindex
        narrow_4_read(off, size, 36, acct)
        ||

        // 40 4 ifindex
        narrow_4_read(off, size, 40, acct)
        ||

        // 44 4 tc_index
        narrow4R_exact4W(off, size, 44, acct)
        ||

        // 48 20 cb[5]
        // Any algined read/write size (1,2,4,8) as long as within the bound
        range_read(off, size, 48, 68, acct)
        ||

        // 68 4 hash
        narrow_4_read(off, size, 68, acct)
        ||

        // 72 4 tc_classid

        // 76 4 data
        exact_4_read(off, size, 76, acct)
        ||
        
        // 80 4 data_end
        exact_4_read(off, size, 80, acct)
        ||

        // 84 4 napi_id
        narrow_4_read(off, size, 84, acct)
        ||

        // 88 4 family
        narrow_4_read(off, size, 88, acct)
        ||

        // 92 4 remote_ip4
        exact_4_read(off, size, 92, acct)
        ||

        // 96 4 local_ip4
        exact_4_read(off, size, 96, acct)
        ||

        // 100 16 remote_ip6[4]
        exact_4_read(off, size, 100, acct)
        ||
        exact_4_read(off, size, 104, acct)
        ||
        exact_4_read(off, size, 108, acct)
        ||
        exact_4_read(off, size, 112, acct)
        ||

        // 116 16 local_ip6[4]
        exact_4_read(off, size, 116, acct)
        ||
        exact_4_read(off, size, 120, acct)
        ||
        exact_4_read(off, size, 124, acct)
        ||
        exact_4_read(off, size, 128, acct)
        ||

        // 132 4 remote_port
        narrow_4_read(off, size, 132, acct)
        ||

        // 136 4 local_port
        narrow_4_read(off, size, 136, acct)
        ||

        // 140 4 data_meta

        // 144 8 flow_keys

        // 152 8 tstamp

        // 160 4 wire_len

        // 164 gso_segs
        narrow_4_read(off, size, 164, acct)
        ||

        // 168 8 sk
        exact_8_read(off, size, 168, acct)
        ||

        // 176 4 gso_size
        narrow_4_read(off, size, 176, acct)

        // 180 1 tstamp_type

        // padding 24bit

        // 184 8 hwtstamp
    }

function sk_skb_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        // 76 4 data
        if exact_4_read(off, size, 76, acct) then dstRegType == PTR_TO_PACKET
        
        // 80 4 data_end
        else if exact_4_read(off, size, 80, acct) then dstRegType == PTR_TO_PACKET_END

        // 168 8 sk
        else if exact_8_read(off, size, 168, acct) then dstRegType == PTR_TO_SOCK_COMMON || dstRegType == NULL
        
        else dstRegType == SCALAR
    }

predicate sk_msg_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // 0 8 data
        exact_8_read(off, size, 0, acct)
        ||

        // 8 8 data_end
        exact_8_read(off, size, 8, acct)
        ||

        // 16 4 family
        exact_4_read(off, size, 16, acct)
        ||
        
        // 20 4 remote_ip4
        exact_4_read(off, size, 20, acct)
        ||

        // 24 4 local_ip4
        exact_4_read(off, size, 24, acct)
        ||

        // 28 16 remote_ip6[4]
        exact_4_read(off, size, 28, acct)
        ||
        exact_4_read(off, size, 32, acct)
        ||
        exact_4_read(off, size, 36, acct)
        ||
        exact_4_read(off, size, 40, acct)
        ||
        
        // 44 16 local_ip6[4]
        exact_4_read(off, size, 44, acct)
        ||
        exact_4_read(off, size, 48, acct)
        ||
        exact_4_read(off, size, 52, acct)
        ||
        exact_4_read(off, size, 56, acct)
        ||

        // 60 4 remote_port
        exact_4_read(off, size, 60, acct)
        ||

        // 64 4 local_port
        exact_4_read(off, size, 64, acct)
        ||

        // 68 4 size
        exact_4_read(off, size, 68, acct)
        ||

        // 72 8 sk
        exact_8_read(off, size, 72, acct)
    }

function sk_msg_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        // 0 8 data
        if exact_8_read(off, size, 0, acct) then dstRegType == PTR_TO_PACKET

        // 8 8 data_end
        else if exact_8_read(off, size, 8, acct) then dstRegType == PTR_TO_PACKET_END
        
        // 72 8 sk
        else if exact_8_read(off, size, 72, acct) then dstRegType == PTR_TO_SOCKET

        else dstRegType == SCALAR
    }

predicate flow_dissector_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // struct __sk__buff

        // 76 4 data
        exact_4_read(off, size, 76, acct)
        ||
        
        // 80 4 data_end
        exact_4_read(off, size, 80, acct)
        ||

        // 144 8 flow_keys
        exact_8_read(off, size, 144, acct)
    }

function flow_dissector_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        // 76 4 data
        if exact_4_read(off, size, 76, acct) then dstRegType == PTR_TO_PACKET
        
        // 80 4 data_end
        else if exact_4_read(off, size, 80, acct) then dstRegType == PTR_TO_PACKET_END

        // 144 8 flow_keys
        else if exact_8_read(off, size, 144, acct) then dstRegType == PTR_TO_FLOW_KEYS

        else dstRegType == SCALAR
    }

predicate kprobe_prog_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // struct pt_regs (Different across arches)
        // x86_64: 168 bytes
        range_read(off, size, 0, 168, acct)
    }

function kprobe_prog_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        dstRegType == SCALAR
    }

predicate tp_prog_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // Disucssion: since the first 8 byte is not readable and writable,
        //              why pass it to the user. Why not pass the pointer from ptr+8
        range_read(off, size, 8, 8192, acct)
    }

function tp_prog_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        dstRegType == SCALAR
    }

predicate pe_prog_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // struct bpf_perf_event_data
        //
        (range_read(off, size, 0, 168, acct) && (size == 8))
        ||
        narrow_8_read(off, size, 168, acct)
        ||
        narrow_8_read(off, size, 176, acct)
    }

function pe_prog_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        dstRegType == SCALAR
    }

predicate raw_tp_prog_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        range_read(off, size, 0, 96, acct)
    }

function raw_tp_prog_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        dstRegType == SCALAR
    }

predicate raw_tp_writable_prog_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        exact_8_read(off, size, 0, acct)
        ||
        range_read(off, size, 1, 96, acct)
    }

function raw_tp_writable_prog_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        if exact_8_read(off, size, 0, acct) then dstRegType == PTR_TO_TP_BUFFER
        else dstRegType == SCALAR
    }

predicate tracing_prog_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // TODO
        false
    }

function tracing_prog_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        // TODO
        dstRegType == SCALAR
    }

predicate cgroup_dev_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // struct bpf_cgroup_dev_ctx

        // 0 4 access_type
        narrow_4_read(off, size, 0, acct)
        ||

        // 4 4 major
        exact_4_read(off, size, 4, acct)
        ||

        // 8 4 minor
        exact_4_read(off, size, 8, acct)
    }

function cgroup_dev_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        dstRegType == SCALAR
    }

predicate sysctl_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // struct bpf_sysctl
        // 0 4 write
        narrow_4_read(off, size, 0, acct)
        ||

        // 4 4 file_pos
        narrow4R_exact4W(off, size, 4, acct)
    }

function sysctl_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        dstRegType == SCALAR
    }

predicate cg_sockopt_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // struct bpf_sockopt
        // 0 8 sk
        exact_8_read(off, size, 0, acct)
        ||

        // 8 8 optval
        exact_8_read(off, size, 8, acct)
        ||

        // 16 8 optval_end
        exact_8_read(off, size, 16, acct)
        ||

        /// 24 4 level
        exact_4_read(off, size, 24, acct)
        ||
        (exact_4_write(off, size, 24, acct) && attachType == BPF_CGROUP_SETSOCKOPT)
        ||

        // 28 4 optname
        exact_4_read(off, size, 28, acct)
        ||
        (exact_4_write(off, size, 28, acct) && attachType == BPF_CGROUP_SETSOCKOPT)
        ||

        // 32 4 optlen
        exact4R_exact4W(off, size, 32, acct)
        ||

        // 36 4 retval
        (exact4R_exact4W(off, size, 36, acct) && attachType == BPF_CGROUP_SETSOCKOPT)
    }

function cg_sockopt_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        // 0 8 sk
        if exact_8_read(off, size, 0, acct) then dstRegType == PTR_TO_SOCKET

        // 8 8 optval
        else if exact_8_read(off, size, 8, acct) then dstRegType == PTR_TO_PACKET

        // 16 8 optval_end
        else if exact_8_read(off, size, 16, acct) then dstRegType == PTR_TO_PACKET_END

        else dstRegType == SCALAR
    }

predicate lirc_mode2_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        exact_4_read(off, size, 4, acct)
    }

function lirc_mode2_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        dstRegType == SCALAR
    }

predicate sk_reusepor_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // struct sk_reuseport_md
        // 0 8 data
        exact_8_read(off, size, 0, acct)
        ||

        // 8 8 data_end
        exact_8_read(off, size, 8, acct)
        ||

        // 16 4 len
        narrow_4_read(off, size, 16, acct)
        ||

        // 20 4 eth_protocol
        // Wrong one: exact_4_read(off, size, 20, acct) => corrected as below:
        ((size == 2 || size == 4) && (20 <= off < off + size <= 24) && acct == READ)
        ||

        // 24 4 ip_protocol
        narrow_4_read(off, size, 24, acct)
        ||

        // 28 4 bind_inany
        narrow_4_read(off, size, 28, acct)
        ||

        // 32 4 hash
        exact_4_read(off, size, 32, acct)
        ||

        // there is 4-byte padding for alignment in c

        // 40 8 sk
        exact_8_read(off, size, 40, acct)
        ||

        // 48 8 migrating_sk
        exact_8_read(off, size, 48, acct)
    }

function sk_reusepor_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        // 0 8 data
        if exact_8_read(off, size, 0, acct) then dstRegType == PTR_TO_PACKET

        // 8 8 data_end
        else if exact_8_read(off, size, 8, acct) then dstRegType == PTR_TO_PACKET_END

        // 40 8 sk
        else if exact_8_read(off, size, 40, acct) then dstRegType == PTR_TO_SOCKET

        // 48 8 migrating_sk
        else if exact_8_read(off, size, 48, acct) then dstRegType == PTR_TO_SOCK_COMMON || dstRegType == NULL

        else dstRegType == SCALAR
    }

predicate sk_lookup_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // struct bpf_sk_lookup
        
        // 0, 8 sk
        exact_8_read(off, size, 0, acct)
        ||

        // 8 4 family
        narrow_4_read(off, size, 8, acct)
        ||

        // 12 4 protocol
        narrow_4_read(off, size, 12, acct)
        ||
        
        // 16 4 remote_ip4
        narrow_4_read(off, size, 16, acct)
        ||

        // 20 16 remote_ip6[4]
        narrow_4_read(off, size, 20, acct)
        ||
        narrow_4_read(off, size, 24, acct)
        ||
        narrow_4_read(off, size, 28, acct)
        ||
        narrow_4_read(off, size, 32, acct)
        ||

        // 36 2 remote_port
        (off == 36 && (size == 2 || size == 1) && acct == READ)
        ||
        (off == 37 && size == 1 && acct == READ)
        ||

        // 40 4 local_ip4
        narrow_4_read(off, size, 40, acct)
        ||

        // 44 16 local_ip6[4]
        narrow_4_read(off, size, 44, acct)
        ||
        narrow_4_read(off, size, 48, acct)
        ||
        narrow_4_read(off, size, 52, acct)
        ||
        narrow_4_read(off, size, 56, acct)
        ||

        // 60 4 local_port
        narrow_4_read(off, size, 60, acct)
        ||

        // 64 4 ingress_ifindex
        narrow_4_read(off, size, 64, acct)
    }

function sk_lookup_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        // 0, 8 sk
        if exact_8_read(off, size, 0, acct) then dstRegType == PTR_TO_SOCKET || dstRegType == NULL
        else dstRegType == SCALAR
    }

predicate btf_ctx_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // TODO
        false
    }

function btf_ctx_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        // TODO
        dstRegType == SCALAR
    }

predicate syscall_prog_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // Any algined read/write size (1,2,4,8) as long as within the bound
        range_read_write(off, size, 0, 65535, acct)
    }

function syscall_prog_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        dstRegType == SCALAR
    }

predicate nf_CTX (off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool)
    {
        // struct bpf_nf_ctx
        exact_8_read(off, size, 0, acct)
        ||
        exact_8_read(off, size, 8, acct)
    }

function nf_retval_CTX (dstRegType: REGTYPE, off: int64, size: int64, acct: ACCESSTYPE, attachType: AttachTypes, priv: bool) : bool
    {
        dstRegType == SCALAR
    }