include "states.dfy"

module CTXMemInit {

    import opened DataTypes
    import opened States

    ghost function scalar_n_field(perm: ACCESSPERM, n: int) : seq<MemSlot>
    {
        scalar_n_field_kind(perm, Normal, n)
    }

    ghost function scalar_n_field_kind(perm: ACCESSPERM, k: Kinds, n: int) : seq<MemSlot>
    {
        if n <= 0 then [] else seq(n, i => MemSlot(perm, Scalar(k, 0), n - i))
    }

    ghost function scalar4_field(perm: ACCESSPERM) : seq<MemSlot>
    {
        scalar_n_field(perm, 4)
    }

    ghost function scalar8_field(perm: ACCESSPERM) : seq<MemSlot>
    {
        scalar_n_field(perm, 8)
    }

    ghost function special_ptr_scalar4_field(perm: ACCESSPERM) : seq<MemSlot>
    {
        scalar_n_field_kind(perm, SpecialPtr, 4)
    }

    ghost function scalar4_fields(perm: ACCESSPERM, count: int) : seq<MemSlot>
    {
        if count <= 0 then [] else seq(4 * count, i => MemSlot(perm, Scalar(Normal, 0), 4 - i % 4))
    }

    ghost function noaccess(n: int) : seq<MemSlot>
    {
        if n <= 0 then [] else seq(n, i => MemSlot(NOACCESS, Uninit, 0))
    }

    ghost function ptr8_field(perm: ACCESSPERM, r: MemRegion) : seq<MemSlot>
    {
        seq(8, i => MemSlot(perm, PtrType(r, 0, 0), 8 - i))
    }

    ghost function ptr_or_null8_field(perm: ACCESSPERM, r: MemRegion) : seq<MemSlot>
    {
        seq(8, i => MemSlot(perm, PtrOrNullType(r, 0, 0), 8 - i))
    }

    ghost function maybe(cond: bool, field: seq<MemSlot>) : seq<MemSlot>
    {
        if cond then field else noaccess(|field|)
    }

    ghost function sk_buff_prefix(
        mark: seq<MemSlot>,
        queue_mapping: seq<MemSlot>,
        priority: seq<MemSlot>,
        tc_index: seq<MemSlot>,
        cb: seq<MemSlot>
    ) : seq<MemSlot>
    {
        // struct __sk_buff, offsets 0..72
        // len, pkt_type, mark, queue_mapping, protocol, vlan_present,
        // vlan_tci, vlan_proto, priority, ingress_ifindex, ifindex,
        // tc_index, cb[5], hash
        scalar4_field(READONLY)
        + scalar4_field(READONLY)
        + mark
        + queue_mapping
        + scalar4_field(READONLY)
        + scalar4_field(READONLY)
        + scalar4_field(READONLY)
        + scalar4_field(READONLY)
        + priority
        + scalar4_field(READONLY)
        + scalar4_field(READONLY)
        + tc_index
        + cb
        + scalar4_field(READONLY)
    }

    ghost function sk_buff_network_fields() : seq<MemSlot>
    {
        // family, remote_ip4, local_ip4, remote_ip6[4], local_ip6[4],
        // remote_port, local_port
        scalar4_fields(READONLY, 13)
    }

    ghost function sk_filter_ctx_data() : seq<MemSlot>
    {
        sk_buff_prefix(
            scalar4_field(READONLY),
            scalar4_field(READONLY),
            scalar4_field(READONLY),
            scalar4_field(READONLY),
            scalar_n_field(RDWR, 20)
        )
        // 72: tc_classid, data, data_end are forbidden for socket filter
        + noaccess(12)
        // 84: napi_id
        + scalar4_field(READONLY)
        // 88: skipped or forbidden fields
        + noaccess(76)
        // 164: gso_segs
        + scalar4_field(READONLY)
        // 168: sk
        + ptr_or_null8_field(READONLY, PTR_TO_SOCK_COMMON)
        // 176: gso_size
        + scalar4_field(READONLY)
    }

    ghost function tc_cls_act_ctx_data() : seq<MemSlot>
    {
        sk_buff_prefix(
            scalar4_field(RDWR),
            scalar4_field(RDWR),
            scalar4_field(RDWR),
            scalar4_field(RDWR),
            scalar_n_field(RDWR, 20)
        )
        // 72: tc_classid
        + scalar4_field(RDWR)
        // 76: data
        + special_ptr_scalar4_field(READONLY)
        // 80: data_end
        + special_ptr_scalar4_field(READONLY)
        // 84: napi_id
        + scalar4_field(READONLY)
        // 88..140: family/address/port fields are forbidden here
        + noaccess(52)
        // 140: data_meta
        + special_ptr_scalar4_field(READONLY)
        // 144: flow_keys forbidden
        + noaccess(8)
        // 152: tstamp
        + scalar8_field(RDWR)
        // 160: wire_len
        + scalar4_field(READONLY)
        // 164: gso_segs
        + scalar4_field(READONLY)
        // 168: sk
        + ptr_or_null8_field(READONLY, PTR_TO_SOCK_COMMON)
        // 176: gso_size
        + scalar4_field(READONLY)
        // 180: tstamp_type
        + scalar_n_field(READONLY, 1)
        // 181..184: padding
        + noaccess(3)
        // 184: hwtstamp
        + scalar8_field(READONLY)
    }

    ghost function xdp_ctx_data(attachType: AttachTypes) : seq<MemSlot>
    {
        // data, data_end, data_meta
        special_ptr_scalar4_field(READONLY)
        + special_ptr_scalar4_field(READONLY)
        + special_ptr_scalar4_field(READONLY)
        // ingress_ifindex
        + scalar4_field(READONLY)
        // rx_queue_index is still TODO in ctxmem-precond.dfy
        + noaccess(4)
        // egress_ifindex
        + maybe(attachType == BPF_XDP_DEVMAP, scalar4_field(READONLY))
    }

    ghost function cg_skb_ctx_data(priv: bool) : seq<MemSlot>
    {
        sk_buff_prefix(
            scalar4_field(RDWR),
            scalar4_field(READONLY),
            scalar4_field(RDWR),
            scalar4_field(READONLY),
            scalar_n_field(RDWR, 20)
        )
        // 72: tc_classid is forbidden
        + noaccess(4)
        // 76: data
        + maybe(priv, special_ptr_scalar4_field(READONLY))
        // 80: data_end
        + maybe(priv, special_ptr_scalar4_field(READONLY))
        // 84: napi_id
        + scalar4_field(READONLY)
        // 88: family/address/port fields
        + sk_buff_network_fields()
        // 140: data_meta and 144: flow_keys are forbidden
        + noaccess(12)
        // 152: tstamp
        + scalar8_field(if priv then RDWR else READONLY)
        // 160: wire_len is forbidden
        + noaccess(4)
        // 164: gso_segs
        + scalar4_field(READONLY)
        // 168: sk
        + ptr_or_null8_field(READONLY, PTR_TO_SOCK_COMMON)
        // 176: gso_size
        + scalar4_field(READONLY)
        // 180: tstamp_type and padding are forbidden
        + noaccess(4)
        // 184: hwtstamp
        + scalar8_field(READONLY)
    }

    ghost function sock_filter_ctx_data(attachType: AttachTypes) : seq<MemSlot>
    {
        var create_or_release := attachType == BPF_CGROUP_INET_SOCK_CREATE || attachType == BPF_CGROUP_INET_SOCK_RELEASE;
        var post_bind4 := attachType == BPF_CGROUP_INET4_POST_BIND;
        var post_bind6 := attachType == BPF_CGROUP_INET6_POST_BIND;

        // bound_dev_if
        maybe(create_or_release, scalar4_field(RDWR))
        // family, type, protocol
        + scalar4_fields(READONLY, 3)
        // mark, priority
        + maybe(create_or_release, scalar4_field(RDWR))
        + maybe(create_or_release, scalar4_field(RDWR))
        // src_ip4
        + maybe(post_bind4, scalar4_field(READONLY))
        // src_ip6[4]
        + maybe(post_bind6, scalar4_fields(READONLY, 4))
        // src_port
        + maybe(post_bind4 || post_bind6, scalar4_field(READONLY))
        // dst_port, dst_ip4, dst_ip6[4], state, rx_queue_mapping
        + scalar4_field(READONLY)
        + scalar4_field(READONLY)
        + scalar4_fields(READONLY, 4)
        + scalar4_field(READONLY)
        + scalar4_field(READONLY)
    }

    ghost function sock_addr_ctx_data(attachType: AttachTypes) : seq<MemSlot>
    {
        var inet4 :=
            attachType == BPF_CGROUP_INET4_BIND ||
            attachType == BPF_CGROUP_INET4_CONNECT ||
            attachType == BPF_CGROUP_INET4_GETPEERNAME ||
            attachType == BPF_CGROUP_INET4_GETSOCKNAME ||
            attachType == BPF_CGROUP_UDP4_SENDMSG ||
            attachType == BPF_CGROUP_UDP4_RECVMSG;
        var inet6 :=
            attachType == BPF_CGROUP_INET6_BIND ||
            attachType == BPF_CGROUP_INET6_CONNECT ||
            attachType == BPF_CGROUP_INET6_GETPEERNAME ||
            attachType == BPF_CGROUP_INET6_GETSOCKNAME ||
            attachType == BPF_CGROUP_UDP6_SENDMSG ||
            attachType == BPF_CGROUP_UDP6_RECVMSG;

        // user_family
        scalar4_field(READONLY)
        // user_ip4
        + maybe(inet4, scalar4_field(RDWR))
        // user_ip6[4]
        + maybe(inet6, scalar4_fields(RDWR, 4))
        // user_port
        + scalar4_field(RDWR)
        // family, type, protocol
        + scalar4_fields(READONLY, 3)
        // msg_src_ip4
        + maybe(attachType == BPF_CGROUP_UDP4_SENDMSG, scalar4_field(RDWR))
        // msg_src_ip6[4]
        + maybe(attachType == BPF_CGROUP_UDP6_SENDMSG, scalar4_fields(RDWR, 4))
        // sk
        + ptr8_field(READONLY, PTR_TO_SOCKET)
    }

    ghost function lwt_ctx_data() : seq<MemSlot>
    {
        sk_buff_prefix(
            scalar4_field(RDWR),
            scalar4_field(READONLY),
            scalar4_field(RDWR),
            scalar4_field(READONLY),
            scalar_n_field(RDWR, 20)
        )
        // 72: tc_classid forbidden
        + noaccess(4)
        // 76: data
        + special_ptr_scalar4_field(READONLY)
        // 80: data_end
        + special_ptr_scalar4_field(READONLY)
        // 84: napi_id
        + scalar4_field(READONLY)
        // 88..164: forbidden fields
        + noaccess(76)
        // 164: gso_segs
        + scalar4_field(READONLY)
        // 168: sk
        + ptr_or_null8_field(READONLY, PTR_TO_SOCK_COMMON)
        // 176: gso_size
        + scalar4_field(READONLY)
    }

    ghost function sock_ops_ctx_data() : seq<MemSlot>
    {
        // op
        scalar4_field(READONLY)
        // union
        + scalar4_field(RDWR)
        + scalar4_fields(READONLY, 39)
        // sk_txhash
        + scalar4_field(RDWR)
        // bytes_received, bytes_acked
        + scalar8_field(READONLY)
        + scalar8_field(READONLY)
        // sk
        + ptr_or_null8_field(READONLY, PTR_TO_SOCKET)
        // skb_data, skb_data_end
        + ptr8_field(READONLY, PTR_TO_PACKET_DATA)
        + ptr8_field(READONLY, PTR_TO_PACKET_END)
        // skb_len, skb_tcp_flags
        + scalar4_field(READONLY)
        + scalar4_field(READONLY)
        // skb_hwtstamp
        + scalar8_field(READONLY)
    }

    ghost function sk_skb_ctx_data() : seq<MemSlot>
    {
        sk_buff_prefix(
            noaccess(4),
            scalar4_field(READONLY),
            scalar4_field(RDWR),
            scalar4_field(RDWR),
            scalar_n_field(READONLY, 20)
        )
        // 72: tc_classid forbidden
        + noaccess(4)
        // 76: data
        + special_ptr_scalar4_field(READONLY)
        // 80: data_end
        + special_ptr_scalar4_field(READONLY)
        // 84: napi_id
        + scalar4_field(READONLY)
        // 88: family/address/port fields
        + sk_buff_network_fields()
        // 140..164: forbidden fields
        + noaccess(24)
        // 164: gso_segs
        + scalar4_field(READONLY)
        // 168: sk
        + ptr_or_null8_field(READONLY, PTR_TO_SOCK_COMMON)
        // 176: gso_size
        + scalar4_field(READONLY)
    }

    ghost function sk_msg_ctx_data() : seq<MemSlot>
    {
        // data, data_end
        ptr8_field(READONLY, PTR_TO_PACKET_DATA)
        + ptr8_field(READONLY, PTR_TO_PACKET_END)
        // family, remote_ip4, local_ip4, remote_ip6[4], local_ip6[4],
        // remote_port, local_port, size
        + scalar4_fields(READONLY, 14)
        // sk
        + ptr8_field(READONLY, PTR_TO_SOCKET)
    }

    ghost function flow_dissector_ctx_data() : seq<MemSlot>
    {
        noaccess(76)
        // data, data_end
        + special_ptr_scalar4_field(READONLY)
        + special_ptr_scalar4_field(READONLY)
        // forbidden gap to flow_keys
        + noaccess(60)
        // flow_keys
        + ptr8_field(READONLY, PTR_TO_FLOW_KEYS)
    }

    ghost function cgroup_dev_ctx_data() : seq<MemSlot>
    {
        scalar4_fields(READONLY, 3)
    }

    ghost function sysctl_ctx_data() : seq<MemSlot>
    {
        scalar4_field(READONLY)
        + scalar4_field(RDWR)
    }

    ghost function cg_sockopt_ctx_data(attachType: AttachTypes) : seq<MemSlot>
    {
        var is_setsockopt := attachType == BPF_CGROUP_SETSOCKOPT;

        ptr8_field(READONLY, PTR_TO_SOCKET)
        + ptr8_field(READONLY, PTR_TO_PACKET_DATA)
        + ptr8_field(READONLY, PTR_TO_PACKET_END)
        // level, optname
        + scalar4_field(if is_setsockopt then RDWR else READONLY)
        + scalar4_field(if is_setsockopt then RDWR else READONLY)
        // optlen
        + scalar4_field(RDWR)
        // retval
        + maybe(is_setsockopt, scalar4_field(RDWR))
    }

    ghost function lirc_mode2_ctx_data() : seq<MemSlot>
    {
        noaccess(4)
        + scalar4_field(READONLY)
    }

    ghost function sk_reuseport_ctx_data() : seq<MemSlot>
    {
        ptr8_field(READONLY, PTR_TO_PACKET_DATA)
        + ptr8_field(READONLY, PTR_TO_PACKET_END)
        // len, eth_protocol, ip_protocol, bind_inany, hash
        + scalar4_fields(READONLY, 5)
        // padding
        + noaccess(4)
        // sk, migrating_sk
        + ptr8_field(READONLY, PTR_TO_SOCKET)
        + ptr_or_null8_field(READONLY, PTR_TO_SOCK_COMMON)
    }

    ghost function sk_lookup_ctx_data() : seq<MemSlot>
    {
        // sk
        ptr_or_null8_field(READONLY, PTR_TO_SOCKET)
        // family, protocol, remote_ip4, remote_ip6[4]
        + scalar4_fields(READONLY, 7)
        // remote_port
        + scalar_n_field(READONLY, 2)
        // padding
        + noaccess(2)
        // local_ip4, local_ip6[4], local_port, ingress_ifindex
        + scalar4_fields(READONLY, 7)
    }

    ghost function nf_ctx_data() : seq<MemSlot>
    {
        scalar8_field(READONLY)
        + scalar8_field(READONLY)
    }

    ghost function initialize_ctx_mem(
        progType: ProgTypes, attachType: AttachTypes, priv: bool
    ) : seq<MemSlot>
    {
        match progType {
            case BPF_PROG_TYPE_SOCKET_FILTER           => sk_filter_ctx_data()
            case BPF_PROG_TYPE_SCHED_CLS               => tc_cls_act_ctx_data()
            case BPF_PROG_TYPE_SCHED_ACT               => tc_cls_act_ctx_data()
            case BPF_PROG_TYPE_XDP                     => xdp_ctx_data(attachType)
            case BPF_PROG_TYPE_CGROUP_SKB              => cg_skb_ctx_data(priv)
            case BPF_PROG_TYPE_CGROUP_SOCK             => sock_filter_ctx_data(attachType)
            case BPF_PROG_TYPE_CGROUP_SOCK_ADDR        => sock_addr_ctx_data(attachType)
            case BPF_PROG_TYPE_LWT_IN                  => lwt_ctx_data()
            case BPF_PROG_TYPE_LWT_OUT                 => lwt_ctx_data()
            case BPF_PROG_TYPE_LWT_XMIT                => lwt_ctx_data()
            case BPF_PROG_TYPE_LWT_SEG6LOCAL           => lwt_ctx_data()
            case BPF_PROG_TYPE_SOCK_OPS                => sock_ops_ctx_data()
            case BPF_PROG_TYPE_SK_SKB                  => sk_skb_ctx_data()
            case BPF_PROG_TYPE_SK_MSG                  => sk_msg_ctx_data()
            case BPF_PROG_TYPE_FLOW_DISSECTOR          => flow_dissector_ctx_data()
            case BPF_PROG_TYPE_KPROBE                  => scalar_n_field(READONLY, 168)
            case BPF_PROG_TYPE_TRACEPOINT              => noaccess(8) + scalar_n_field(READONLY, 8184)
            case BPF_PROG_TYPE_PERF_EVENT              => scalar_n_field(READONLY, 184)
            case BPF_PROG_TYPE_RAW_TRACEPOINT          => scalar_n_field(READONLY, 96)
            case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE => ptr8_field(READONLY, PTR_TO_TP_BUFFER) + scalar_n_field(READONLY, 88)
            case BPF_PROG_TYPE_TRACING                 => []
            case BPF_PROG_TYPE_CGROUP_DEVICE           => cgroup_dev_ctx_data()
            case BPF_PROG_TYPE_CGROUP_SYSCTL           => sysctl_ctx_data()
            case BPF_PROG_TYPE_CGROUP_SOCKOPT          => cg_sockopt_ctx_data(attachType)
            case BPF_PROG_TYPE_LIRC_MODE2              => lirc_mode2_ctx_data()
            case BPF_PROG_TYPE_SK_REUSEPORT            => sk_reuseport_ctx_data()
            case BPF_PROG_TYPE_SK_LOOKUP               => sk_lookup_ctx_data()
            case BPF_PROG_TYPE_STRUCT_OPS              => []
            case BPF_PROG_TYPE_EXT                     => []
            case BPF_PROG_TYPE_LSM                     => []
            case BPF_PROG_TYPE_SYSCALL                 => scalar_n_field(RDWR, 65535)
            case BPF_PROG_TYPE_NETFILTER               => nf_ctx_data()
        }
    }
}
