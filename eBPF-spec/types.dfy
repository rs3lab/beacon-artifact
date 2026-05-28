type int64 = x: int | -0x8000_0000_0000_0000 <= x < 0x8000_0000_0000_0000
type uint64 = x: int | 0 <= x <= 0xFFFF_FFFF_FFFF_FFFF 

datatype Option<T> = None | Some(value: T)
datatype CTXPermission = ReadOnly | ReadWrite | NoAccess

datatype SIZE =
    | B
    | H
    | W
    | DW

datatype SIGNNESS =
    | SIGN
    | UNSI

datatype REGTYPE = 
    | UNINT
    | NULL
    | SCALAR
    //
    | CTXMEM
    | STACKMEM
    //
    | MAP_PTR
    | PTR_TO_MAP_VALUE
    | PTR_TO_MAP_KEY
    //
    | PTR_TO_PACKET_META
    | PTR_TO_PACKET
    | PTR_TO_PACKET_END
    //
    | PTR_TO_FLOW_KEYS
    //
    | PTR_TO_SOCKET
    | PTR_TO_SOCK_COMMON // TODO: what is the difference between PTR_TO_SOCKET and PTR_TO_SOCK_COMMON
    | PTR_TO_TCP_SOCK
    | PTR_TO_XDP_SOCK
    //
    | PTR_TO_TP_BUFFER
    //
    | PTR_TO_ARENA
    //
    | PTR_TO_FUNC
    //
    | STACK_ITER
    | STACK_DYNPTR

    /*
    NOT_INIT = 0,        /* nothing was written into register */
    SCALAR_VALUE,        /* reg doesn't contain a valid pointer */
    PTR_TO_CTX,      /* reg points to bpf_context */
    CONST_PTR_TO_MAP,    /* reg points to struct bpf_map */
    PTR_TO_MAP_VALUE,    /* reg points to map element value */
    PTR_TO_STACK,        /* reg == frame_pointer + offset */

    PTR_TO_PACKET_META,  /* skb->data - meta_len */
    PTR_TO_PACKET_END,   /* skb->data + headlen */
    PTR_TO_PACKET,       /* reg points to skb->data */

    PTR_TO_FLOW_KEYS,    /* reg points to bpf_flow_keys */

    PTR_TO_SOCKET,       /* reg points to struct bpf_sock */
    PTR_TO_SOCK_COMMON,  /* reg points to sock_common */
    PTR_TO_TCP_SOCK,     /* reg points to struct tcp_sock */
    PTR_TO_XDP_SOCK,     /* reg points to struct xdp_sock */

        CONST_PTR_TO_DYNPTR,     /* reg points to a const struct bpf_dynptr */

    // LOCK

    PTR_TO_MAP_KEY,      /* reg points to a map element key */

    PTR_TO_TP_BUFFER,    /* reg points to a writable raw tp's buffer */
        PTR_TO_BTF_ID,


        PTR_TO_MEM,      /* reg points to valid memory region */
    PTR_TO_ARENA,
        PTR_TO_BUF,      /* reg points to a read/write buffer */
    PTR_TO_FUNC,         /* reg points to a bpf program function */
    */

datatype REG = 
    | R0
    | R1
    | R2
    | R3
    | R4
    | R5
    | R6
    | R7
    | R8
    | R9
    | R10
    | Rn

datatype ATOMICOP =
    | ATOMIC_ADD
    | ATOMIC_AND
    | ATOMIC_OR
    | ATOMIC_XOR
    | ATOMIC_FETCH_ADD
    | ATOMIC_FETCH_AND
    | ATOMIC_FETCH_OR
    | ATOMIC_FETCH_XOR
    | ATOMIC_XCHG
    | ATOMIC_CMPXCHG

// Less or greater jump
datatype LGJMP =
    | JGT
    | JGE
    | JSGT
    | JSGE
    | JLT
    | JLE
    | JSLT
    | JSLE

datatype ACCESSTYPE =
    | READ
    | WRITE

datatype ProgTypes =
    | BPF_PROG_TYPE_SOCKET_FILTER
    | BPF_PROG_TYPE_SCHED_CLS
    | BPF_PROG_TYPE_SCHED_ACT
    | BPF_PROG_TYPE_XDP
    | BPF_PROG_TYPE_CGROUP_SKB
    | BPF_PROG_TYPE_CGROUP_SOCK
    | BPF_PROG_TYPE_CGROUP_SOCK_ADDR
    | BPF_PROG_TYPE_LWT_IN
    | BPF_PROG_TYPE_LWT_OUT
    | BPF_PROG_TYPE_LWT_XMIT
    | BPF_PROG_TYPE_LWT_SEG6LOCAL
    | BPF_PROG_TYPE_SOCK_OPS
    | BPF_PROG_TYPE_SK_SKB
    | BPF_PROG_TYPE_SK_MSG
    | BPF_PROG_TYPE_FLOW_DISSECTOR
    | BPF_PROG_TYPE_KPROBE
    | BPF_PROG_TYPE_TRACEPOINT
    | BPF_PROG_TYPE_PERF_EVENT
    | BPF_PROG_TYPE_RAW_TRACEPOINT
    | BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
    | BPF_PROG_TYPE_TRACING
    | BPF_PROG_TYPE_CGROUP_DEVICE
    | BPF_PROG_TYPE_CGROUP_SYSCTL
    | BPF_PROG_TYPE_CGROUP_SOCKOPT
    | BPF_PROG_TYPE_LIRC_MODE2
    | BPF_PROG_TYPE_SK_REUSEPORT
    | BPF_PROG_TYPE_SK_LOOKUP
    | BPF_PROG_TYPE_STRUCT_OPS
    | BPF_PROG_TYPE_EXT
    | BPF_PROG_TYPE_LSM
    | BPF_PROG_TYPE_SYSCALL
    | BPF_PROG_TYPE_NETFILTER

datatype AttachTypes =
    | BPF_CGROUP_INET_INGRESS
    | BPF_CGROUP_INET_EGRESS
    | BPF_CGROUP_INET_SOCK_CREATE
    | BPF_CGROUP_SOCK_OPS
    | BPF_SK_SKB_STREAM_PARSER
    | BPF_SK_SKB_STREAM_VERDICT
    | BPF_CGROUP_DEVICE
    | BPF_SK_MSG_VERDICT
    | BPF_CGROUP_INET4_BIND
    | BPF_CGROUP_INET6_BIND
    | BPF_CGROUP_INET4_CONNECT
    | BPF_CGROUP_INET6_CONNECT
    | BPF_CGROUP_INET4_POST_BIND
    | BPF_CGROUP_INET6_POST_BIND
    | BPF_CGROUP_UDP4_SENDMSG
    | BPF_CGROUP_UDP6_SENDMSG
    | BPF_LIRC_MODE2
    | BPF_FLOW_DISSECTOR
    | BPF_CGROUP_SYSCTL
    | BPF_CGROUP_UDP4_RECVMSG
    | BPF_CGROUP_UDP6_RECVMSG
    | BPF_CGROUP_GETSOCKOPT
    | BPF_CGROUP_SETSOCKOPT
    | BPF_TRACE_RAW_TP
    | BPF_TRACE_FENTRY
    | BPF_TRACE_FEXIT
    | BPF_MODIFY_RETURN
    | BPF_LSM_MAC
    | BPF_TRACE_ITER
    | BPF_CGROUP_INET4_GETPEERNAME
    | BPF_CGROUP_INET6_GETPEERNAME
    | BPF_CGROUP_INET4_GETSOCKNAME
    | BPF_CGROUP_INET6_GETSOCKNAME
    | BPF_XDP_DEVMAP
    | BPF_CGROUP_INET_SOCK_RELEASE
    | BPF_XDP_CPUMAP
    | BPF_SK_LOOKUP
    | BPF_XDP
    | BPF_SK_SKB_VERDICT
    | BPF_SK_REUSEPORT_SELECT
    | BPF_SK_REUSEPORT_SELECT_OR_MIGRATE
    | BPF_PERF_EVENT
    | BPF_TRACE_KPROBE_MULTI
    | BPF_LSM_CGROUP
    | BPF_STRUCT_OPS
    | BPF_NETFILTER
    | BPF_TCX_INGRESS
    | BPF_TCX_EGRESS
    | BPF_TRACE_UPROBE_MULTI
    | BPF_CGROUP_UNIX_CONNECT
    | BPF_CGROUP_UNIX_SENDMSG
    | BPF_CGROUP_UNIX_RECVMSG
    | BPF_CGROUP_UNIX_GETPEERNAME
    | BPF_CGROUP_UNIX_GETSOCKNAME
    | BPF_NETKIT_PRIMARY
    | BPF_NETKIT_PEER

datatype MapTypes =
    | BPF_MAP_TYPE_HASH
    | BPF_MAP_TYPE_ARRAY
    | BPF_MAP_TYPE_PROG_ARRAY
    | BPF_MAP_TYPE_PERF_EVENT_ARRAY
    | BPF_MAP_TYPE_PERCPU_HASH
    | BPF_MAP_TYPE_PERCPU_ARRAY
    | BPF_MAP_TYPE_STACK_TRACE
    | BPF_MAP_TYPE_CGROUP_ARRAY
    | BPF_MAP_TYPE_LRU_HASH
    | BPF_MAP_TYPE_LRU_PERCPU_HASH
    | BPF_MAP_TYPE_LPM_TRIE
    | BPF_MAP_TYPE_ARRAY_OF_MAPS
    | BPF_MAP_TYPE_HASH_OF_MAPS
    | BPF_MAP_TYPE_DEVMAP
    | BPF_MAP_TYPE_SOCKMAP
    | BPF_MAP_TYPE_CPUMAP
    | BPF_MAP_TYPE_XSKMAP
    | BPF_MAP_TYPE_SOCKHASH
    | BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED
    | BPF_MAP_TYPE_CGROUP_STORAGE
    | BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
    | BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED
    | BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
    | BPF_MAP_TYPE_QUEUE
    | BPF_MAP_TYPE_STACK
    | BPF_MAP_TYPE_SK_STORAGE
    | BPF_MAP_TYPE_DEVMAP_HASH
    | BPF_MAP_TYPE_STRUCT_OPS
    | BPF_MAP_TYPE_RINGBUF
    | BPF_MAP_TYPE_INODE_STORAGE
    | BPF_MAP_TYPE_TASK_STORAGE
    | BPF_MAP_TYPE_BLOOM_FILTER
    | BPF_MAP_TYPE_USER_RINGBUF
    | BPF_MAP_TYPE_CGRP_STORAGE
    | BPF_MAP_TYPE_ARENA

class RegState {
    ghost var regNo: REG
    ghost var regType: REGTYPE
    ghost var regVal: bv64
    ghost var mapFd: int64
    ghost var memId: int64

    ghost constructor {:axiom} (regNo: REG)
        ensures this.regNo == regNo
        ensures this.regVal == 0
        ensures this.regType == UNINT
        // Cannot combine mapFd and memId together as for PTR_TO_MAP_VALUE,
        // we need to know the memId for multiple lookups and its mapFd to know which map
        ensures this.mapFd == -1
        /*
            Stack: frameNo
            CONST_PTR_TO_MAP: different maps
            PTR_TO_MAP_VALUE: different returned memory
            ...
        */
        ensures this.memId == -1
}

class MapState {
    ghost var mapType: MapTypes
    ghost var keySize: int64
    ghost var valSize: int64
    ghost var maxEntries: int64
    ghost var mapFlag: int64        // TODO: remove?
    ghost var readable: bool
    ghost var writable: bool
    ghost var innerMapFd: int64
}

class SpinLockState{
    ghost var isLocked: bool
    ghost var memId:    int64
    ghost var ptrType:  REGTYPE
}

class MutableVars{
    ghost var idCounter: int64
}