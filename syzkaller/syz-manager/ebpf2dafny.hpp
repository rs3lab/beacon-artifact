#include <sys/types.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <regex>
#include <set>

#define BPF_BASE_TYPE_MASK 0xff
#define PTR_MAYBE_NULL 0x100

struct verify_range {
    int start;
    int end;
};

std::string op2dafnyop[] = {
	"Add",
	"Sub",
	"Mul",
	"Div",
	"Bvor",
	"Bvand",
	"Bvshl",
	"Bvlshr",
	"Neg",
	"Mod",
	"Bvxor",
	"Mov",
	"Bvashr",
	"End",
};

std::map<int, std::string> sizeMarco2num = {
	{0x10, "1"},
	{0x08, "2"},
	{0x00, "4"},
	{0x18, "8"}
};

std::ofstream statistic_file, prog_staticstic_file, log_file;
std::mutex file_mutex;
std::atomic<uint64_t> globalCounter(0);

std::unordered_map<std::string, std::string> memTypes2Opname = {
	{"STACKMEM", "STACKMEM"},
	{"CTXMEM", "CTXMEM"},
	//
	{"MAP_PTR", "MAPMEM"},
	{"PTR_TO_MAP_VALUE", "MAPVALUE"},
	{"PTR_TO_MAP_KEY", "MAPKEY"},
	//
	{"PTR_TO_PACKET_META", "PACKET"},
	{"PTR_TO_PACKET", "PACKET"},
	{"PTR_TO_PACKET_END", "PACKET"},
	//
	{"PTR_TO_FLOW_KEYS", "FLOWKEYS"},
	//
	{"PTR_TO_SOCKET", "SOCK"},
	{"PTR_TO_SOCK_COMMON", "SOCK"},
	{"PTR_TO_TCP_SOCK", "SOCK"},
	{"PTR_TO_XDP_SOCK", "SOCK"},
	//
	{"PTR_TO_TP_BUFFER", "TPBUFFER"},
	{"PTR_TO_ARENA", "ARENA"},
};

int floor_division(int x, int y) {
	if (x % y == 0) return (x / y); else return (x/y + 1);
}

std::string bpf_prog_type_str[] = {
    "BPF_PROG_TYPE_UNSPEC",
    "BPF_PROG_TYPE_SOCKET_FILTER",
    "BPF_PROG_TYPE_KPROBE",
    "BPF_PROG_TYPE_SCHED_CLS",
    "BPF_PROG_TYPE_SCHED_ACT",
    "BPF_PROG_TYPE_TRACEPOINT",
    "BPF_PROG_TYPE_XDP",
    "BPF_PROG_TYPE_PERF_EVENT",
    "BPF_PROG_TYPE_CGROUP_SKB",
    "BPF_PROG_TYPE_CGROUP_SOCK",
    "BPF_PROG_TYPE_LWT_IN",
    "BPF_PROG_TYPE_LWT_OUT",
    "BPF_PROG_TYPE_LWT_XMIT",
    "BPF_PROG_TYPE_SOCK_OPS",
    "BPF_PROG_TYPE_SK_SKB",
    "BPF_PROG_TYPE_CGROUP_DEVICE",
    "BPF_PROG_TYPE_SK_MSG",
    "BPF_PROG_TYPE_RAW_TRACEPOINT",
    "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
    "BPF_PROG_TYPE_LWT_SEG6LOCAL",
    "BPF_PROG_TYPE_LIRC_MODE2",
    "BPF_PROG_TYPE_SK_REUSEPORT",
    "BPF_PROG_TYPE_FLOW_DISSECTOR",
    "BPF_PROG_TYPE_CGROUP_SYSCTL",
    "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
    "BPF_PROG_TYPE_CGROUP_SOCKOPT",
    "BPF_PROG_TYPE_TRACING",
    "BPF_PROG_TYPE_STRUCT_OPS",
    "BPF_PROG_TYPE_EXT",
    "BPF_PROG_TYPE_LSM",
    "BPF_PROG_TYPE_SK_LOOKUP",
    "BPF_PROG_TYPE_SYSCALL",
    "BPF_PROG_TYPE_NETFILTER",
};


std::string expected_attach_type_str[] = {
    "BPF_CGROUP_INET_INGRESS",
    "BPF_CGROUP_INET_EGRESS",
    "BPF_CGROUP_INET_SOCK_CREATE",
    "BPF_CGROUP_SOCK_OPS",
    "BPF_SK_SKB_STREAM_PARSER",
    "BPF_SK_SKB_STREAM_VERDICT",
    "BPF_CGROUP_DEVICE",
    "BPF_SK_MSG_VERDICT",
    "BPF_CGROUP_INET4_BIND",
    "BPF_CGROUP_INET6_BIND",
    "BPF_CGROUP_INET4_CONNECT",
    "BPF_CGROUP_INET6_CONNECT",
    "BPF_CGROUP_INET4_POST_BIND",
    "BPF_CGROUP_INET6_POST_BIND",
    "BPF_CGROUP_UDP4_SENDMSG",
    "BPF_CGROUP_UDP6_SENDMSG",
    "BPF_LIRC_MODE2",
    "BPF_FLOW_DISSECTOR",
    "BPF_CGROUP_SYSCTL",
    "BPF_CGROUP_UDP4_RECVMSG",
    "BPF_CGROUP_UDP6_RECVMSG",
    "BPF_CGROUP_GETSOCKOPT",
    "BPF_CGROUP_SETSOCKOPT",
    "BPF_TRACE_RAW_TP",
    "BPF_TRACE_FENTRY",
    "BPF_TRACE_FEXIT",
    "BPF_MODIFY_RETURN",
    "BPF_LSM_MAC",
    "BPF_TRACE_ITER",
    "BPF_CGROUP_INET4_GETPEERNAME",
    "BPF_CGROUP_INET6_GETPEERNAME",
    "BPF_CGROUP_INET4_GETSOCKNAME",
    "BPF_CGROUP_INET6_GETSOCKNAME",
    "BPF_XDP_DEVMAP",
    "BPF_CGROUP_INET_SOCK_RELEASE",
    "BPF_XDP_CPUMAP",
    "BPF_SK_LOOKUP",
    "BPF_XDP",
    "BPF_SK_SKB_VERDICT",
    "BPF_SK_REUSEPORT_SELECT",
    "BPF_SK_REUSEPORT_SELECT_OR_MIGRATE",
    "BPF_PERF_EVENT",
    "BPF_TRACE_KPROBE_MULTI",
    "BPF_LSM_CGROUP",
    "BPF_STRUCT_OPS",
    "BPF_NETFILTER",
    "BPF_TCX_INGRESS",
    "BPF_TCX_EGRESS",
    "BPF_TRACE_UPROBE_MULTI",
    "BPF_CGROUP_UNIX_CONNECT",
    "BPF_CGROUP_UNIX_SENDMSG",
    "BPF_CGROUP_UNIX_RECVMSG",
    "BPF_CGROUP_UNIX_GETPEERNAME",
    "BPF_CGROUP_UNIX_GETSOCKNAME",
    "BPF_NETKIT_PRIMARY",
    "BPF_NETKIT_PEER",
    "BPF_TRACE_KPROBE_SESSION"
};

std::string bpf_map_type_str[] = {
    "BPF_MAP_TYPE_UNSPEC",
    "BPF_MAP_TYPE_HASH",
    "BPF_MAP_TYPE_ARRAY",
    "BPF_MAP_TYPE_PROG_ARRAY",
    "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
    "BPF_MAP_TYPE_PERCPU_HASH",
    "BPF_MAP_TYPE_PERCPU_ARRAY",
    "BPF_MAP_TYPE_STACK_TRACE",
    "BPF_MAP_TYPE_CGROUP_ARRAY",
    "BPF_MAP_TYPE_LRU_HASH",
    "BPF_MAP_TYPE_LRU_PERCPU_HASH",
    "BPF_MAP_TYPE_LPM_TRIE",
    "BPF_MAP_TYPE_ARRAY_OF_MAPS",
    "BPF_MAP_TYPE_HASH_OF_MAPS",
    "BPF_MAP_TYPE_DEVMAP",
    "BPF_MAP_TYPE_SOCKMAP",
    "BPF_MAP_TYPE_CPUMAP",
    "BPF_MAP_TYPE_XSKMAP",
    "BPF_MAP_TYPE_SOCKHASH",
    "BPF_MAP_TYPE_CGROUP_STORAGE",
    "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY",
    "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE",
    "BPF_MAP_TYPE_QUEUE",
    "BPF_MAP_TYPE_STACK",
    "BPF_MAP_TYPE_SK_STORAGE",
    "BPF_MAP_TYPE_DEVMAP_HASH",
    "BPF_MAP_TYPE_STRUCT_OPS",
    "BPF_MAP_TYPE_RINGBUF",
    "BPF_MAP_TYPE_INODE_STORAGE",
    "BPF_MAP_TYPE_TASK_STORAGE",
    "BPF_MAP_TYPE_BLOOM_FILTER",
    "BPF_MAP_TYPE_USER_RINGBUF",
    "BPF_MAP_TYPE_CGRP_STORAGE",
    "BPF_MAP_TYPE_ARENA"
};


std::string helper_names[] = {
    "unspec",
    "map_lookup_elem",
    "map_update_elem",
    "map_delete_elem",
    "probe_read",
    "ktime_get_ns",
    "trace_printk",
    "get_prandom_u32",
    "get_smp_processor_id",
    "skb_store_bytes",
    "l3_csum_replace",
    "l4_csum_replace",
    "tail_call",
    "clone_redirect",
    "get_current_pid_tgid",
    "get_current_uid_gid",
    "get_current_comm",
    "get_cgroup_classid",
    "skb_vlan_push",
    "skb_vlan_pop",
    "skb_get_tunnel_key",
    "skb_set_tunnel_key",
    "perf_event_read",
    "redirect",
    "get_route_realm",
    "perf_event_output",
    "skb_load_bytes",
    "get_stackid",
    "csum_diff",
    "skb_get_tunnel_opt",
    "skb_set_tunnel_opt",
    "skb_change_proto",
    "skb_change_type",
    "skb_under_cgroup",
    "get_hash_recalc",
    "get_current_task",
    "probe_write_user",
    "current_task_under_cgroup",
    "skb_change_tail",
    "skb_pull_data",
    "csum_update",
    "set_hash_invalid",
    "get_numa_node_id",
    "skb_change_head",
    "xdp_adjust_head",
    "probe_read_str",
    "get_socket_cookie",
    "get_socket_uid",
    "set_hash",
    "setsockopt",
    "skb_adjust_room",
    "redirect_map",
    "sk_redirect_map",
    "sock_map_update",
    "xdp_adjust_meta",
    "perf_event_read_value",
    "perf_prog_read_value",
    "getsockopt",
    "override_return",
    "sock_ops_cb_flags_set",
    "msg_redirect_map",
    "msg_apply_bytes",
    "msg_cork_bytes",
    "msg_pull_data",
    "bind",
    "xdp_adjust_tail",
    "skb_get_xfrm_state",
    "get_stack",
    "skb_load_bytes_relative",
    "fib_lookup",
    "sock_hash_update",
    "msg_redirect_hash",
    "sk_redirect_hash",
    "lwt_push_encap",
    "lwt_seg6_store_bytes",
    "lwt_seg6_adjust_srh",
    "lwt_seg6_action",
    "rc_repeat",
    "rc_keydown",
    "skb_cgroup_id",
    "get_current_cgroup_id",
    "get_local_storage",
    "sk_select_reuseport",
    "skb_ancestor_cgroup_id",
    "sk_lookup_tcp",
    "sk_lookup_udp",
    "sk_release",
    "map_push_elem",
    "map_pop_elem",
    "map_peek_elem",
    "msg_push_data",
    "msg_pop_data",
    "rc_pointer_rel",
    "spin_lock",
    "spin_unlock",
    "sk_fullsock",
    "tcp_sock",
    "skb_ecn_set_ce",
    "get_listener_sock",
    "skc_lookup_tcp",
    "tcp_check_syncookie",
    "sysctl_get_name",
    "sysctl_get_current_value",
    "sysctl_get_new_value",
    "sysctl_set_new_value",
    "strtol",
    "strtoul",
    "sk_storage_get",
    "sk_storage_delete",
    "send_signal",
    "tcp_gen_syncookie",
    "skb_output",
    "probe_read_user",
    "probe_read_kernel",
    "probe_read_user_str",
    "probe_read_kernel_str",
    "tcp_send_ack",
    "send_signal_thread",
    "jiffies64",
    "read_branch_records",
    "get_ns_current_pid_tgid",
    "xdp_output",
    "get_netns_cookie",
    "get_current_ancestor_cgroup_id",
    "sk_assign",
    "ktime_get_boot_ns",
    "seq_printf",
    "seq_write",
    "sk_cgroup_id",
    "sk_ancestor_cgroup_id",
    "ringbuf_output",
    "ringbuf_reserve",
    "ringbuf_submit",
    "ringbuf_discard",
    "ringbuf_query",
    "csum_level",
    "skc_to_tcp6_sock",
    "skc_to_tcp_sock",
    "skc_to_tcp_timewait_sock",
    "skc_to_tcp_request_sock",
    "skc_to_udp6_sock",
    "get_task_stack",
    "load_hdr_opt",
    "store_hdr_opt",
    "reserve_hdr_opt",
    "inode_storage_get",
    "inode_storage_delete",
    "d_path",
    "copy_from_user",
    "snprintf_btf",
    "seq_printf_btf",
    "skb_cgroup_classid",
    "redirect_neigh",
    "per_cpu_ptr",
    "this_cpu_ptr",
    "redirect_peer",
    "task_storage_get",
    "task_storage_delete",
    "get_current_task_btf",
    "bprm_opts_set",
    "ktime_get_coarse_ns",
    "ima_inode_hash",
    "sock_from_file",
    "check_mtu",
    "for_each_map_elem",
    "snprintf",
    "sys_bpf",
    "btf_find_by_name_kind",
    "sys_close",
    "timer_init",
    "timer_set_callback",
    "timer_start",
    "timer_cancel",
    "get_func_ip",
    "get_attach_cookie",
    "task_pt_regs",
    "get_branch_snapshot",
    "trace_vprintk",
    "skc_to_unix_sock",
    "kallsyms_lookup_name",
    "find_vma",
    "loop",
    "strncmp",
    "get_func_arg",
    "get_func_ret",
    "get_func_arg_cnt",
    "get_retval",
    "set_retval",
    "xdp_get_buff_len",
    "xdp_load_bytes",
    "xdp_store_bytes",
    "copy_from_user_task",
    "skb_set_tstamp",
    "ima_file_hash",
    "kptr_xchg",
    "map_lookup_percpu_elem",
    "skc_to_mptcp_sock",
    "dynptr_from_mem",
    "ringbuf_reserve_dynptr",
    "ringbuf_submit_dynptr",
    "ringbuf_discard_dynptr",
    "dynptr_read",
    "dynptr_write",
    "dynptr_data",
    "tcp_raw_gen_syncookie_ipv4",
    "tcp_raw_gen_syncookie_ipv6",
    "tcp_raw_check_syncookie_ipv4",
    "tcp_raw_check_syncookie_ipv6",
    "ktime_get_tai_ns",
    "user_ringbuf_drain",
    "cgrp_storage_get",
    "cgrp_storage_delete"
};

enum PrivLevel {
    PRIV_UNPRIV = 0,
    PRIV_CAP_BPF,
    PRIV_CAP_PERFMON,
    PRIV_CAP_NET_ADMIN,
    PRIV_CAP_SYS_ADMIN
};

inline std::string annotate(int insn_idx) {
    std::ostringstream oss;
    oss << " // Instruction " << insn_idx;
    return oss.str();
}

int regex_match_error_insn(std::string dafny_output) {
    
    // Regular expression to match numbers following "Instruction"
    std::regex instruction_regex(R"(Instruction\s+(\d+))");
    std::smatch match;

    // Set to store unique instruction numbers
    std::set<int> linenos;

    // Iterate over all matches
    std::string::const_iterator search_start(dafny_output.cbegin());
    while (std::regex_search(search_start, dafny_output.cend(), match, instruction_regex)) {
        // Convert the matched number string to an integer
        int number = std::stoi(match[1]);
        
        // Insert the number into the set (automatically handles deduplication)
        linenos.insert(number);

        // Update the search position
        search_start = match.suffix().first;
    }

    /*
    for (int line : linenos) {
        std::cerr << line << " ";
    }
    std::cerr << std::endl;
    */

    if (!linenos.empty()) {
        return *linenos.begin(); // Dereference the iterator to get the first value
    } else {
        return -1;
    }
}
