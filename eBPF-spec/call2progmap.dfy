include "types.dfy"

/*
    Each helper needs to check the current program type and map type if it's calling maps
 */

//////////////////////// <func, map> pairs ////////////////////////////////////////

predicate bpf_map_lookup_elem_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_ARRAY_OF_MAPS || mapType == BPF_MAP_TYPE_HASH_OF_MAPS || mapType == BPF_MAP_TYPE_DEVMAP || mapType == BPF_MAP_TYPE_SOCKMAP || mapType == BPF_MAP_TYPE_XSKMAP || mapType == BPF_MAP_TYPE_SOCKHASH || mapType == BPF_MAP_TYPE_STACK || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_map_update_elem_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_map_delete_elem_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SOCKMAP || mapType == BPF_MAP_TYPE_SOCKHASH || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_probe_read_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_ktime_get_ns_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_trace_printk_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_prandom_u32_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_smp_processor_id_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_store_bytes_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_l3_csum_replace_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_l4_csum_replace_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_tail_call_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_PROG_ARRAY
}

predicate bpf_clone_redirect_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_current_pid_tgid_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_current_uid_gid_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_current_comm_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_cgroup_classid_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_vlan_push_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_vlan_pop_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_get_tunnel_key_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_set_tunnel_key_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_perf_event_read_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_PERF_EVENT_ARRAY
}

predicate bpf_redirect_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_route_realm_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_perf_event_output_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_PERF_EVENT_ARRAY
}

predicate bpf_skb_load_bytes_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_stackid_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_STACK_TRACE
}

predicate bpf_csum_diff_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_get_tunnel_opt_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_set_tunnel_opt_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_change_proto_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_change_type_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_under_cgroup_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_CGROUP_ARRAY
}

predicate bpf_get_hash_recalc_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_current_task_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_probe_write_user_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_current_task_under_cgroup_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_CGROUP_ARRAY
}

predicate bpf_skb_change_tail_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_pull_data_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_csum_update_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_set_hash_invalid_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_numa_node_id_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_change_head_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_xdp_adjust_head_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_probe_read_str_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_socket_cookie_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_socket_uid_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_set_hash_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_setsockopt_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_adjust_room_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_redirect_map_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_DEVMAP || mapType == BPF_MAP_TYPE_CPUMAP || mapType == BPF_MAP_TYPE_XSKMAP || mapType == BPF_MAP_TYPE_STACK
}

predicate bpf_sk_redirect_map_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_SOCKMAP
}

predicate bpf_sock_map_update_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_SOCKMAP
}

predicate bpf_xdp_adjust_meta_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_perf_event_read_value_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_PERF_EVENT_ARRAY
}

predicate bpf_perf_prog_read_value_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_getsockopt_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_override_return_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_sock_ops_cb_flags_set_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_msg_redirect_map_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_SOCKMAP
}

predicate bpf_msg_apply_bytes_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_msg_cork_bytes_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_msg_pull_data_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_bind_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_xdp_adjust_tail_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_get_xfrm_state_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_stack_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_load_bytes_relative_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_fib_lookup_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_sock_hash_update_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_SOCKHASH
}

predicate bpf_msg_redirect_hash_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_SOCKHASH
}

predicate bpf_sk_redirect_hash_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_SOCKHASH
}

predicate bpf_lwt_push_encap_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_lwt_seg6_store_bytes_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_lwt_seg6_adjust_srh_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_lwt_seg6_action_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_rc_repeat_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_rc_keydown_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_cgroup_id_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_current_cgroup_id_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_local_storage_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED || mapType == BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
}

predicate bpf_sk_select_reuseport_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_SOCKMAP || mapType == BPF_MAP_TYPE_SOCKHASH || mapType == BPF_MAP_TYPE_CGROUP_STORAGE
}

predicate bpf_skb_ancestor_cgroup_id_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_sk_lookup_tcp_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_sk_lookup_udp_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_sk_release_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_map_push_elem_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED || mapType == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE || mapType == BPF_MAP_TYPE_INODE_STORAGE
}

predicate bpf_map_pop_elem_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED || mapType == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
}

predicate bpf_map_peek_elem_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED || mapType == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE || mapType == BPF_MAP_TYPE_INODE_STORAGE
}

predicate bpf_msg_push_data_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_msg_pop_data_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_rc_pointer_rel_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_spin_lock_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_spin_unlock_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_sk_fullsock_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_tcp_sock_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_ecn_set_ce_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_listener_sock_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skc_lookup_tcp_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_tcp_check_syncookie_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_sysctl_get_name_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_sysctl_get_current_value_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_sysctl_get_new_value_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_sysctl_set_new_value_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_strtol_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_strtoul_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_sk_storage_get_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_QUEUE
}

predicate bpf_sk_storage_delete_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_QUEUE
}

predicate bpf_send_signal_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_tcp_gen_syncookie_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_output_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_PERF_EVENT_ARRAY
}

predicate bpf_probe_read_user_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_probe_read_kernel_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_probe_read_user_str_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_probe_read_kernel_str_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_tcp_send_ack_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_send_signal_thread_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_jiffies64_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_read_branch_records_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_ns_current_pid_tgid_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_xdp_output_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_PERF_EVENT_ARRAY
}

predicate bpf_get_netns_cookie_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_current_ancestor_cgroup_id_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_sk_assign_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_ktime_get_boot_ns_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_seq_printf_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_seq_write_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_sk_cgroup_id_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_sk_ancestor_cgroup_id_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_ringbuf_output_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_DEVMAP_HASH
}

predicate bpf_ringbuf_reserve_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_DEVMAP_HASH
}

predicate bpf_ringbuf_submit_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_ringbuf_discard_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_ringbuf_query_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_DEVMAP_HASH
}

predicate bpf_csum_level_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skc_to_tcp6_sock_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skc_to_tcp_sock_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skc_to_tcp_timewait_sock_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skc_to_tcp_request_sock_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skc_to_udp6_sock_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_task_stack_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_load_hdr_opt_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_store_hdr_opt_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_reserve_hdr_opt_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_inode_storage_get_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_STRUCT_OPS
}

predicate bpf_inode_storage_delete_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_STRUCT_OPS
}

predicate bpf_d_path_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_copy_from_user_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_snprintf_btf_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_seq_printf_btf_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_cgroup_classid_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_redirect_neigh_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_per_cpu_ptr_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_this_cpu_ptr_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_redirect_peer_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_task_storage_get_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_RINGBUF
}

predicate bpf_task_storage_delete_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_RINGBUF
}

predicate bpf_get_current_task_btf_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_bprm_opts_set_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_ktime_get_coarse_ns_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_ima_inode_hash_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_sock_from_file_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_check_mtu_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_for_each_map_elem_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_snprintf_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_sys_bpf_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_btf_find_by_name_kind_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_sys_close_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_timer_init_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_timer_set_callback_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_timer_start_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_timer_cancel_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_func_ip_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_attach_cookie_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_task_pt_regs_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_branch_snapshot_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_trace_vprintk_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skc_to_unix_sock_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_kallsyms_lookup_name_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_find_vma_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_loop_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_strncmp_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_func_arg_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_func_ret_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_func_arg_cnt_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_get_retval_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_set_retval_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_xdp_get_buff_len_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_xdp_load_bytes_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_xdp_store_bytes_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_copy_from_user_task_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_skb_set_tstamp_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_ima_file_hash_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_kptr_xchg_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_QUEUE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_STRUCT_OPS || mapType == BPF_MAP_TYPE_RINGBUF || mapType == BPF_MAP_TYPE_BLOOM_FILTER || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_map_lookup_percpu_elem_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH
}

predicate bpf_skc_to_mptcp_sock_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_dynptr_from_mem_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_ringbuf_reserve_dynptr_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_DEVMAP_HASH
}

predicate bpf_ringbuf_submit_dynptr_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_DEVMAP_HASH
}

predicate bpf_ringbuf_discard_dynptr_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_DEVMAP_HASH
}

predicate bpf_dynptr_read_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_dynptr_write_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_dynptr_data_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_tcp_raw_gen_syncookie_ipv4_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_tcp_raw_gen_syncookie_ipv6_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_tcp_raw_check_syncookie_ipv4_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_tcp_raw_check_syncookie_ipv6_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_ktime_get_tai_ns_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_HASH || mapType == BPF_MAP_TYPE_ARRAY || mapType == BPF_MAP_TYPE_PERCPU_HASH || mapType == BPF_MAP_TYPE_PERCPU_ARRAY || mapType == BPF_MAP_TYPE_LRU_HASH || mapType == BPF_MAP_TYPE_LRU_PERCPU_HASH || mapType == BPF_MAP_TYPE_LPM_TRIE || mapType == BPF_MAP_TYPE_SK_STORAGE || mapType == BPF_MAP_TYPE_USER_RINGBUF
}

predicate bpf_user_ringbuf_drain_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_TASK_STORAGE
}

predicate bpf_cgrp_storage_get_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_BLOOM_FILTER
}

predicate bpf_cgrp_storage_delete_mapType(mapType: MapTypes) {
	 mapType  == BPF_MAP_TYPE_BLOOM_FILTER
}

/////////////////////////////////////////// <func, progType> pairs ///////////////////////////////////

predicate bpf_map_lookup_elem_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_map_update_elem_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_map_delete_elem_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_probe_read_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_ktime_get_ns_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_trace_printk_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_get_prandom_u32_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_get_smp_processor_id_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_skb_store_bytes_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SK_SKB
}

predicate bpf_l3_csum_replace_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_XMIT
}

predicate bpf_l4_csum_replace_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_XMIT
}

predicate bpf_tail_call_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_clone_redirect_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_XMIT
}

predicate bpf_get_current_pid_tgid_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_get_current_uid_gid_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_get_current_comm_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_get_cgroup_classid_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL
}

predicate bpf_skb_vlan_push_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT
}

predicate bpf_skb_vlan_pop_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT
}

predicate bpf_skb_get_tunnel_key_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_XMIT
}

predicate bpf_skb_set_tunnel_key_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_XMIT
}

predicate bpf_perf_event_read_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_redirect_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_LWT_XMIT
}

predicate bpf_get_route_realm_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL
}

predicate bpf_perf_event_output_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_skb_load_bytes_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR
}

predicate bpf_get_stackid_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_csum_diff_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL
}

predicate bpf_skb_get_tunnel_opt_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_XMIT
}

predicate bpf_skb_set_tunnel_opt_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_XMIT
}

predicate bpf_skb_change_proto_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT
}

predicate bpf_skb_change_type_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT
}

predicate bpf_skb_under_cgroup_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL
}

predicate bpf_get_hash_recalc_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL
}

predicate bpf_get_current_task_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_current_task_under_cgroup_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_skb_change_tail_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SK_SKB
}

predicate bpf_skb_pull_data_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL
}

predicate bpf_csum_update_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_XMIT
}

predicate bpf_set_hash_invalid_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_XMIT
}

predicate bpf_get_numa_node_id_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_skb_change_head_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SK_SKB
}

predicate bpf_xdp_adjust_head_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_XDP
}

predicate bpf_probe_read_str_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_get_socket_cookie_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_get_socket_uid_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_SK_SKB
}

predicate bpf_set_hash_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT
}

predicate bpf_setsockopt_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCK_OPS
}

predicate bpf_skb_adjust_room_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_SK_SKB
}

predicate bpf_redirect_map_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_XDP
}

predicate bpf_sk_redirect_map_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SK_SKB
}

predicate bpf_sock_map_update_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCK_OPS
}

predicate bpf_xdp_adjust_meta_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_XDP
}

predicate bpf_perf_event_read_value_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_perf_prog_read_value_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_PERF_EVENT
}

predicate bpf_getsockopt_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCK_OPS
}

predicate bpf_override_return_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE
}

predicate bpf_sock_ops_cb_flags_set_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCK_OPS
}

predicate bpf_msg_redirect_map_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SK_MSG
}

predicate bpf_msg_apply_bytes_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SK_MSG
}

predicate bpf_msg_cork_bytes_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SK_MSG
}

predicate bpf_msg_pull_data_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SK_MSG
}

predicate bpf_xdp_adjust_tail_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_XDP
}

predicate bpf_skb_get_xfrm_state_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT
}

predicate bpf_get_stack_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_skb_load_bytes_relative_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_SK_REUSEPORT
}

predicate bpf_fib_lookup_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP
}

predicate bpf_sock_hash_update_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCK_OPS
}

predicate bpf_msg_redirect_hash_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SK_MSG
}

predicate bpf_sk_redirect_hash_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SK_SKB
}

predicate bpf_lwt_push_encap_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_XMIT
}

predicate bpf_skb_cgroup_id_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_CGROUP_SKB
}

predicate bpf_get_current_cgroup_id_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_get_local_storage_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT
}

predicate bpf_sk_select_reuseport_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SK_REUSEPORT
}

predicate bpf_skb_ancestor_cgroup_id_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_CGROUP_SKB
}

predicate bpf_sk_lookup_tcp_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR
}

predicate bpf_sk_lookup_udp_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR
}

predicate bpf_sk_release_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_SK_LOOKUP
}

predicate bpf_map_push_elem_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_map_pop_elem_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_map_peek_elem_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_msg_push_data_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SK_MSG
}

predicate bpf_msg_pop_data_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SK_MSG
}

predicate bpf_spin_lock_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_spin_unlock_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_sk_fullsock_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_CGROUP_SKB
}

predicate bpf_tcp_sock_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT
}

predicate bpf_skb_ecn_set_ce_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_CGROUP_SKB
}

predicate bpf_get_listener_sock_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_CGROUP_SKB
}

predicate bpf_skc_lookup_tcp_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR
}

predicate bpf_tcp_check_syncookie_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP
}

predicate bpf_sysctl_get_name_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_CGROUP_SYSCTL
}

predicate bpf_sysctl_get_current_value_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_CGROUP_SYSCTL
}

predicate bpf_sysctl_get_new_value_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_CGROUP_SYSCTL
}

predicate bpf_sysctl_set_new_value_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_CGROUP_SYSCTL
}

predicate bpf_strtol_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_strtoul_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_sk_storage_get_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_sk_storage_delete_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_send_signal_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_tcp_gen_syncookie_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP
}

predicate bpf_skb_output_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_probe_read_user_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_probe_read_kernel_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_probe_read_user_str_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_probe_read_kernel_str_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_send_signal_thread_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_jiffies64_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_read_branch_records_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_PERF_EVENT
}

predicate bpf_get_ns_current_pid_tgid_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_xdp_output_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_get_netns_cookie_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT
}

predicate bpf_get_current_ancestor_cgroup_id_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_sk_assign_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_SK_LOOKUP
}

predicate bpf_ktime_get_boot_ns_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_sk_cgroup_id_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_CGROUP_SKB
}

predicate bpf_sk_ancestor_cgroup_id_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_CGROUP_SKB
}

predicate bpf_ringbuf_output_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_ringbuf_reserve_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_ringbuf_submit_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_ringbuf_discard_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_ringbuf_query_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_csum_level_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_LWT_XMIT
}

predicate bpf_skc_to_tcp6_sock_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_skc_to_tcp_sock_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_skc_to_tcp_timewait_sock_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_skc_to_tcp_request_sock_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_skc_to_udp6_sock_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_get_task_stack_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_load_hdr_opt_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCK_OPS
}

predicate bpf_store_hdr_opt_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCK_OPS
}

predicate bpf_reserve_hdr_opt_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCK_OPS
}

predicate bpf_inode_storage_get_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_LSM
}

predicate bpf_inode_storage_delete_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_LSM
}

predicate bpf_d_path_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_copy_from_user_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_snprintf_btf_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_redirect_neigh_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT
}

predicate bpf_per_cpu_ptr_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_this_cpu_ptr_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_redirect_peer_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT
}

predicate bpf_task_storage_get_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_task_storage_delete_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_get_current_task_btf_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_bprm_opts_set_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_LSM
}

predicate bpf_ktime_get_coarse_ns_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_SK_LOOKUP
}

predicate bpf_ima_inode_hash_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_LSM
}

predicate bpf_sock_from_file_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_check_mtu_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP
}

predicate bpf_for_each_map_elem_progType(progType: ProgTypes) {
	progType == BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_snprintf_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_sys_bpf_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SYSCALL
}

predicate bpf_btf_find_by_name_kind_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SYSCALL
}

predicate bpf_sys_close_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SYSCALL
}

predicate bpf_timer_init_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_timer_set_callback_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_timer_start_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_timer_cancel_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_get_func_ip_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_get_attach_cookie_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT
}

predicate bpf_task_pt_regs_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_get_branch_snapshot_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_trace_vprintk_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_skc_to_unix_sock_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_kallsyms_lookup_name_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SYSCALL
}

predicate bpf_find_vma_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_loop_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_strncmp_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_xdp_get_buff_len_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_xdp_load_bytes_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_XDP
}

predicate bpf_xdp_store_bytes_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_XDP
}

predicate bpf_copy_from_user_task_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_skb_set_tstamp_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT
}

predicate bpf_ima_file_hash_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_LSM
}

predicate bpf_kptr_xchg_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_map_lookup_percpu_elem_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_skc_to_mptcp_sock_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL
}

predicate bpf_dynptr_from_mem_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_ringbuf_reserve_dynptr_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_ringbuf_submit_dynptr_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_ringbuf_discard_dynptr_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_dynptr_read_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_dynptr_write_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_dynptr_data_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_tcp_raw_gen_syncookie_ipv4_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP
}

predicate bpf_tcp_raw_gen_syncookie_ipv6_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP
}

predicate bpf_tcp_raw_check_syncookie_ipv4_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP
}

predicate bpf_tcp_raw_check_syncookie_ipv6_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_XDP
}

predicate bpf_ktime_get_tai_ns_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_user_ringbuf_drain_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_cgrp_storage_get_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}

predicate bpf_cgrp_storage_delete_progType(progType: ProgTypes) {
	progType== BPF_PROG_TYPE_SOCKET_FILTER || progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_SCHED_CLS || progType == BPF_PROG_TYPE_SCHED_ACT || progType == BPF_PROG_TYPE_TRACEPOINT || progType == BPF_PROG_TYPE_XDP || progType == BPF_PROG_TYPE_PERF_EVENT || progType == BPF_PROG_TYPE_CGROUP_SKB || progType == BPF_PROG_TYPE_CGROUP_SOCK || progType == BPF_PROG_TYPE_LWT_IN || progType == BPF_PROG_TYPE_LWT_OUT || progType == BPF_PROG_TYPE_LWT_XMIT || progType == BPF_PROG_TYPE_SOCK_OPS || progType == BPF_PROG_TYPE_SK_SKB || progType == BPF_PROG_TYPE_CGROUP_DEVICE || progType == BPF_PROG_TYPE_SK_MSG || progType == BPF_PROG_TYPE_RAW_TRACEPOINT || progType == BPF_PROG_TYPE_CGROUP_SOCK_ADDR || progType == BPF_PROG_TYPE_LWT_SEG6LOCAL || progType == BPF_PROG_TYPE_SK_REUSEPORT || progType == BPF_PROG_TYPE_FLOW_DISSECTOR || progType == BPF_PROG_TYPE_CGROUP_SYSCTL || progType == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE || progType == BPF_PROG_TYPE_CGROUP_SOCKOPT || progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SK_LOOKUP || progType == BPF_PROG_TYPE_SYSCALL || progType == BPF_PROG_TYPE_NETFILTER
}