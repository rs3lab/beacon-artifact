#pragma once
#include "../../include/linux/bpf.h"


#define BATCH_OPS(_name)			\
	.map_lookup_batch =			\
	#_name"_map_lookup_batch",		\
	.map_lookup_and_delete_batch =		\
	#_name"_map_lookup_and_delete_batch",	\
	.map_update_batch =			\
	"generic_map_update_batch",		\
	.map_delete_batch =			\
	"generic_map_delete_batch"

/* map is generic key/value storage optionally accessible by eBPF programs */
// Comes from updated bpf.h
// Other structures can be found via bpf_types.h
struct bpf_map_ops {
	const char *map_meta_equal;
	const char *map_alloc_check;
	const char *map_alloc;
	const char *map_free;

	const char *map_get_next_key;
	const char *map_poll;
	const char *map_release_uref;
	const char *map_lookup_elem;
	const char *map_lookup_and_delete_elem;
	const char *map_lookup_elem_sys_only; 
	const char *map_update_elem;
	const char *map_delete_elem;
	const char *map_gen_lookup;
	const char *map_direct_value_addr;
	const char *map_direct_value_meta;
	const char *map_mmap;
	const char *map_lookup_percpu_elem;
	const char *map_seq_show_elem;
	const char *map_check_btf;
	const char *map_lookup_batch;
	const char *map_lookup_and_delete_batch;
	const char *map_update_batch;
	const char *map_delete_batch;
	const char *map_set_for_each_callback_args;
	const char *map_for_each_callback ;
	const char *map_mem_usage ;
	const char *map_btf_id;
	const char *iter_seq_info;

	const char *map_fd_get_ptr;
	const char *map_fd_put_ptr;
	const char *map_fd_sys_lookup_elem ;

	const char *map_poke_track ;
	const char *map_poke_untrack ;
	const char *map_poke_run ;
	const char *map_release;
	
	const char *map_push_elem;
	const char *map_peek_elem;
	const char *map_pop_elem;
	const char *map_owner_storage_ptr;
	const char *map_redirect;
	const char *map_local_storage_charge;
	const char *map_local_storage_uncharge; 
}; 



const struct bpf_map_ops array_map_ops = {
	.map_meta_equal = "array_map_meta_equal",
	.map_alloc_check = "array_map_alloc_check",
	.map_alloc = "array_map_alloc",
	.map_free = "array_map_free",
	.map_get_next_key = "array_map_get_next_key",
	.map_release_uref = "array_map_free_timers",
	.map_lookup_elem = "array_map_lookup_elem",
	.map_update_elem = "array_map_update_elem",
	.map_delete_elem = "array_map_delete_elem",
	.map_gen_lookup = "array_map_gen_lookup",
	.map_direct_value_addr = "array_map_direct_value_addr",
	.map_direct_value_meta = "array_map_direct_value_meta",
	.map_mmap = "array_map_mmap",
	.map_seq_show_elem = "array_map_seq_show_elem",
	.map_check_btf = "array_map_check_btf",
	.map_lookup_batch = "generic_map_lookup_batch",
	.map_update_batch = "generic_map_update_batch",
	.map_set_for_each_callback_args = "map_set_for_each_callback_args",
	.map_for_each_callback = "bpf_for_each_array_elem",
	.map_mem_usage = "array_map_mem_usage",
	.map_btf_id = "array_map_btf_ids",
	.iter_seq_info = "iter_seq_info",
};
const struct bpf_map_ops percpu_array_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc_check = "array_map_alloc_check",
	.map_alloc = "array_map_alloc",
	.map_free = "array_map_free",
	.map_get_next_key = "array_map_get_next_key",
	.map_lookup_elem = "percpu_array_map_lookup_elem",
	.map_update_elem = "array_map_update_elem",
	.map_delete_elem = "array_map_delete_elem",
	.map_lookup_percpu_elem = "percpu_array_map_lookup_percpu_elem",
	.map_seq_show_elem = "percpu_array_map_seq_show_elem",
	.map_check_btf = "array_map_check_btf",
	.map_lookup_batch = "generic_map_lookup_batch",
	.map_update_batch = "generic_map_update_batch",
	.map_set_for_each_callback_args = "map_set_for_each_callback_args",
	.map_for_each_callback = "bpf_for_each_array_elem",
	.map_mem_usage = "array_map_mem_usage",
	.map_btf_id = "&array_map_btf_ids[0]",
	.iter_seq_info = "iter_seq_info",
};
const struct bpf_map_ops prog_array_map_ops = {
	.map_alloc_check = "fd_array_map_alloc_check",
	.map_alloc = "prog_array_map_alloc",
	.map_free = "prog_array_map_free",
	.map_get_next_key = "array_map_get_next_key",
	.map_release_uref = "prog_array_map_clear",
	.map_lookup_elem = "fd_array_map_lookup_elem",
	.map_delete_elem = "fd_array_map_delete_elem",
	.map_seq_show_elem = "prog_array_map_seq_show_elem",
	.map_mem_usage = "array_map_mem_usage",
	.map_btf_id = "&array_map_btf_ids[0]",
	.map_fd_get_ptr = "prog_fd_array_get_ptr",
	.map_fd_put_ptr = "prog_fd_array_put_ptr",
	.map_fd_sys_lookup_elem = "prog_fd_array_sys_lookup_elem",
	.map_poke_track = "prog_array_map_poke_track",
	.map_poke_untrack = "prog_array_map_poke_untrack",
	.map_poke_run = "prog_array_map_poke_run",
};
const struct bpf_map_ops perf_event_array_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc_check = "fd_array_map_alloc_check",
	.map_alloc = "array_map_alloc",
	.map_free = "perf_event_fd_array_map_free",
	.map_get_next_key = "array_map_get_next_key",
	.map_lookup_elem = "fd_array_map_lookup_elem",
	.map_delete_elem = "fd_array_map_delete_elem",
	.map_check_btf = "map_check_no_btf",
	.map_mem_usage = "array_map_mem_usage",
	.map_btf_id = "&array_map_btf_ids[0]",
	.map_fd_get_ptr = "perf_event_fd_array_get_ptr",
	.map_fd_put_ptr = "perf_event_fd_array_put_ptr",
	.map_release = "perf_event_fd_array_release",
};
const struct bpf_map_ops cgroup_array_map_ops = {
    .map_meta_equal = "bpf_map_meta_equal",
    .map_alloc_check = "fd_array_map_alloc_check",
    .map_alloc = "array_map_alloc",
    .map_free = "cgroup_fd_array_free",
    .map_get_next_key = "array_map_get_next_key",
    .map_lookup_elem = "fd_array_map_lookup_elem",
    .map_delete_elem = "fd_array_map_delete_elem",
    .map_check_btf = "map_check_no_btf",
    .map_mem_usage = "array_map_mem_usage",
    .map_btf_id = "&array_map_btf_ids[0]",
    .map_fd_get_ptr = "cgroup_fd_array_get_ptr",
    .map_fd_put_ptr = "cgroup_fd_array_put_ptr",
};
const struct bpf_map_ops array_of_maps_map_ops = {
    .map_alloc_check = "fd_array_map_alloc_check",
    .map_alloc = "array_of_map_alloc",
    .map_free = "array_of_map_free",
    .map_get_next_key = "array_map_get_next_key",
    .map_lookup_elem = "array_of_map_lookup_elem",
    .map_delete_elem = "fd_array_map_delete_elem",
    .map_gen_lookup = "array_of_map_gen_lookup",
    .map_check_btf = "map_check_no_btf",
    .map_lookup_batch = "generic_map_lookup_batch",
    .map_update_batch = "generic_map_update_batch",
    .map_mem_usage = "array_map_mem_usage",
    .map_btf_id = "&array_map_btf_ids[0]",
    .map_fd_get_ptr = "bpf_map_fd_get_ptr",
    .map_fd_put_ptr = "bpf_map_fd_put_ptr",
    .map_fd_sys_lookup_elem = "bpf_map_fd_sys_lookup_elem",
};
const struct bpf_map_ops bloom_filter_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc = "bloom_map_alloc",
	.map_free = "bloom_map_free",
	.map_get_next_key = "bloom_map_get_next_key",
	.map_lookup_elem = "bloom_map_lookup_elem",
	.map_update_elem = "bloom_map_update_elem",
	.map_delete_elem = "bloom_map_delete_elem",
	.map_check_btf = "bloom_map_check_btf",
	.map_mem_usage = "bloom_map_mem_usage",
	.map_btf_id = "&bpf_bloom_map_btf_ids[0]",
	.map_push_elem = "bloom_map_push_elem",
	.map_peek_elem = "bloom_map_peek_elem",
	.map_pop_elem = "bloom_map_pop_elem",
};
const struct bpf_map_ops cgrp_storage_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc_check = "bpf_local_storage_map_alloc_check",
	.map_alloc = "cgroup_storage_map_alloc",
	.map_free = "cgroup_storage_map_free",
	.map_get_next_key = "notsupp_get_next_key",
	.map_lookup_elem = "bpf_cgrp_storage_lookup_elem",
	.map_update_elem = "bpf_cgrp_storage_update_elem",
	.map_delete_elem = "bpf_cgrp_storage_delete_elem",
	.map_check_btf = "bpf_local_storage_map_check_btf",
	.map_mem_usage = "bpf_local_storage_map_mem_usage",
	.map_btf_id = "&bpf_local_storage_map_btf_id[0]",
	.map_owner_storage_ptr = "cgroup_storage_ptr",
};
const struct bpf_map_ops inode_storage_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc_check = "bpf_local_storage_map_alloc_check",
	.map_alloc = "inode_storage_map_alloc",
	.map_free = "inode_storage_map_free",
	.map_get_next_key = "notsupp_get_next_key",
	.map_lookup_elem = "bpf_fd_inode_storage_lookup_elem",
	.map_update_elem = "bpf_fd_inode_storage_update_elem",
	.map_delete_elem = "bpf_fd_inode_storage_delete_elem",
	.map_check_btf = "bpf_local_storage_map_check_btf",
	.map_mem_usage = "bpf_local_storage_map_mem_usage",
	.map_btf_id = "&bpf_local_storage_map_btf_id[0]",
	.map_owner_storage_ptr = "inode_storage_ptr",
};
const struct bpf_map_ops bpf_struct_ops_map_ops = {
	.map_alloc_check = "bpf_struct_ops_map_alloc_check",
	.map_alloc = "bpf_struct_ops_map_alloc",
	.map_free = "bpf_struct_ops_map_free",
	.map_get_next_key = "bpf_struct_ops_map_get_next_key",
	.map_lookup_elem = "bpf_struct_ops_map_lookup_elem",
	.map_update_elem = "bpf_struct_ops_map_update_elem",
	.map_delete_elem = "bpf_struct_ops_map_delete_elem",
	.map_seq_show_elem = "bpf_struct_ops_map_seq_show_elem",
	.map_mem_usage = "bpf_struct_ops_map_mem_usage",
	.map_btf_id = "&bpf_struct_ops_map_btf_ids[0]",
};
const struct bpf_map_ops task_storage_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc_check = "bpf_local_storage_map_alloc_check",
	.map_alloc = "task_storage_map_alloc",
	.map_free = "task_storage_map_free",
	.map_get_next_key = "notsupp_get_next_key",
	.map_lookup_elem = "bpf_pid_task_storage_lookup_elem",
	.map_update_elem = "bpf_pid_task_storage_update_elem",
	.map_delete_elem = "bpf_pid_task_storage_delete_elem",
	.map_check_btf = "bpf_local_storage_map_check_btf",
	.map_mem_usage = "bpf_local_storage_map_mem_usage",
	.map_btf_id = "&bpf_local_storage_map_btf_id[0]",
	.map_owner_storage_ptr = "task_storage_ptr",
};
const struct bpf_map_ops cpu_map_ops = {
	.map_meta_equal		= "bpf_map_meta_equal",
	.map_alloc		= "cpu_map_alloc",
	.map_free		= "cpu_map_free",
	.map_get_next_key	= "cpu_map_get_next_key",
	.map_lookup_elem	= "cpu_map_lookup_elem",
	.map_update_elem	= "cpu_map_update_elem",
	.map_delete_elem	= "cpu_map_delete_elem",
	.map_check_btf		= "map_check_no_btf",
	.map_mem_usage		= "cpu_map_mem_usage",
	.map_btf_id		= "&cpu_map_btf_ids[0]",
	.map_redirect		= "cpu_map_redirect",
};
const struct bpf_map_ops dev_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc = "dev_map_alloc",
	.map_free = "dev_map_free",
	.map_get_next_key = "dev_map_get_next_key",
	.map_lookup_elem = "dev_map_lookup_elem",
	.map_update_elem = "dev_map_update_elem",
	.map_delete_elem = "dev_map_delete_elem",
	.map_check_btf = "map_check_no_btf",
	.map_mem_usage = "dev_map_mem_usage",
	.map_btf_id = "&dev_map_btf_ids[0]",
	.map_redirect = "dev_map_redirect",
};
const struct bpf_map_ops dev_map_hash_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc = "dev_map_alloc",
	.map_free = "dev_map_free",
	.map_get_next_key = "dev_map_hash_get_next_key",
	.map_lookup_elem = "dev_map_hash_lookup_elem",
	.map_update_elem = "dev_map_hash_update_elem",
	.map_delete_elem = "dev_map_hash_delete_elem",
	.map_check_btf = "map_check_no_btf",
	.map_mem_usage = "dev_map_mem_usage",
	.map_btf_id = "&dev_map_btf_ids[0]",
	.map_redirect = "dev_hash_map_redirect",
};
const struct bpf_map_ops htab_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc_check = "htab_map_alloc_check",
	.map_alloc = "htab_map_alloc",
	.map_free = "htab_map_free",
	.map_get_next_key = "htab_map_get_next_key",
	.map_release_uref = "htab_map_free_timers",
	.map_lookup_elem = "htab_map_lookup_elem",
	.map_lookup_and_delete_elem = "htab_map_lookup_and_delete_elem",
	.map_update_elem = "htab_map_update_elem",
	.map_delete_elem = "htab_map_delete_elem",
	.map_gen_lookup = "htab_map_gen_lookup",
	.map_seq_show_elem = "htab_map_seq_show_elem",
	BATCH_OPS(htab),
	.map_set_for_each_callback_args = "map_set_for_each_callback_args",
	.map_for_each_callback = "bpf_for_each_hash_elem",
	.map_mem_usage = "htab_map_mem_usage",
	.map_btf_id = "&htab_map_btf_ids[0]",
	.iter_seq_info = "&iter_seq_info",
};
const struct bpf_map_ops htab_lru_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc_check = "htab_map_alloc_check",
	.map_alloc = "htab_map_alloc",
	.map_free = "htab_map_free",
	.map_get_next_key = "htab_map_get_next_key",
	.map_release_uref = "htab_map_free_timers",
	.map_lookup_elem = "htab_lru_map_lookup_elem",
	.map_lookup_and_delete_elem = "htab_lru_map_lookup_and_delete_elem",
	.map_lookup_elem_sys_only = "htab_lru_map_lookup_elem_sys",
	.map_update_elem = "htab_lru_map_update_elem",
	.map_delete_elem = "htab_lru_map_delete_elem",
	.map_gen_lookup = "htab_lru_map_gen_lookup",
	.map_seq_show_elem = "htab_map_seq_show_elem",
	BATCH_OPS(htab_lru),
	.map_set_for_each_callback_args = "map_set_for_each_callback_args",
	.map_for_each_callback = "bpf_for_each_hash_elem",
	.map_mem_usage = "htab_map_mem_usage",
	.map_btf_id = "&htab_map_btf_ids[0]",
	.iter_seq_info = "&iter_seq_info",
};
const struct bpf_map_ops htab_percpu_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc_check = "htab_map_alloc_check",
	.map_alloc = "htab_map_alloc",
	.map_free = "htab_map_free",
	.map_get_next_key = "htab_map_get_next_key",
	.map_lookup_elem = "htab_percpu_map_lookup_elem",
	.map_lookup_and_delete_elem = "htab_percpu_map_lookup_and_delete_elem",
	.map_update_elem = "htab_percpu_map_update_elem",
	.map_delete_elem = "htab_map_delete_elem",
	.map_lookup_percpu_elem = "htab_percpu_map_lookup_percpu_elem",
	.map_seq_show_elem = "htab_percpu_map_seq_show_elem",
	BATCH_OPS(htab_percpu),
	.map_set_for_each_callback_args = "map_set_for_each_callback_args",
	.map_for_each_callback = "bpf_for_each_hash_elem",
	.map_mem_usage = "htab_map_mem_usage",
	.map_btf_id = "&htab_map_btf_ids[0]",
	.iter_seq_info = "&iter_seq_info",
};
const struct bpf_map_ops htab_lru_percpu_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc_check = "htab_map_alloc_check",
	.map_alloc = "htab_map_alloc",
	.map_free = "htab_map_free",
	.map_get_next_key = "htab_map_get_next_key",
	.map_lookup_elem = "htab_lru_percpu_map_lookup_elem",
	.map_lookup_and_delete_elem = "htab_lru_percpu_map_lookup_and_delete_elem",
	.map_update_elem = "htab_lru_percpu_map_update_elem",
	.map_delete_elem = "htab_lru_map_delete_elem",
	.map_lookup_percpu_elem = "htab_lru_percpu_map_lookup_percpu_elem",
	.map_seq_show_elem = "htab_percpu_map_seq_show_elem",
	BATCH_OPS(htab_lru_percpu),
	.map_set_for_each_callback_args = "map_set_for_each_callback_args",
	.map_for_each_callback = "bpf_for_each_hash_elem",
	.map_mem_usage = "htab_map_mem_usage",
	.map_btf_id = "&htab_map_btf_ids[0]",
	.iter_seq_info = "&iter_seq_info",
};
const struct bpf_map_ops htab_of_maps_map_ops = {
	.map_alloc_check = "fd_htab_map_alloc_check",
	.map_alloc = "htab_of_map_alloc",
	.map_free = "htab_of_map_free",
	.map_get_next_key = "htab_map_get_next_key",
	.map_lookup_elem = "htab_of_map_lookup_elem",
	.map_delete_elem = "htab_map_delete_elem",
	.map_gen_lookup = "htab_of_map_gen_lookup",
	.map_check_btf = "map_check_no_btf",
	BATCH_OPS(htab),
	.map_mem_usage = "htab_map_mem_usage",
	.map_btf_id = "&htab_map_btf_ids[0]",
	.map_fd_get_ptr = "bpf_map_fd_get_ptr",
	.map_fd_put_ptr = "bpf_map_fd_put_ptr",
	.map_fd_sys_lookup_elem = "bpf_map_fd_sys_lookup_elem",
};
const struct bpf_map_ops cgroup_storage_map_ops = {
	.map_alloc = "cgroup_storage_map_alloc",
	.map_free = "cgroup_storage_map_free",
	.map_get_next_key = "cgroup_storage_get_next_key",
	.map_lookup_elem = "cgroup_storage_lookup_elem",
	.map_update_elem = "cgroup_storage_update_elem",
	.map_delete_elem = "cgroup_storage_delete_elem",
	.map_seq_show_elem = "cgroup_storage_seq_show_elem",
	.map_check_btf = "cgroup_storage_check_btf",
	.map_mem_usage = "cgroup_storage_map_usage",
	.map_btf_id = "&cgroup_storage_map_btf_ids[0]",
};
const struct bpf_map_ops trie_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc = "trie_alloc",
	.map_free = "trie_free",
	.map_get_next_key = "trie_get_next_key",
	.map_lookup_elem = "trie_lookup_elem",
	.map_update_elem = "trie_update_elem",
	.map_delete_elem = "trie_delete_elem",
	.map_check_btf = "trie_check_btf",
	.map_lookup_batch = "generic_map_lookup_batch",
	.map_update_batch = "generic_map_update_batch",
	.map_delete_batch = "generic_map_delete_batch",
	.map_mem_usage = "trie_mem_usage",
	.map_btf_id = "&trie_map_btf_ids[0]",
};
const struct bpf_map_ops queue_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc_check = "queue_stack_map_alloc_check",
	.map_alloc = "queue_stack_map_alloc",
	.map_free = "queue_stack_map_free",
	.map_get_next_key = "queue_stack_map_get_next_key",
	.map_lookup_elem = "queue_stack_map_lookup_elem",
	.map_update_elem = "queue_stack_map_update_elem",
	.map_delete_elem = "queue_stack_map_delete_elem",
	.map_mem_usage = "queue_stack_map_mem_usage",
	.map_btf_id = "&queue_map_btf_ids[0]",
	.map_push_elem = "queue_stack_map_push_elem",
	.map_peek_elem = "queue_map_peek_elem",
	.map_pop_elem = "queue_map_pop_elem",
};
const struct bpf_map_ops stack_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc_check = "queue_stack_map_alloc_check",
	.map_alloc = "queue_stack_map_alloc",
	.map_free = "queue_stack_map_free",
	.map_get_next_key = "queue_stack_map_get_next_key",
	.map_lookup_elem = "queue_stack_map_lookup_elem",
	.map_update_elem = "queue_stack_map_update_elem",
	.map_delete_elem = "queue_stack_map_delete_elem",
	.map_mem_usage = "queue_stack_map_mem_usage",
	.map_btf_id = "&queue_map_btf_ids[0]",
	.map_push_elem = "queue_stack_map_push_elem",
	.map_peek_elem = "stack_map_peek_elem",
	.map_pop_elem = "stack_map_pop_elem",
};
const struct bpf_map_ops reuseport_array_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc_check = "reuseport_array_alloc_check",
	.map_alloc = "reuseport_array_alloc",
	.map_free = "reuseport_array_free",
	.map_get_next_key = "reuseport_array_get_next_key",
	.map_lookup_elem = "reuseport_array_lookup_elem",
	.map_delete_elem = "reuseport_array_delete_elem",
	.map_mem_usage = "reuseport_array_mem_usage",
	.map_btf_id = "&reuseport_array_map_btf_ids[0]",
};
const struct bpf_map_ops ringbuf_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc = "ringbuf_map_alloc",
	.map_free = "ringbuf_map_free",
	.map_get_next_key = "ringbuf_map_get_next_key",
	.map_poll = "ringbuf_map_poll_kern",
	.map_lookup_elem = "ringbuf_map_lookup_elem",
	.map_update_elem = "ringbuf_map_update_elem",
	.map_delete_elem = "ringbuf_map_delete_elem",
	.map_mmap = "ringbuf_map_mmap_kern",
	.map_mem_usage = "ringbuf_map_mem_usage",
	.map_btf_id = "&ringbuf_map_btf_ids[0]",
};
const struct bpf_map_ops user_ringbuf_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc = "ringbuf_map_alloc",
	.map_free = "ringbuf_map_free",
	.map_get_next_key = "ringbuf_map_get_next_key",
	.map_poll = "ringbuf_map_poll_user",
	.map_lookup_elem = "ringbuf_map_lookup_elem",
	.map_update_elem = "ringbuf_map_update_elem",
	.map_delete_elem = "ringbuf_map_delete_elem",
	.map_mmap = "ringbuf_map_mmap_user",
	.map_mem_usage = "ringbuf_map_mem_usage",
	.map_btf_id = "&user_ringbuf_map_btf_ids[0]",
};
const struct bpf_map_ops stack_trace_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc = "stack_map_alloc",
	.map_free = "stack_map_free",
	.map_get_next_key = "stack_map_get_next_key",
	.map_lookup_elem = "stack_map_lookup_elem",
	.map_update_elem = "stack_map_update_elem",
	.map_delete_elem = "stack_map_delete_elem",
	.map_check_btf = "map_check_no_btf",
	.map_mem_usage = "stack_map_mem_usage",
	.map_btf_id = "&stack_trace_map_btf_ids[0]",
};
const struct bpf_map_ops bpf_map_offload_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc = "bpf_map_offload_map_alloc",
	.map_free = "bpf_map_offload_map_free",
	.map_check_btf = "map_check_no_btf",
	.map_mem_usage = "bpf_map_offload_map_mem_usage",
};
const struct bpf_map_ops sk_storage_map_ops = {
	.map_meta_equal = "bpf_map_meta_equal",
	.map_alloc_check = "bpf_local_storage_map_alloc_check",
	.map_alloc = "bpf_sk_storage_map_alloc",
	.map_free = "bpf_sk_storage_map_free",
	.map_get_next_key = "notsupp_get_next_key",
	.map_lookup_elem = "bpf_fd_sk_storage_lookup_elem",
	.map_update_elem = "bpf_fd_sk_storage_update_elem",
	.map_delete_elem = "bpf_fd_sk_storage_delete_elem",
	.map_check_btf = "bpf_local_storage_map_check_btf",
	.map_mem_usage = "bpf_local_storage_map_mem_usage",
	.map_btf_id = "&bpf_local_storage_map_btf_id[0]",
	.map_owner_storage_ptr = "bpf_sk_storage_ptr",
	.map_local_storage_charge = "bpf_sk_storage_charge",
	.map_local_storage_uncharge = "bpf_sk_storage_uncharge",
};
const struct bpf_map_ops sock_map_ops = {
	.map_meta_equal		= "bpf_map_meta_equal",
	.map_alloc		= "sock_map_alloc",
	.map_free		= "sock_map_free",
	.map_get_next_key	= "sock_map_get_next_key",
	.map_release_uref	= "sock_map_release_progs",
	.map_lookup_elem	= "sock_map_lookup",
	.map_lookup_elem_sys_only = "sock_map_lookup_sys",
	.map_update_elem	= "sock_map_update_elem",
	.map_delete_elem	= "sock_map_delete_elem",
	.map_check_btf		= "map_check_no_btf",
	.map_mem_usage		= "sock_map_mem_usage",
	.map_btf_id		= "&sock_map_btf_ids[0]",
	.iter_seq_info		= "&sock_map_iter_seq_info",
};
const struct bpf_map_ops sock_hash_ops = {
	.map_meta_equal		= "bpf_map_meta_equal",
	.map_alloc		= "sock_hash_alloc",
	.map_free		= "sock_hash_free",
	.map_get_next_key	= "sock_hash_get_next_key",
	.map_release_uref	= "sock_hash_release_progs",
	.map_lookup_elem	= "sock_hash_lookup",
	.map_lookup_elem_sys_only = "sock_hash_lookup_sys",
	.map_update_elem	= "sock_map_update_elem",
	.map_delete_elem	= "sock_hash_delete_elem",
	.map_check_btf		= "map_check_no_btf",
	.map_mem_usage		= "sock_hash_mem_usage",
	.map_btf_id		= "&sock_hash_map_btf_ids[0]",
	.iter_seq_info		= "&sock_hash_iter_seq_info",
};
const struct bpf_map_ops xsk_map_ops = {
	.map_meta_equal = "xsk_map_meta_equal",
	.map_alloc = "xsk_map_alloc",
	.map_free = "xsk_map_free",
	.map_get_next_key = "xsk_map_get_next_key",
	.map_lookup_elem = "xsk_map_lookup_elem",
	.map_lookup_elem_sys_only = "xsk_map_lookup_elem_sys_only",
	.map_update_elem = "xsk_map_update_elem",
	.map_delete_elem = "xsk_map_delete_elem",
	.map_gen_lookup = "xsk_map_gen_lookup",
	.map_check_btf = "map_check_no_btf",
	.map_mem_usage = "xsk_map_mem_usage",
	.map_btf_id = "&xsk_map_btf_ids[0]",
	.map_redirect = "xsk_map_redirect",
};
const struct bpf_map_ops default_ops = {};
const struct bpf_map_ops getMapOp(bpf_map_type maptype){
	switch (maptype)
	{
	case BPF_MAP_TYPE_ARRAY:
		return array_map_ops;
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		return percpu_array_map_ops;
	case BPF_MAP_TYPE_PROG_ARRAY:
		return prog_array_map_ops;
	case BPF_MAP_TYPE_CGROUP_ARRAY:
		return cgroup_array_map_ops;
	case BPF_MAP_TYPE_ARRAY_OF_MAPS:
		return array_of_maps_map_ops;
	case BPF_MAP_TYPE_HASH:
		return htab_map_ops;
	case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
		return perf_event_array_map_ops;
	case BPF_MAP_TYPE_PERCPU_HASH:
		return htab_percpu_map_ops;
	case BPF_MAP_TYPE_STACK_TRACE:
		return stack_trace_map_ops;
	case BPF_MAP_TYPE_LRU_HASH:
		return htab_lru_map_ops;
	case BPF_MAP_TYPE_LRU_PERCPU_HASH:
		return htab_lru_percpu_map_ops;
	case BPF_MAP_TYPE_LPM_TRIE:
		return trie_map_ops;
	case BPF_MAP_TYPE_HASH_OF_MAPS:
		return htab_of_maps_map_ops;
	case BPF_MAP_TYPE_DEVMAP:
		return dev_map_ops;
	case BPF_MAP_TYPE_SOCKMAP:
		return sock_map_ops;
	case BPF_MAP_TYPE_CPUMAP:
		return cpu_map_ops;
	case BPF_MAP_TYPE_XSKMAP:
		return xsk_map_ops;
	case BPF_MAP_TYPE_SOCKHASH:
		return sock_hash_ops;
	case BPF_MAP_TYPE_CGROUP_STORAGE: 
	case BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE:
		return cgroup_storage_map_ops;
	case BPF_MAP_TYPE_REUSEPORT_SOCKARRAY:
		return reuseport_array_ops;
	case BPF_MAP_TYPE_QUEUE:
		return queue_map_ops;
	case BPF_MAP_TYPE_STACK:
		return stack_map_ops;
	case BPF_MAP_TYPE_SK_STORAGE:
		return sk_storage_map_ops;
	case BPF_MAP_TYPE_DEVMAP_HASH:
		return dev_map_hash_ops;
	case BPF_MAP_TYPE_STRUCT_OPS:
		return bpf_struct_ops_map_ops;
	case BPF_MAP_TYPE_RINGBUF:
		return ringbuf_map_ops;
	case BPF_MAP_TYPE_INODE_STORAGE:
		return inode_storage_map_ops;
	case BPF_MAP_TYPE_TASK_STORAGE:
		return task_storage_map_ops;
	case BPF_MAP_TYPE_BLOOM_FILTER:
		return bloom_filter_map_ops;
	case BPF_MAP_TYPE_USER_RINGBUF:
		return user_ringbuf_map_ops;
	case BPF_MAP_TYPE_CGRP_STORAGE:
		return cgrp_storage_map_ops;
	case BPF_MAP_TYPE_UNSPEC:
	default:
		return default_ops;
	}
}