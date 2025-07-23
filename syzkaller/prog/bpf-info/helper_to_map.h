#include "helper_proto.h"
#include "../genmap.hpp"

#define HELPER_TO_MAP_SIZE 37
const static struct {
	proto_addr func_name;
	bpf_map_type mapTypes[MAX_TYPE_SIZE];
} helper_to_map[HELPER_TO_MAP_SIZE]
{
	{
	    bpf_tail_call,
	    {BPF_MAP_TYPE_PROG_ARRAY},
	},
	    {
		bpf_perf_event_read,
		{BPF_MAP_TYPE_PERF_EVENT_ARRAY},
	    },
	    {
		bpf_perf_event_output,
		{BPF_MAP_TYPE_PERF_EVENT_ARRAY},
	    },
	    {
		bpf_skb_output,
		{BPF_MAP_TYPE_PERF_EVENT_ARRAY},
	    },
	    {
		bpf_perf_event_read_value,
		{BPF_MAP_TYPE_PERF_EVENT_ARRAY},
	    },
	    {
		bpf_xdp_output,
		{BPF_MAP_TYPE_PERF_EVENT_ARRAY},
	    },
	    {
		bpf_ringbuf_output,
		{BPF_MAP_TYPE_RINGBUF},
	    },
	    {
		bpf_ringbuf_reserve,
		{BPF_MAP_TYPE_RINGBUF},
	    },
	    {
		bpf_ringbuf_query,
		{BPF_MAP_TYPE_RINGBUF},
	    },
	    {
		bpf_ringbuf_reserve_dynptr,
		{BPF_MAP_TYPE_RINGBUF},
	    },
	    {
		bpf_ringbuf_submit_dynptr,
		{BPF_MAP_TYPE_RINGBUF},
	    },
	    {
		bpf_ringbuf_discard_dynptr,
		{BPF_MAP_TYPE_RINGBUF},
	    },
	    {
		bpf_user_ringbuf_drain,
		{BPF_MAP_TYPE_USER_RINGBUF},
	    },
	    {
		bpf_get_stackid,
		{BPF_MAP_TYPE_STACK_TRACE},
	    },
	    {
		bpf_skb_under_cgroup,
		{BPF_MAP_TYPE_CGROUP_ARRAY},
	    },
	    {
		bpf_current_task_under_cgroup,
		{BPF_MAP_TYPE_CGROUP_ARRAY},
	    },
	    {
		bpf_get_local_storage,
		{BPF_MAP_TYPE_CGROUP_STORAGE, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE},
	    },
	    {
		bpf_redirect_map,
		{BPF_MAP_TYPE_CGROUP_STORAGE, BPF_MAP_TYPE_DEVMAP, BPF_MAP_TYPE_CPUMAP, BPF_MAP_TYPE_XSKMAP},
	    },
	    {
		bpf_map_lookup_elem_func,
		//{BPF_MAP_TYPE_DEVMAP_HASH_DEV, BPF_MAP_TYPE_DEVMAP_DEV, BPF_MAP_TYPE_XSKMAP_DEV, BPF_MAP_TYPE_ARRAY_OF_MAPS_DEV, BPF_MAP_TYPE_HASH_OF_MAPS_DEV}
		{BPF_MAP_TYPE_DEVMAP_HASH, BPF_MAP_TYPE_DEVMAP, BPF_MAP_TYPE_XSKMAP, BPF_MAP_TYPE_ARRAY_OF_MAPS, BPF_MAP_TYPE_HASH_OF_MAPS, BPF_MAP_TYPE_SOCKMAP, BPF_MAP_TYPE_SOCKHASH},
	    },
	    {
		bpf_sk_select_reuseport,
		{BPF_MAP_TYPE_SOCKHASH, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY, BPF_MAP_TYPE_SOCKMAP},
	    },
	    {
		bpf_msg_redirect_map,
		{BPF_MAP_TYPE_SOCKMAP},
	    },
	    {
		bpf_map_delete_elem_func,
		{BPF_MAP_TYPE_SOCKMAP, BPF_MAP_TYPE_SOCKHASH},
	    },
	    {
		bpf_sock_map_update,
		{BPF_MAP_TYPE_SOCKMAP},
	    },
	    {
		bpf_sk_redirect_map,
		{BPF_MAP_TYPE_SOCKMAP},
	    },
	    {
		bpf_sk_redirect_hash,
		{BPF_MAP_TYPE_SOCKHASH},
	    },
	    {
		bpf_sock_hash_update,
		{BPF_MAP_TYPE_SOCKHASH},
	    },
	    {
		bpf_msg_redirect_hash,
		{BPF_MAP_TYPE_SOCKHASH},
	    },
	    {
		bpf_map_peek_elem,
		{BPF_MAP_TYPE_BLOOM_FILTER, BPF_MAP_TYPE_QUEUE, BPF_MAP_TYPE_STACK},
	    },
	    {
		bpf_sk_storage_get,
		{BPF_MAP_TYPE_SK_STORAGE},
	    },
	    {
		bpf_sk_storage_delete,
		{BPF_MAP_TYPE_SK_STORAGE},
	    },
	    {
		bpf_kptr_xchg,
		{BPF_MAP_TYPE_SK_STORAGE, BPF_MAP_TYPE_INODE_STORAGE, BPF_MAP_TYPE_TASK_STORAGE, BPF_MAP_TYPE_CGRP_STORAGE},
	    },
	    {
		bpf_inode_storage_get,
		{BPF_MAP_TYPE_INODE_STORAGE},
	    },
	    {
		bpf_inode_storage_delete,
		{BPF_MAP_TYPE_INODE_STORAGE},
	    },
	    {
		bpf_task_storage_get,
		{BPF_MAP_TYPE_TASK_STORAGE},
	    },
	    {
		bpf_task_storage_delete,
		{BPF_MAP_TYPE_TASK_STORAGE},
	    },
	    {
		bpf_cgrp_storage_get,
		{BPF_MAP_TYPE_CGRP_STORAGE},
	    },
	    {
		bpf_cgrp_storage_delete,
		{
		    BPF_MAP_TYPE_CGRP_STORAGE,
		},
	    },
};

bool doesHelperAllowMapType(proto_addr helper,bpf_map_type target_type){
	if (helper == unspec) {
		return false;
	}
	for (int i = 0; i < HELPER_TO_MAP_SIZE; i++)
	{
		if(helper_to_map[i].func_name == helper){
			for (int j = 0; j < MAX_TYPE_SIZE; j++)
			{
				bpf_map_type type = helper_to_map[i].mapTypes[j];
				if(type == BPF_MAP_TYPE_UNSPEC){
					return false;
				}else if (type == target_type)
				{
					return true;
				}
			}
			return false;
		}
		
	}
	return false;
	

}
