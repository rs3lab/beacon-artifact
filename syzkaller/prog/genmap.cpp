#include "genmap.hpp"
#include "bpf-info/map_op.h"
#include "genrand.hpp"
#include <stdio.h>
void createOneMap(union bpf_attr *mapAttr, int idx) {
    // Skipping BPF_MAP_TYPE_UNSPEC
    // bpf_map_type
    mapAttr->map_type = (rand() % (__MAX_BPF_MAP_TYPE - 1)) + 1;

    // We use the fd of the first map to fill in inner_fd for maps in maps, and we need map_meta_equal to be defined for this 
    // see map_in_map.c function bpf_map_meta_alloc 
    while(idx == 0 && !getMapOp((bpf_map_type)mapAttr->map_type).map_meta_equal){
            mapAttr->map_type = (rand() % (__MAX_BPF_MAP_TYPE - 1)) + 1;
        }
    mapAttr->map_flags = 0;
    int value_idx;
    // Good place to start for writing these is to check func map_alloc_check and map_alloc in the bpf_map_ops for the type
    // These mappings are defined in linux/bpf_types.h 
    switch (mapAttr->map_type) {
        case BPF_MAP_TYPE_LRU_HASH: 
        case BPF_MAP_TYPE_LRU_PERCPU_HASH: 
            if (rand() %2) {
                mapAttr->map_flags |= BPF_F_NO_COMMON_LRU;
            }
        
        case BPF_MAP_TYPE_HASH:
        case BPF_MAP_TYPE_PERCPU_HASH:
            // https://docs.kernel.org/bpf/map_hash.html
            // only key?
            mapAttr->key_size = 4; // ??? this coulds be changed?
            mapAttr->value_size = MAPSIZE[rand() % (sizeof(MAPSIZE))];
            mapAttr->max_entries = randRange(1, INT_MAX >> 12);
            // htab_map_alloc_check: lru && !prealloc => -ENOTSUPP
            if(mapAttr->map_type != BPF_MAP_TYPE_LRU_HASH && mapAttr->map_type != BPF_MAP_TYPE_LRU_PERCPU_HASH){
                mapAttr->map_flags |= BPF_F_NO_PREALLOC; 
            }
            break;

        case BPF_MAP_TYPE_DEVMAP:
        case BPF_MAP_TYPE_DEVMAP_HASH: 
            // https://docs.kernel.org/bpf/map_devmap.html
            mapAttr->key_size = 4;
            mapAttr->value_size = MAPSIZE[randRange(2, 3)];
            mapAttr->max_entries = randRange(1, INT_MAX >> 12);
            break;

        case BPF_MAP_TYPE_STRUCT_OPS:
            // https://patchwork.ozlabs.org/project/netdev/patch/20191231062050.281712-1-kafai@fb.com/
            /*
            attr->btf_vmlinux_value_type_id set to the btf id "struct bpf_struct_ops_tcp_congestion_ops" 
            of the running kernel.
            */
            // For now fallback to BPF_MAP_TYPE_ARRAY
            mapAttr->map_type = BPF_MAP_TYPE_ARRAY;
            
        case BPF_MAP_TYPE_ARRAY:
        case BPF_MAP_TYPE_PERCPU_ARRAY:
            // fprintf(stderr, "map_array\n");
            mapAttr->key_size = 4; // necessary for ALL ARRAY types
            mapAttr->value_size = MAPSIZE[rand() % (sizeof(MAPSIZE))];
            //always allocated so don't want to run out of memory
	        mapAttr->max_entries = randRange(1, INT_MAX >> 20+7);   // To avoid overflow and 0 
            break;

        case BPF_MAP_TYPE_XSKMAP: 
            mapAttr->key_size = 4; // necessary 
            mapAttr->value_size = 4; // necessary for all I think (are fd's)
            // either add no prealloc flag or something
            mapAttr->max_entries = randRange(1, 245);   // To avoid overflow and 0
            break;
            
        case BPF_MAP_TYPE_HASH_OF_MAPS: // this could be changed for arbitrary key size
        case BPF_MAP_TYPE_ARRAY_OF_MAPS:
        case BPF_MAP_TYPE_PROG_ARRAY:
        // https://man7.org/linux/man-pages/man2/bpf.2.html
        case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
        case BPF_MAP_TYPE_CGROUP_ARRAY:
            // https://blogs.oracle.com/linux/post/bpf-in-depth-communicating-with-userspace
            // https://docs.kernel.org/bpf/map_xskmap.html
            mapAttr->key_size = 4; // necessary 
            mapAttr->value_size = 4; // necessary for all I think (are fd's)
            // either add no prealloc flag or something
            mapAttr->max_entries = randRange(1, 245);   // To avoid overflow and 0
            break;

        case BPF_MAP_TYPE_STACK_TRACE:
            mapAttr->key_size = 4;
            mapAttr->value_size = 8; // could be multiple 
            mapAttr->max_entries = randRange(1, INT_MAX >> 15);   // To avoid overflow and 0
            //mapAttr->map_flags |= BPF_F_NO_PREALLOC; EINVAL
	        break;

        case BPF_MAP_TYPE_LPM_TRIE:
            mapAttr->map_flags |= BPF_F_NO_PREALLOC;
            mapAttr->max_entries = randRange(1, INT_MAX);
            mapAttr->key_size = MAPSIZE[randRange(5, sizeof(MAPSIZE))];
            mapAttr->value_size = MAPSIZE[rand() % (sizeof(MAPSIZE))];
            break;

        case BPF_MAP_TYPE_SOCKMAP:
            // https://docs.kernel.org/bpf/map_sockmap.html
            mapAttr->key_size = 4;
            mapAttr->value_size = MAPSIZE[randRange(2, 3)];
            mapAttr->max_entries = randRange(1, INT_MAX >> 20 + 3);   // To avoid overflow and 0
            break;
        case BPF_MAP_TYPE_SOCKHASH:
            // https://docs.kernel.org/bpf/map_sockmap.html
            mapAttr->key_size = MAPSIZE[rand() % (sizeof(MAPSIZE))];
            mapAttr->value_size = MAPSIZE[randRange(2, 3)];
            mapAttr->max_entries = randRange(1, INT_MAX >> 20);   // To avoid overflow and 0
            mapAttr->flags |= BPF_F_NO_PREALLOC;
            break;

        case BPF_MAP_TYPE_CPUMAP:
            // https://docs.kernel.org/bpf/map_cpumap.html
            mapAttr->key_size = 4;
            mapAttr->value_size = MAPSIZE[randRange(2, 3)];
            mapAttr->max_entries = 1;
            break;

        case BPF_MAP_TYPE_CGROUP_STORAGE:
        case BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE:
            mapAttr->key_size = 8; // can also be 12?
            mapAttr->value_size = 4; // not 100% sure MAPSIZE[randRange(0, 1)];
            mapAttr->max_entries = 0; // not sure about this
            break;

            
        case BPF_MAP_TYPE_REUSEPORT_SOCKARRAY:
            // https://patchwork.ozlabs.org/project/netdev/patch/20180808080124.3013877-1-kafai@fb.com/
            mapAttr->key_size = 4;
            mapAttr->value_size = MAPSIZE[randRange(2, 3)];
            mapAttr->max_entries = randRange(1, INT_MAX >> 20 + 3 );   // To avoid overflow and 0
            break;

        case BPF_MAP_TYPE_QUEUE:
        case BPF_MAP_TYPE_STACK:
            // https://docs.kernel.org/bpf/map_queue_stack.html 
            mapAttr->key_size = 0;
            mapAttr->value_size = 4; //MAPSIZE[rand() % (sizeof(MAPSIZE))];
            mapAttr->max_entries = randRange(1, INT_MAX >> 20);
            break;

        case BPF_MAP_TYPE_RINGBUF:
        case BPF_MAP_TYPE_USER_RINGBUF:
            // https://www.kernel.org/doc/html/next/bpf/ringbuf.html
            mapAttr->key_size = 0;
            mapAttr->value_size = 0;
            // See ringbuf_map_alloc where we need to pass !PAGE_ALIGNED(attr->max_entries)
            mapAttr->max_entries = MAPSIZE[rand() % (sizeof(MAPSIZE))]<<12; 
            break;

        case BPF_MAP_TYPE_BLOOM_FILTER:
            // https://docs.kernel.org/bpf/map_bloom_filter.html
            mapAttr->key_size = 0;
            mapAttr->value_size = MAPSIZE[rand() % (sizeof(MAPSIZE))];
            mapAttr->max_entries = randRange(1, INT_MAX >> 20);
            break; 
        case BPF_MAP_TYPE_TASK_STORAGE: 
            //https://man.archlinux.org/man/core/man-pages/bpf-helpers.7.en
        case BPF_MAP_TYPE_INODE_STORAGE: 
            // https://lore.kernel.org/bpf/Y+KXjKK+ncbket1C@maniforge.lan/T/
        case BPF_MAP_TYPE_SK_STORAGE:
        case BPF_MAP_TYPE_CGRP_STORAGE:
            // https://docs.kernel.org/bpf/map_sk_storage.html
            // https://docs.kernel.org/bpf/map_cgrp_storage.html
            mapAttr->key_size = 4; // sizeof(int)
            value_idx = rand() % (sizeof(MAPSIZE));
            mapAttr->value_size = MAPSIZE[value_idx];
            mapAttr->max_entries = 0;
            mapAttr->map_flags |= BPF_F_NO_PREALLOC;
            mapAttr->btf_key_type_id = INT_TYPE_ID;
            mapAttr->btf_value_type_id = TYPE_ID_PER_SIZE[value_idx];
            break;

        default:
            fprintf(stderr, "Not handled: bpf_map_type_dev %d\n", mapAttr->map_type);
            break;
        }
        fprintf(stderr, "Created map with type %d flags %llu key_size %d value_size %d max_entries %d key_type_id %d value_type_id %d\n",
         mapAttr->map_type, mapAttr->flags, mapAttr->key_size, mapAttr->value_size, mapAttr->max_entries, mapAttr->btf_key_type_id, mapAttr->btf_value_type_id);
    };

bool isMapWritable(union bpf_attr * mapAttrs, int mapIdx, int maxMaps){
    if (mapIdx >= maxMaps) {
        fprintf(stderr,"isMapWritable obtained some very wrong values mapIdx %d while maxMaps %d\n", mapIdx, maxMaps);
        return false;
    }
    bpf_map_type type = getMapType(mapAttrs, mapIdx, maxMaps);
    return getMapOp(type).map_direct_value_addr;
}

bpf_map_type getMapType(union bpf_attr * mapAttrs, int mapIdx, int maxMaps){
    if (mapIdx >= maxMaps) {
        fprintf(stderr,"getMapType obtained some very wrong values mapIdx %d while maxMaps %d\n", mapIdx, maxMaps);
        return BPF_MAP_TYPE_UNSPEC;
    }
    return (bpf_map_type) ((mapAttrs + mapIdx)->map_type);
}