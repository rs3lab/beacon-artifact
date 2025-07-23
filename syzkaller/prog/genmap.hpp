#pragma once
#include "../include/linux/bpf.h"
#define INT_MAX 0xFFFFFFFu

#define INT_TYPE_ID 1
static __u8 MAPSIZE[] =          {1, 2, 4, 8, 16, 32, 64, 128};
static __u8 TYPE_ID_PER_SIZE[] = {3, 4, 1, 2,  5,  6,  7,   8};
// checks if map value can be directly written to
bool isMapWritable(union bpf_attr *mapAttrs, int mapIdx, int maxMaps);

bpf_map_type getMapType(union bpf_attr *mapAttrs, int mapIdx, int maxMaps);

// not adding flags or NUMA NODE for now, we need idx to not create problem  maps as first one (MAP_IN_MAP problems)
void createOneMap(union bpf_attr *mapAttr, int idx); 