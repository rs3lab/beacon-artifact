```bash
from 25 to 27: R0=map_value(map=bpf_map,ks=4,vs=8) R6_w=scalar(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=2554,var_off=(0x0; 0xfff)) R8=fp-8 R9=0 R10=fp0 fp-8=mmmmmmmm
27: R0=map_value(map=bpf_map,ks=4,vs=8) R6_w=scalar(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=2554,var_off=(0x0; 0xfff)) R8=fp-8 R9=0 R10=fp0 fp-8=mmmmmmmm
27: (bf) r5 = r10                     ; R5_w=fp0 R10=fp0
28: (0f) r5 += r6
mark_precise: frame0: last_idx 28 first_idx 22 subseq_idx -1 
mark_precise: frame0: regs=r6 stack= before 27: (bf) r5 = r10
mark_precise: frame0: regs=r6 stack= before 25: (a5) if r6 < 0x9fb goto pc+1
mark_precise: frame0: regs=r6 stack= before 23: (25) if r6 > 0x1 goto pc+1
mark_precise: frame0: regs=r6 stack= before 22: (79) r6 = *(u64 *)(r0 +0)
29: R5_w=fp(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=2554,var_off=(0x0; 0xfff)) R6_w=scalar(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=2554,var_off=(0x0; 0xfff))
29: (bf) r7 = r10                     ; R7_w=fp0 R10=fp0
30: (07) r7 += 20                     ; R7=fp20
31: (ad) if r7 < r5 goto pc+2         ; R5=fp(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=2554,var_off=(0x0; 0xfff)) R7=fp20
32: (bf) r9 = r5                      ; R5=fp(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=2554,var_off=(0x0; 0xfff)) R9_w=fp(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=2554,var_off=(0x0; 0xfff))
33: (95) exit

from 31 to 34: R0=map_value(map=bpf_map,ks=4,vs=8) R5=fp(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=2554,var_off=(0x0; 0xfff)) R6=scalar(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=2554,var_off=(0x0; 0xfff)) R7=fp20 R8=fp-8 R9=0 R10=fp0 fp-8=mmmmmmmm
34: R0=map_value(map=bpf_map,ks=4,vs=8) R5=fp(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=2554,var_off=(0x0; 0xfff)) R6=scalar(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=2554,var_off=(0x0; 0xfff)) R7=fp20 R8=fp-8 R9=0 R10=fp0 fp-8=mmmmmmmm
34: (bf) r7 = r5                      ; R5=fp(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=2554,var_off=(0x0; 0xfff)) R7_w=fp(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=2554,var_off=(0x0; 0xfff))
```




from 9 to 11: R0=map_value(map=array_map3,ks=4,vs=8) R9=ctx() R10=fp0 fp-8=mmmmmmmm
11: R0=map_value(map=array_map3,ks=4,vs=8) R9=ctx() R10=fp0 fp-8=mmmmmmmm
11: (61) r6 = *(u32 *)(r0 +0)         ; R0=map_value(map=array_map3,ks=4,vs=8) R6_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
12: (bf) r1 = r10                     ; R1_w=fp0 R10=fp0
13: (0f) r1 += r6
mark_precise: frame0: last_idx 13 first_idx 11 subseq_idx -1 
mark_precise: frame0: regs=r6 stack= before 12: (bf) r1 = r10
mark_precise: frame0: regs=r6 stack= before 11: (61) r6 = *(u32 *)(r0 +0)
14: R1_w=fp(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R6_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
14: (bf) r2 = r10                     ; R2_w=fp0 R10=fp0
15: (07) r2 += -512                   ; R2_w=fp-512
16: (ad) if r1 < r2 goto pc+2         ; R1_w=fp(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R2_w=fp-512
17: (3d) if r1 >= r10 goto pc+1       ; R1_w=fp(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R10=fp0
18: (71) r3 = *(u8 *)(r1 +0)
invalid unbounded variable-offset read from stack R1

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, __u64);
} array_map3 SEC(".maps");

SEC("socket")
int test_spec(void *ctx)
{
        asm volatile (
                "r9 = r1;\n"
                "r1 = %[array_map3] ll;\n"
                "r2 = 0;\n"
                "*(u64 *)(r10 - 8) = r2;\n"
                "r2 = r10;\n"
                "r2 += -8;\n"
                "call %[bpf_map_lookup_elem];\n"
                "if r0 != 0 goto +1;\n"
                "exit;\n"
                "r6 = *(u32*)(r0 + 0);\n"
                "r1 = r10;\n"
                "r1 += r6;\n"
                "r2 = r10;\n"
                "r2 += -512;\n"
                "if r1 < r2 goto +2;\n"
                "if r1 >= r10 goto +1;\n"
                "r3 = *(u8*)(r1-0);\n"
        :
        : __imm_addr(array_map3),
          __imm(bpf_map_lookup_elem),
          __imm(bpf_get_cgroup_classid)
        : __clobber_all);

        return 0;
}

