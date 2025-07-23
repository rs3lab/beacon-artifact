```bash
0: R1=ctx() R10=fp0
; asm volatile( @ repro.bpf.c:31
0: (bf) r8 = r1                       ; R1=ctx() R8_w=ctx()
1: (18) r1 = 0xff163a1e47d4a000       ; R1_w=map_ptr(map=bpf_map,ks=4,vs=8)
3: (b7) r9 = 0                        ; R9_w=0
4: (bf) r2 = r10                      ; R2_w=fp0 R10=fp0
5: (07) r2 += -4                      ; R2_w=fp-4
6: (85) call bpf_map_lookup_elem#1    ; R0_w=map_value_or_null(id=1,map=bpf_map,ks=4,vs=8)
7: (55) if r0 != 0x0 goto pc+1        ; R0_w=0
8: (95) exit

from 7 to 9: R0=map_value(map=bpf_map,ks=4,vs=8) R8=ctx() R9=0 R10=fp0 fp-8=mmmm????
9: R0=map_value(map=bpf_map,ks=4,vs=8) R8=ctx() R9=0 R10=fp0 fp-8=mmmm????
9: (b7) r6 = 1                        ; R6_w=1
10: (61) r5 = *(u32 *)(r8 +16)        ; R5_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R8=ctx()
11: (2f) r6 *= r5                     ; R5_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R6_w=scalar()
12: (25) if r6 > 0x2 goto pc+1        ; R6_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=2,var_off=(0x0; 0x3))
13: (95) exit

from 12 to 14: R0=map_value(map=bpf_map,ks=4,vs=8) R5_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R6_w=scalar(umin=3) R8=ctx() R9=0 R10=fp0 fp-8=mmmm????
14: R0=map_value(map=bpf_map,ks=4,vs=8) R5_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R6_w=scalar(umin=3) R8=ctx() R9=0 R10=fp0 fp-8=mmmm????
14: (7b) *(u64 *)(r0 +0) = r10        ; R0=map_value(map=bpf_map,ks=4,vs=8) R10=fp0
15: (b7) r4 = 0                       ; R4_w=0
16: (7b) *(u64 *)(r0 +0) = r4         ; R0=map_value(map=bpf_map,ks=4,vs=8) R4_w=0
17: (79) r5 = *(u64 *)(r0 +0)         ; R0=map_value(map=bpf_map,ks=4,vs=8) R5_w=scalar()
18: (18) r7 = 0x0                     ; R7_w=0
20: (4f) r5 |= r7                     ; R5_w=scalar() R7_w=0
21: (bf) r8 = r5                      ; R5_w=scalar(id=2) R8_w=scalar(id=2)
; return 0; @ repro.bpf.c:63
22: (b7) r0 = 0                       ; R0_w=0
23: (95) exit
processed 22 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 1
```

```bash
0: R1=ctx() R10=fp0
; asm volatile( @ repro.bpf.c:31
0: (bf) r8 = r1                       ; R1=ctx() R8_w=ctx()
1: (18) r1 = 0xff163a1e47cd4000       ; R1_w=map_ptr(map=bpf_map,ks=4,vs=8)
3: (b7) r9 = 0                        ; R9_w=0
4: (bf) r2 = r10                      ; R2_w=fp0 R10=fp0
5: (07) r2 += -4                      ; R2_w=fp-4
6: (85) call bpf_map_lookup_elem#1    ; R0_w=map_value_or_null(id=1,map=bpf_map,ks=4,vs=8)
7: (55) if r0 != 0x0 goto pc+1        ; R0_w=0
8: (95) exit

from 7 to 9: R0=map_value(map=bpf_map,ks=4,vs=8) R8=ctx() R9=0 R10=fp0 fp-8=mmmm????
9: R0=map_value(map=bpf_map,ks=4,vs=8) R8=ctx() R9=0 R10=fp0 fp-8=mmmm????
9: (61) r5 = *(u32 *)(r8 +16)         ; R5_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R8=ctx()
10: (bf) r6 = r5                      ; R5_w=scalar(id=2,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R6_w=scalar(id=2,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
11: (25) if r6 > 0x2 goto pc+1        ; R6_w=scalar(id=2,smin=smin32=0,smax=umax=smax32=umax32=2,var_off=(0x0; 0x3))
12: (95) exit

from 11 to 13: R0=map_value(map=bpf_map,ks=4,vs=8) R5_w=scalar(id=2,smin=umin=umin32=3,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R6_w=scalar(id=2,smin=umin=umin32=3,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R8=ctx() R9=0 R10=fp0 fp-8=mmmm????
13: R0=map_value(map=bpf_map,ks=4,vs=8) R5_w=scalar(id=2,smin=umin=umin32=3,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R6_w=scalar(id=2,smin=umin=umin32=3,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R8=ctx() R9=0 R10=fp0 fp-8=mmmm????
13: (7b) *(u64 *)(r0 +0) = r10        ; R0=map_value(map=bpf_map,ks=4,vs=8) R10=fp0
14: (b7) r4 = 0                       ; R4_w=0
15: (7b) *(u64 *)(r0 +0) = r4         ; R0=map_value(map=bpf_map,ks=4,vs=8) R4_w=0
16: (79) r5 = *(u64 *)(r0 +0)         ; R0=map_value(map=bpf_map,ks=4,vs=8) R5_w=scalar()
17: (18) r7 = 0x0                     ; R7_w=0
19: (4f) r5 |= r7                     ; R5_w=scalar() R7_w=0
20: (bf) r8 = r5                      ; R5_w=scalar(id=3) R8_w=scalar(id=3)
; return 0; @ repro.bpf.c:62
21: (b7) r0 = 0                       ; R0_w=0
22: (95) exit
processed 21 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 1
```