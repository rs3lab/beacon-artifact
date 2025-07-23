0: R1=ctx() R10=fp0
; asm volatile ("                                       \ @
verifier_spill_fill.c:19
0: (b7) r1 = 1024                     ; R1_w=1024
1: (63) *(u32 *)(r10 -12) = r1        ; R1_w=1024 R10=fp0 fp-16=mmmm????
2: (61) r1 = *(u32 *)(r10 -12)        ;
R1_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
R10=fp0 fp-16=mmmm????
3: (95) exit
R0 !read_ok
processed 4 insns (limit 1000000) max_states_per_insn 0 total_states 0
peak_states 0 mark_read 0
