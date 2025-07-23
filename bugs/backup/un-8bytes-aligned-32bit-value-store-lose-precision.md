If a 32-bit integer is placed on the stack at the non-8-byte-algined location, like fp-12 (fp is the base of the stack pointer), 
after initilizing it as 1, when loading it from the stack, the 32-bit integer will become as unknown 32-bit value, and then when accessing the memory with the integer as index, it will fail, although the access is valid.


```c
SEC("tp/syscalls/sys_enter_write")
int test_prog(void *ctx)
{
        unsigned int num = 1;
        char arr[10];
        arr[num] = 1;
        return 0;
}
```

```
// eBPF verification code
0: R1=ctx() R10=fp0
0: (7b) *(u64 *)(r10 -8) = r1         ; R1=ctx() R10=fp0 fp-8_w=ctx()
1: (b7) r1 = 1                        ; R1_w=1
2: (63) *(u32 *)(r10 -12) = r1        ; R1_w=1 R10=fp0 fp-16=mmmm????
3: (61) r3 = *(u32 *)(r10 -12)        ; R3_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R10=fp0 fp-16=mmmm????
4: (bf) r2 = r10                      ; R2_w=fp0 R10=fp0
5: (07) r2 += -22                     ; R2_w=fp-22
6: (0f) r2 += r3
mark_precise: frame0: last_idx 6 first_idx 0 subseq_idx -1 
mark_precise: frame0: regs=r3 stack= before 5: (07) r2 += -22
mark_precise: frame0: regs=r3 stack= before 4: (bf) r2 = r10
mark_precise: frame0: regs=r3 stack= before 3: (61) r3 = *(u32 *)(r10 -12)
7: R2_w=fp(off=-22,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R3_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
7: (73) *(u8 *)(r2 +0) = r1
invalid unbounded variable-offset write to stack R2
processed 8 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0

Failed to load and verify BPF skeleton
```

A real case:

```c
	char mem[12];
	u32 x;
	u32 gap;
	u32 y;

	...
	if (x >= 0 && x < 8) {
		// x will be spilled to the stack
		// and it would less the range
		// if it is spilled at a non-8-byte-aligned slots
		if (y >= 0 && y < 8) {
			// when fill from stack, the bound info has lost.
			// so failed
			mem[x] = 0; // 
		}
	}
```


----------------


```
SEC("tp/syscalls/sys_enter_write")
int test_prog(void *ctx)
{
        unsigned int num = 1;
        unsigned int *ptr= & num;
        char arr[10];
        arr[*ptr] = 1;
        return 0;
}

```

```bash
// Linux kernel verification log
0: R1=ctx() R10=fp0
0: (7b) *(u64 *)(r10 -8) = r1         ; R1=ctx() R10=fp0 fp-8_w=ctx()
1: (b7) r1 = 1                        ; R1_w=1
2: (63) *(u32 *)(r10 -12) = r1        ; R1_w=1 R10=fp0 fp-16=mmmm????
3: (bf) r2 = r10                      ; R2_w=fp0 R10=fp0
4: (07) r2 += -12                     ; R2_w=fp-12
5: (7b) *(u64 *)(r10 -24) = r2        ; R2_w=fp-12 R10=fp0 fp-24_w=fp-12
6: (79) r2 = *(u64 *)(r10 -24)        ; R2_w=fp-12 R10=fp0 fp-24_w=fp-12
7: (61) r3 = *(u32 *)(r2 +0)          ; R2_w=fp-12 R3_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) fp-16=mmmm????
8: (bf) r2 = r10                      ; R2_w=fp0 R10=fp0
9: (07) r2 += -34                     ; R2_w=fp-34
10: (0f) r2 += r3
mark_precise: frame0: last_idx 10 first_idx 0 subseq_idx -1 
mark_precise: frame0: regs=r3 stack= before 9: (07) r2 += -34
mark_precise: frame0: regs=r3 stack= before 8: (bf) r2 = r10
mark_precise: frame0: regs=r3 stack= before 7: (61) r3 = *(u32 *)(r2 +0)
11: R2_w=fp(off=-34,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R3_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
11: (73) *(u8 *)(r2 +0) = r1
invalid unbounded variable-offset write to stack R2
processed 12 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```

--------------


another example, which mis-decide a bounded loop as infinite loop:

func#0 @0
0: R1=ctx() R10=fp0
0: (7b) *(u64 *)(r10 -8) = r1         ; R1=ctx() R10=fp0 fp-8_w=ctx()
1: (b7) r1 = 0                        ; R1_w=0
2: (63) *(u32 *)(r10 -24) = r1        ; R1_w=0 R10=fp0 fp-24=????0
3: (63) *(u32 *)(r10 -28) = r1
mark_precise: frame0: last_idx 3 first_idx 0 subseq_idx -1 
mark_precise: frame0: regs=r1 stack= before 2: (63) *(u32 *)(r10 -24) = r1
mark_precise: frame0: regs=r1 stack= before 1: (b7) r1 = 0
4: R1_w=0 R10=fp0 fp-32=0000????
4: (05) goto pc+0
5: (61) r1 = *(u32 *)(r10 -28)        ; R1_w=0 R10=fp0 fp-32=0000????
6: (25) if r1 > 0x9 goto pc+6
mark_precise: frame0: last_idx 6 first_idx 0 subseq_idx -1 
mark_precise: frame0: regs=r1 stack= before 5: (61) r1 = *(u32 *)(r10 -28)
6: R1_w=0
7: (05) goto pc+0
8: (05) goto pc+0
9: (61) r1 = *(u32 *)(r10 -28)        ; R1_w=0 R10=fp0 fp-32=0000????
10: (07) r1 += 1                      ; R1_w=1
11: (63) *(u32 *)(r10 -28) = r1       ; R1_w=1 R10=fp0 fp-32=mmmm????
12: (05) goto pc-8
5: (61) r1 = *(u32 *)(r10 -28)        ; R1_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R10=fp0 fp-32=mmmm????
6: (25) if r1 > 0x9 goto pc+6         ; R1_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=9,var_off=(0x0; 0xf))
7: (05) goto pc+0
8: (05) goto pc+0
9: (61) r1 = *(u32 *)(r10 -28)        ; R1_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R10=fp0 fp-32=mmmm????
10: (07) r1 += 1                      ; R1_w=scalar(smin=umin=1,smax=umax=0x100000000,var_off=(0x0; 0x1ffffffff))
11: (63) *(u32 *)(r10 -28) = r1       ; R1_w=scalar(smin=umin=1,smax=umax=0x100000000,var_off=(0x0; 0x1ffffffff)) R10=fp0 fp-32=mmmm????
12: (05) goto pc-8
5: (61) r1 = *(u32 *)(r10 -28)        ; R1_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R10=fp0 fp-32=mmmm????
6: (25) if r1 > 0x9 goto pc+6         ; R1_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=9,var_off=(0x0; 0xf))
7: (05) goto pc+0
8: (05) goto pc+0
infinite loop detected at insn 9
cur state: R1_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=9,var_off=(0x0; 0xf)) R10=fp0 fp-8=ctx() fp-24=????0 fp-32=mmmm????
old state: R1_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=9,var_off=(0x0; 0xf)) R10=fp0 fp-8=ctx() fp-24=????0 fp-32_r=mmmm????
processed 26 insns (limit 1000000) max_states_per_insn 1 total_states 2 peak_states 2 mark_read 1

Failed to load and verify BPF skeleton

SEC("tp/syscalls/sys_enter_write")
int test_prog(void *ctx)
{

        char arr[9];
        unsigned int i = 0;
        for(unsigned int j = 0; j < 10; j++) {
                // arr[i] = 1;
                // bpf_printk("1");
        }

        return 0;
}
