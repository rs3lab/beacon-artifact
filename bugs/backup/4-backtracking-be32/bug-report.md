# A Logic Bug in the Verifier

We found a logic bug in the verifier,
which incorrectly propogate the precision of registers
when meet the `be32` instruction (big endian swap).
The bug is detected by the assertion in the verifier.

## PoC

The simplied PoC in terms of BPF bytecode is shown below.

When calling a subprogram, similar to c program functions,
it saves the arguments in the registers from r1 to r5 and
then jumps to the subprogram offset.

In the subprogram,
it finds an operation `*(u64 *)(r10 -480) = r5`,
which is security critical
and thus annotate the src register `r5` as precise.
The precision label is used in the state pruning,
which only compares the registers and stack slots with precision label
to decides whether two states are the same or not.
Further, it needs to back propagate this precision label to
all other stack slots and registers which affect the value of `r5`
(quite similar to tain-analysis).

However,
in the procedure of back propagation,
it incorrectly propagates the precision label to r0
([see why it is make this mistack here](#root-cause)),
when meeting `r2 = be32 r2`, 
which should only propagate the precision label from `r2` to `r2`,
actually without doing anything since src register is the dst register.

Finally,
since the caller only passed arguments to the subprogram from r1 to r5,
when the back-propagation comes to the `call pc+x` instruction,
the precision should be only in r1 to r5 at most
instead of in other registers.
However, it detects `r0` is annotated as precise
and thus throws an WARNING.

```C
...
// Call a subprogram
call pc+x
...
r2 = be32 r2
r5 = r2
...
*(u64 *)(r10 -480) = r5
// !!! Trigger back track/propogate
// Set r5 as precise (precise == security critical registers/stack slots)
// Back propogate the precision label to registers or stack,
// which affects r5.
       ...
       // Propagate the precision to r2
       r5 = r2
       // !!! ROOT CAUSE
       // r2 has already be labelled as precise
       // Incorrectly propage the precision to register r0
       r2 = be32 r2
       // !!! ASSERTION
       // As the the caller only passed arguments in r1-r5,
       // The precise should only be possible on r1-r5,
       // Otherwise, the assertion is raised.
       call pc+x
```

## Root Cause

The root cause is that
eBPF instruction set utilize one bit `bpf_insn.code.src` of the instruction
for two different meanings.
```c
struct bpf_insn {
    __u8    code;
    /* code =  opcode     : 4 bits
               src        : 1 bit
               insn class : 3 bits            
     */
    __u8    dst_reg:4;  /* dest register */
    __u8    src_reg:4;  /* source register */
    __s16   off;        /* signed offset */
    __s32   imm;        /* signed immediate constant */
};

```


- Meaning-1: Whether the insn utilize a src_reg or imm?

       - bpf_insn.code.src == BPF_X (0x8), utilize src_reg
       - bpf_insn.code.src == BPF_K (0x0), utilize imm

- Meaning-2: Whether the swap insn is to do little endian or big endian swap.

       - bpf_insn.code.src == BPF_TO_BE (0x8), converting to big endian
       - bpf_insn.code.src == BPF_TO_LE (0x0), converting to little endian


During the back propagation,
it decies to propagate precision to the src_reg
once it uses a src_reg in the instruction.
The buggy verifier uses this condition
`if bpf_insn.code.src == BPF_X(0x08)`.

However, it is wrong
when executing a big endian swap instruction,
which doesn't have src_reg but with `bpf_nsn.code.src == BPF_TO_BE(0x08)`.
Subsequently, the verifier would incorrectly decides it uses `src_reg`
and thus annotate `src_reg`, which is zero and acting as `r0`,
as precise.

## Patch

To patch this bug, we only need to
add one more condition `BPF_OP(insn->code) != BPF_END)`,
which excludes the swap instruction.

```diff
---
 kernel/bpf/verifier.c                         |  8 ++++++-
 .../selftests/bpf/verifier/byte_swap.c        | 24 +++++++++++++++++++
 2 files changed, 31 insertions(+), 1 deletion(-)
 create mode 100644 tools/testing/selftests/bpf/verifier/byte_swap.c

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index eed7350e15f4..60db8d68d123 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -3529,7 +3529,13 @@ static int backtrack_insn(struct bpf_verifier_env *env, int idx, int subseq_idx,
 				bt_clear_reg(bt, dreg);
 			}
 		} else {
-			if (BPF_SRC(insn->code) == BPF_X) {
+			/* Swap instructions (BPF_TO_BE) and BPF_X both
+			   use value 0x08 in the field of BPF_SRC.
+			   Thus, we have to check both the BPF_SRC and BPF_OP
+			   to decide whether the insn uses the src_reg and then
+			   propagate the precision to the src_reg.
+			*/
+			if (BPF_SRC(insn->code) == BPF_X && BPF_OP(insn->code) != BPF_END) {
 				/* dreg += sreg
 				 * both dreg and sreg need precision
 				 * before this insn
diff --git a/tools/testing/selftests/bpf/verifier/byte_swap.c b/tools/testing/selftests/bpf/verifier/byte_swap.c
new file mode 100644
index 000000000000..96338a0ec748
--- /dev/null
+++ b/tools/testing/selftests/bpf/verifier/byte_swap.c
@@ -0,0 +1,24 @@
+{
+    "byte_swap: precision marking test",
+    .insns = {
+    BPF_MOV64_IMM(BPF_REG_2, 1),
+    BPF_MOV64_IMM(BPF_REG_3, 2),
+    BPF_CALL_REL(1),
+    BPF_EXIT_INSN(),
+    BPF_ALU64_IMM(BPF_NEG, BPF_REG_2, BPF_REG_0),
+    BPF_ENDIAN(BPF_X, BPF_REG_2, 32),
+    BPF_MOV64_REG(BPF_REG_4, BPF_REG_2),
+    BPF_ALU64_IMM(BPF_NEG, BPF_REG_4, BPF_REG_0),
+    BPF_ALU64_IMM(BPF_LSH, BPF_REG_4, 34),
+    BPF_ALU64_IMM(BPF_NEG, BPF_REG_2, BPF_REG_0),
+    BPF_MOV32_REG(BPF_REG_5, BPF_REG_4),
+    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -448),
+    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, -456),
+    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_3, -464),
+    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_4, -472),
+    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_5, -480),
+    BPF_MOV64_IMM(BPF_REG_0, 0),
+    BPF_EXIT_INSN(),
+    },
+    .result = ACCEPT,
+},
-- 
2.25.1
```
