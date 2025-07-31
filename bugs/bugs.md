| RC | # | Instruction | Status | link | Description and Consequence|
|----|---|-------------|--------|------|----------------------------|
|RC4 | 1 | `mov`       | Fixed  | [CVE-2023-52920](https://nvd.nist.gov/vuln/detail/CVE-2023-52920), [report](https://lore.kernel.org/bpf/20231020155842.130257-1-tao.lyu@epfl.ch/), [patch](https://github.com/torvalds/linux/commit/41f6f64e6999)   | Fails to track non-r10 precision on stack, leading to privilege escalation. |
|RC3 | 2 | `kfunc call`| Fixed  | [report](https://lore.kernel.org/bpf/20241106201849.2269411-1-tao.lyu@epfl.ch/), [patch](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf.git/commit/?id=12659d28615d)   | Miss argument type checks, leading to DoS.|
|RC4 | 3 | `store`     | Fixed  | [report](https://lore.kernel.org/bpf/20241127185135.2753982-2-memxor@gmail.com/), [patch](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf.git/commit/?id=69772f509e08)   | Incorrectly mark stack slot type, leading to ASLR bypass.|
|RC3 | 4 | `atomic*`   | Fixed  | [report](https://lore.kernel.org/bpf/CAEf4BzaqOt8DyB781geXYfrosmgQCkzDOCOH8WBVmCAPs+wQBw@mail.gmail.com/), [patch](https://github.com/torvalds/linux/commit/41f6f64e6999)   | Miss propogating precisions to stack slots used in atomic instructions.|
|RC3| 5  | `atomic_xchg`| Acked | [report](https://lore.kernel.org/bpf/20231020172941.155388-1-tao.lyu@epfl.ch/)   | Verifier misidentifies scalar type, failing stack pointer validation.|
|RC1 | 6 | `store`     | Acked  | [report](https://lore.kernel.org/bpf/CAP01T768+4FkNC=nw6qnUP3NqQ3+0G_O+LLbMnyWQpkW100RNg@mail.gmail.com/)   | Not propagate scalar range from registers to stack.|
|RC3 | 7 | `be32`      | Fixed  | [report](https://lore.kernel.org/bpf/20231030132145.20867-2-shung-hsi.yu@suse.com/), [patch](https://github.com/torvalds/linux/commit/291d044fd51f8484066300ee42afecf8c8db7b3a)   | Incorrect precision back-propagation. |
|RC3 | 8 | `store`     | Fixed  | [report](https://lore.kernel.org/bpf/20240403202409.2615469-1-tao.lyu@epfl.ch/), [patch](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf.git/commit/?id=b0e66977dc07)   | Mis-reject a 32-bit store to ovewrite a spilled 64-bit scalar on the stack.|
|RC2 | 9 | `atomic*`   | Acked  | [Acked in history commit](https://github.com/torvalds/linux/commit/ca36960211eb228bcbc7aaebfa0d027368a94c60)   | Allow atomic instructions operating on local memory regions.|
|RC2 | 10| `arith operations`| Reported | [report](https://lore.kernel.org/bpf/2eb5612b88b04587af00394606021972@epfl.ch/) | Inconsistent constraints on instructions converting pointer to scalars.|
|RC1 | 11 | `jumps`    | Reported | [report](https://lore.kernel.org/bpf/2eb5612b88b04587af00394606021972@epfl.ch/) | Coarse-grained pointer comparision |
|RC1 | 12 | `memory operations` | Reported | [report](https://lore.kernel.org/bpf/2eb5612b88b04587af00394606021972@epfl.ch/) | Imprecise memory data tracking |
|RC1 | 13 | `arith operations`  | Reported | [report](https://lore.kernel.org/bpf/2eb5612b88b04587af00394606021972@epfl.ch/) | Inaccurate tracking of arithmetic instruction result|


One undefined-behavior and memory issues in the eBPF verifier itself:

| #  | Description |
|----|-------------|
| 14 | [UBSAN: array-index-out-of-bounds in check_stack_range_initialized](./array-index-out-of-bounds)|
| 15 | [UBSAN: shift-out-of-bounds in check_mem_access](./shift-out-of-bounds)|
