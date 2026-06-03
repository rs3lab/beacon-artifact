# insn2dafny — eBPF Shallow Embedding Translator

Translates raw eBPF bytecode into a **Dafny ghost method** that uses
the `eBPF-Spec` formal specification functions step-by-step. This
enables Dafny to verify security properties (integrity, non-leakage)
over concrete eBPF programs.

## Build

```bash
make
```

Requires: `gcc` with C11 support.

## Usage

```bash
./insn2dafny <insn_file> [method_name] > output.dfy
```

**Input format** (`insn_file`): one eBPF instruction per line,
8 space-separated lowercase hex bytes, little-endian encoding:

```
# Comments start with #
b7 01 00 00 2a 00 00 00   # r1 = 42
07 01 00 00 0a 00 00 00   # r1 += 10
7b 2a f8 ff 00 00 00 00   # *(r10-8) = r2
```

Byte layout: `code | (src<<4)|dst | off_lo | off_hi | imm0 | imm1 | imm2 | imm3`

## Instruction Categories Supported

### Arithmetic
| eBPF bytecode | Dafny function | Dafny instruction |
|---|---|---|
| ALU64/ALU NEG | `arith_unary` | `ARITHUNARY(dst, NEG32/NEG64)` |
| ALU64/ALU END | `arith_unary` | `ARITHUNARY(dst, BV2LE/BV2BE/BV2SWAP...)` |
| ALU64 ADD/SUB reg | `add64_reg` / `sub64_reg` | `ARITHBINREG(dst, src, ADD64/SUB64)` |
| ALU64 ADD/SUB imm | `add64_imm` / `sub64_imm` | `ARITHBINIMM(dst, imm, ADD64/SUB64)` |
| ALU64 MUL/DIV/MOD/XOR/AND/OR/LSH/RSH/ARSH reg/imm | `arith_binop_reg/imm` | all 64-bit ops |
| ALU (32-bit) same ops | same functions | 32-bit ops (ADD32, MUL32 ...) |

### Data Move
| eBPF bytecode | Dafny function | Dafny instruction |
|---|---|---|
| MOV64/MOV32 imm | `datamov_imm` | `DATAMOVIMM(dst, imm, MOVIMM64/MOVIMM32)` |
| MOV64/MOV32 reg | `datamov_reg` | `DATAMOVREG(dst, src, MOV64/MOV32)` |
| MOV reg with off=8/16/32 (MOVSX) | `datamov_reg` | `DATAMOVREG(dst, src, MOVSX8TO64/...)` |
| LD_IMM64 (two insns) | `datamov_imm` | `DATAMOVIMM(dst, imm, LOADIMM64)` |
| LD_IMM64 with map fd | `datamov_imm` | `DATAMOVIMM(dst, fd, LOADMAPFD)` |

### Memory
| eBPF bytecode | Dafny function | Dafny instruction |
|---|---|---|
| LDX B/H/W/DW | `mem_load` | `MEMLD(dst, src, off, B/HW/W/DW, false)` |
| STX B/H/W/DW | `mem_store_reg` | `MEMSTX(dst, src, off, size)` |
| ST B/H/W/DW | `mem_store_imm` | `MEMST(dst, imm, off, size)` |
| STX ATOMIC (ADD/AND/OR/XOR/XCHG/CMPXCHG + FETCH variants) | `mem_atomic` | `ATOMICLS(dst, src, off, size, op)` |

### Control Flow
| eBPF bytecode | Dafny function | Dafny instruction |
|---|---|---|
| JMP JEQ/JNE/JGT/JGE/JLT/JLE/JSGT/JSGE/JSLT/JSLE reg | `cond_jump_reg` | `CONDJMPREG(dst, src, JEQ64/...)` |
| JMP same ops imm | `cond_jump_imm` | `CONDJMPIMM(dst, imm, JEQ64/...)` |
| JMP32 same ops | same functions | 32-bit variants (JEQ32/...) |

## Output

The translator emits a complete Dafny file like:

```dafny
include "../spec/arith-spec.dfy"
include "../spec/datamov-spec.dfy"
// ...

module Embedded_my_prog {

    import opened eBPFArithSpec
    // ...

    ghost method {:timeLimit 300} my_prog(rand: bv64)
    {
        var cfg := ConfigState(...);
        var init_s := init_state(cfg, rand);
        assert {:split_here} mem_inv(init_s);

        // step 0 : datamov_imm
        var s0 := datamov_imm(init_s, DATAMOVIMM(R1, 0x000000000000002a, MOVIMM64));
        assert {:split_here} mem_inv(s0);

        // step 1 : add64_imm
        var s1 := add64_imm(s0, ARITHBINIMM(R1, 0x000000000000000a, ADD64));
        assert {:split_here} mem_inv(s1);
        // ...
    }
}
```

Every step has a `mem_inv` assertion with `{:split_here}` so Dafny can
verify them independently for efficiency.

## Running Tests

```bash
make test
# or directly:
python3 tests/run_tests.py
```

Test files in `tests/`:
- `arith.bpf` — 14 arithmetic instructions (all ALU ops)
- `datamov.bpf` — data move including wide imm, MOVSX
- `memory.bpf` — stack load/store (LDX, STX, ST)
- `ctrlflow.bpf` — conditional jumps (JMP + JMP32)
- `edge_sub64.bpf` — edge case: SUB64 reg + imm

Generated `.dfy` files land in `tests/output/` for inspection.

## Integration with eBPF-Spec

Once you have the generated `.dfy`:

1. Place it in the `eBPF-spec/` repo directory
2. Run the Dafny verifier:
   ```bash
   dotnet Dafny.dll verify --verification-time-limit 300 \
       spec/terms.dfy spec/types.dfy ... \
       my_prog.dfy
   ```
3. Dafny will check all `mem_inv` assertions and can be extended with
   property-specific postconditions.

## Adding Custom Config

Edit the `BpfProgConfig cfg` block in `main()` or pass a config JSON
(planned for Week-2) to set:
- `allow_ptr_leak` — allows pointer leakage (unprivileged = false)
- `prog_type` — BPF program type (affects ctx memory layout)
- `map_fd_arr` — map file descriptor index array
- `host_le` — host endianness for byte-swap instructions