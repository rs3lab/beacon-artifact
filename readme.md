<h1> eBPF Misbehavior Detection:
<br /> Fuzzing with a Specification-Based Oracle </h1>


## Overview

**Beacon** is a fuzzer integrated with our specification-based oracle, **SpecCheck**, to test the Linux eBPF verifier.

**SpecCheck** encodes eBPF instruction semantics and safety properties as a specification and turn the claim of whether a concrete eBPF program is safe into checking the satisfiability of the corresponding safety constraints, which can be reasoned automatically without abstraction. The output from the oracle will be cross-checked with the eBPF verifier for any discrepancies.

This repo includes the source code and documentation of Beacon.
Its organization is listed below.

```bash
Beacon
    |------ syzkaller       ; source code of the Google syzkaller
    |       |------ prog    ; the modified test case generator for eBPF verifier
    |       |------ syz-manager
    |       |       |------ rpc.go          ; call the specification to detect bugs
    |       |       |------ ebpf2dafny.cpp  ; shallow embedding process
    |
    |------ ebpf-dafny-spec ; the specification of eBPF
    |------ fuzzing-dir     ; the testing kernel, VM image, fuzzing config, and runtime data
    |------ env.sh          ; the script to setup the env
    |------ readme.md
```


## Environment setup

- Operating system version: ubuntu 22.04

- Execute [`env.sh`](./env.sh) to setup the env.


## Run Beacon

- Compile the fuzzer
```bash
cd syzkaller
make
```

- Replace `http` field in `fuzzing-dir/ebpf.cfg` with your own ip

- Execute the below command to start the fuzzer

```bash
cd fuzzing-dir
sudo syzkaller/bin/syz-manager -config ebpf.cfg
```

> **Note**: If the command fails or stucks without any hints,
please try add `-debug` to see the details.

## Evaluations

### Bug-finding (Section 6.1)

Bug exposure time in fuzzing varies. It can be minutes, days or even weeks.
To show we did find these bugs listed in the paper,
we attach the detailed information (e.g., reporting, conformation, anc fixes) [here](./bugs.md).

TODO: SpecCheck can detect the PoCs

### Comparison (Section 6.2)


### Performance (Section 6.3)


## Contact

If you have any questions or suggestions,
feel free to reach out to us at (tao.lyu@epfl.ch).