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

## A ready environment on Cloudlab

We have already setup a ready enviroment on Cloudlab


## Environment setup

- Operating system version: ubuntu 22.04

- Execute [`env.sh`](./env.sh) to setup the env.

- **We have already set up a ready enviroment on a 32-core Cloudlab.**
If you prefer to directly use that environment,
please share your SSH public key to us throught the Hotcrp.

## Run Beacon

- Compile the fuzzer
```bash
cd syzkaller
make
```

- Replace `http` field in `fuzzing-dir/ebpf.cfg` with your own ip.

- Execute the below command to start the fuzzer

```bash
cd fuzzing-dir
sudo ../syzkaller/bin/syz-manager -config ebpf.cfg
```

> **Note**: If the command fails or stucks without any hints,
please try add `-debug` to see the details.

- Open the address specified in the `http` field in your browser to see the instant fuzzing statistics.

> **Note**: If you are running the fuzzer on your server and open the address on your local browser, you must use the ip instead of `localhost`.


## Evaluations

### Bug-finding (Section 6.1)

Bug exposure time in fuzzing varies. It can be minutes, days or even weeks.
To show we did find these bugs listed in the paper,
we attach the detailed information (e.g., reporting, conformation, anc fixes) [here](./bugs/bugs.md).

TODO: SpecCheck can detect the PoCs

### Comparison (Section 6.2)

buzzer-env.sh

### Performance (Section 6.3)

This experiment needs to be run on a *224-core machine for 40 hours* to reproduce the result.
After the running,
the file `fuzzing-dir/workdir/verify-per.csv` records the statistics of tests,
including the verification result from the runtime and SpecCheck, the time spent at different stage.

The fuzzing speed and code coverage show on both the web page and terminal.
After opening the webpage specified by the `http` field in your configuration file,
you will see the the speed `exec total 	xx (xx/sec)` and the branch coverage `signal 	xx`.
To see the latest speed and coverage, you need to manually refresh the webpage.
Also, you can see them on the terminal (``VMs 1, executed xx, signal xx/xx, ... , speed 22/sec``),
which outputs the latest data every 10 seconds.

- Fuzzing througput
    - **Speed**: If you are not running on the machine with less cores,
    the speed can be slower than the number (23-25 exec/second) in the paper.

    - **Figure 9(a)**: Run the below command to generate Figure 9 `data/fig9.pdf` and see the entire execution time
    distribution of test cases during fuzzing in Figure 9 (a).
        ```bash
        ./visual.sh --original
        # or below on your new data
        ./visual.sh --regenerated
        ```

- Performance improvement from state sampling
    
    - Execute the below command to run the fuzzer to reproduce the state sampling improvments.
        ```bash
        cd fuzzing-dir
        sudo ../syzkaller/bin/syz-manager -config ebpf-impv.cfg
        ```
    
    - Check out the figure previously generate figure 9 (b) to see the improvements. If you want to see the improvements on your newly collected data, you need to rerun `./visual.sh --regenerated`.


- Code coverage
    We introduced how to check the coverage of Beacon at the begining.
    Here, to compare with BRF, you need to run the below commands to start it and see it coverage in the terminal `VMs 1, executed xx, signal xx`, which signal is the branch coverage.
    ```
    cd fuzzing-dir
    sudo ../sota/brf/bin/syz-manager -config brf.cfg
    ```

## Contact

If you have any questions or suggestions,
feel free to reach out to us at (tao.lyu@epfl.ch).