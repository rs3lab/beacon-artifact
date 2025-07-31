<h1> eBPF Misbehavior Detection:
<br /> Fuzzing with a Specification-Based Oracle </h1>


## Overview

**Beacon** is a Syzkaller-based fuzzer integrated with our specification-based oracle, **SpecCheck**, to test the Linux eBPF verifier.

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

You can choose to run the evaluation on our server with already setup env or on your own server with preparing the env by yourself.

### Our server

- How to login to our server?
    
    Please send me your SSH public key to me throught hotcrp or my email (tao.lyu@epfl.ch). I'll add your public key to our server and reply you the server address and access account.

    Moreover, since we only have one server, and the evaluation, especially the performance evaluation fully occupies the server for 6 days around. Please schedule your occupation in advance.
    
    > **Note: The account has constrained access permission. Any behavior outside of the evaluation are disallowed and once they are detected, we will report to the chair.**


### Your own env

- Operating system version: ubuntu 22.04

- Execute [`env.sh`](./env.sh) to setup the env.

- **We have already set up a ready enviroment on a 32-core Cloudlab.**
If you prefer to directly use that environment,
please share your SSH public key to us throught the Hotcrp.
Note: Due to limited CPU and memory, performance will degrade linearly.

- Compile the fuzzer
    ```bash
    cd syzkaller
    make
    ```
- Replace the `http` field in `fuzzing-dir/ebpf.cfg` with your own ip.


## Run Beacon

- Execute the below command to start the fuzzer
    ```bash
    cd fuzzing-dir
    ../syzkaller/bin/syz-manager -config ebpf.cfg
    ```

    > **Note**: If the command fails or stucks without any hints,
please try add `-debug` to see the details.

- Open the address specified in the `http` field of `ebpf.cfg` in your browser to see the instant fuzzing statistics.

    > **Note**: If you are running the fuzzer on your server and open the address on your local browser, you must use the ip instead of `localhost`.

- Press `Ctrl+c` to kill the fuzzing process.


## Evaluations

### Bug-finding (Section 6.1)

Bug exposure time in fuzzing varies. It can be minutes, days or even weeks.
To show we did find these bugs listed in the paper,
we attach the detailed information (e.g., reporting, conformation, anc fixes) [here](./bugs/bugs.md).


### Comparison (Section 6.2)

Boot the virtual machine and run the `eval.sh` script to see the result of SpecCheck on existing bug dataset.

```bash
./boot.sh
# login using root and "123456" as password
cd /root/linux-bpfselftest/tools/testing/selftests/bpf
./eval.sh
# The result looks like the below. The rows after each fuzzer (e.g., BRF and buzzer) represents the information of their bugs that are detected by SpecCheck.
# BRF:
# prog_name	veri_res	...
# func	Oracle:unsafe	...
# 
# buzzer:
# ...
```

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

    - **Speed**: 
    Run the beacon for **few hours or 40 hours at most** to observe the speed on the terminal.
    If you are not running on the machine with less cores,
    the speed can be slower than the number (23-25 exec/second) in the paper.
        ```bash
        cd fuzzing-dir
        ../syzkaller/bin/syz-manager -config ebpf.cfg
        ```

    - **Figure 9(a)**: After the running, execute the below command to generate Figure 9 (a) `data/fig-9a.pdf` or `data/fig9a-regen.pdf`.
    **Notably, as the generated test cases are non-deterministic across different fuzzing instance, the time distribution of a new fuzzing instance is not exactly the same as Figure 9 (a) but has the similar distribution.**
        ```bash
        ./visual.sh --original --fig9a
        # or below on your new data
        ./visual.sh --regenerated --fig9a
        ```

- Performance improvement from state sampling
    
    - Execute the below command to run the fuzzer to reproduce the state sampling improvments. In the paper, we run it for 40 hours. But since the key point here is to show the state sampling can improve performance, and the performance improvement cannot be exactly same as the paper because of the non-determinism of test case generator, you can choose to run shorter time, e.g., 5 hours.
        ```bash
        cd fuzzing-dir
        ../syzkaller/bin/syz-manager -config ebpf-impv.cfg
        ```
    
    - Check out the figure previously generate figure 9 (b) to see the improvements. If you want to see the improvements on your newly collected data, you need to run the below command to checkout the figures in `fuzzing-dir/data/fig-9b.pdf` or `fuzzing-dir/data/fig9b-regen.pdf`
        ```bash
        ./visual.sh --original --fig9b
        # or
        ./visual.sh --regenerated --fig9b
        ```

- Code coverage
    We introduced how to check the coverage of Beacon at the begining.
    Here, to compare with BRF, you need to run the below commands to start BRF and see it coverage in the terminal `VMs 1, executed xx, signal xx`, which signal is the branch coverage. You can see BRF and Beacon achieve the similar coverage after **40 hours**.
    ```
    cd fuzzing-dir
    ../sota/brf/bin/syz-manager -config brf.cfg
    ```

## Contact

If you have any questions or suggestions,
feel free to reach out to us at (tao.lyu@epfl.ch).