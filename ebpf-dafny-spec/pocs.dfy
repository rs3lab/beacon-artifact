include "spec.dfy"

method PoC_spinlock() {


	/*
        r0 = bpf_map_lookup_elem(&map, ...); // id=1
        r6 = r0;
        r0 = bpf_map_lookup_elem(&map, ...); // id=2
        r7 = r0;

        bpf_spin_lock(r1=r6);
        if (cond) // unknown scalar, hence verifier cannot predict branch
            r6 = r7;
        p:
        bpf_spin_unlock(r1=r7);

        +	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        +	BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_6, offsetof(struct __sk_buff, mark)),
        +	BPF_LD_MAP_FD(BPF_REG_1, 0),
        +	BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),
        +	BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),

        +	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        +	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        +	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        +	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        +	BPF_EXIT_INSN(),
        +	BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
        +	BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),
        +	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        +	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        +	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        +	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        +	BPF_EXIT_INSN(),
        +	BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),
        +	BPF_MOV64_REG(BPF_REG_1, BPF_REG_7),
        +	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 4),
        +	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_spin_lock),
        +	BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0, 1),
        +	BPF_JMP_IMM(BPF_JA, 0, 0, 1),
        +	BPF_MOV64_REG(BPF_REG_7, BPF_REG_8),
        +	BPF_MOV64_REG(BPF_REG_1, BPF_REG_7),
        +	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 4),
        +	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_spin_unlock),
        +	BPF_MOV64_IMM(BPF_REG_0, 0),
        +	BPF_EXIT_INSN(),
     */
    var s:= new State();
    s.progType := BPF_PROG_TYPE_SCHED_CLS;
    assert s.maps.Length == 10;
    s.CreateMap(0, BPF_MAP_TYPE_ARRAY, 4, 8, 1, 0, 0);

    s.Mov64_REG(s.r6, s.r1);
    assert s.r6.regVal == 0;
    s.Load_CTXMEM(s.r6, s.r6, 8, 4, false);
    s.Load_MAPFD(s.r1, 0);
    s.Mov64_REG(s.r9, s.r1);
    //
    var immReg := new RegState(Rn);
    immReg.regType := SCALAR;
    immReg.regVal := 0;
    s.Store_STACKMEM(s.r10, immReg, -4, 4);
    s.Mov64_REG(s.r2, s.r10);
    s.Add64_IMM(s.r2, -4);
    //
    s.bpf_map_lookup_elem();
    if (!s.JNE64_IMM(s.r0, 0)) {
        assert s.r0.regType == NULL;
        assume s.r0.regType == NULL ==> s.r0.regType == SCALAR && s.r0.regVal == 0;
        s.EXIT();
    } else {
        s.Mov64_REG(s.r7, s.r0);
        s.Mov64_REG(s.r1, s.r9);
        s.Mov64_REG(s.r2, s.r10);
        s.Add64_IMM(s.r2, -4);
        s.bpf_map_lookup_elem();
        if (!s.JNE64_IMM(s.r0, 0)) {
            assert s.r0.regType == NULL;
            assume s.r0.regType == NULL ==> s.r0.regType == SCALAR && s.r0.regVal == 0;
            s.EXIT();
        } else {
            s.Mov64_REG(s.r8, s.r0);
            s.Mov64_REG(s.r1, s.r7);
            s.Add64_IMM(s.r1, 4);
            s.bpf_spin_lock();
            if (!s.JEQ64_IMM(s.r6, 0)) {
                s.Mov64_REG(s.r1, s.r7);
                s.Add64_IMM(s.r1, 4);
                s.bpf_spin_unlock();
                s.Mov64_IMM(s.r0, 0);
                s.EXIT();
            } else {
                s.Mov64_REG(s.r7, s.r8);
                s.Mov64_REG(s.r1, s.r7);
                s.Add64_IMM(s.r1, 4);
                s.bpf_spin_unlock();
                s.Mov64_IMM(s.r0, 0);
                s.EXIT();
            }
        }
    }
}


// untermination in bpf_iter_num
method infinite_loop_in_bpf_iter_num()
    {

        /*
             	r0 = bpf_map_lookup_elem(&map, ...); // id=1
                r6 = r0;
                r0 = bpf_map_lookup_elem(&map, ...); // id=2
                r7 = r0;

                bpf_spin_lock(r1=r6);
                if (cond)
                    r6 = r7;
            p:
                bpf_spin_unlock(r1=r6);
         */

        var s:= new State();

        s.r2.regType := SCALAR;
        s.r2.regVal := 0;

        s.r3.regType := SCALAR;
        s.r3.regVal := 100;

        s.bpf_iter_num_new();
        assert s.NumIters[0].end == 100;

        var ret := 0;
        // s.bpf_iter_num_next();
        // assert s.NumIters[0].end == 100;
        // assert s.NumIters[0].start == 1;
        // assert ret == 1;
        // assert s.NumIters[0].end == 100;

        ghost var x: bv64 := 0;
        // assert s.NumIters[0].end == 100;
        // assert s.NumIters[0].start == 1;
        while ((s.NumIters[0].end - s.NumIters[0].start) != 0)
            invariant x < 100 ==> s.NumIters[0].start == x && s.NumIters[0].end == 100
            invariant x >= 100 ==> s.NumIters[0].start == 0 && s.NumIters[0].end == 0
            modifies s.NumIters[0]
            {
                
                s.r2.regType := SCALAR;
                s.r2.regVal := 0;
                s.r3.regType := SCALAR;
                s.r3.regVal := 100;
                
                ret := s.bpf_iter_num_next();
                x := x + 1;

                s.r2.regType := SCALAR;
                s.r2.regVal := 0;
                s.r3.regType := SCALAR;
                s.r3.regVal := 100;

                s.bpf_iter_num_new();
            }
    }