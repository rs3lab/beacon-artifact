include "spec.dfy"


method mask(r5:bv64, r11:bv64) returns (ret:bv64)
	ensures 0 <= ret <= r5
	{
		var input := r5;
		var bound := r11;
		
		bound := bound - input;
		bound := bound | input;
		bound := !bound;
		bound := signShift64Bit(bound, 64);
		bound := bound & input;

		ret := bound;
	}

method testMain() {
	var s := new State(
		// allow_ptr_leak_set:bool, bypass_spec_v1_set:bool, priv_set:bool, has_net_admin:bool
		true, true, true, true, 
		false);
	s.progType := BPF_PROG_TYPE_TRACEPOINT;
	s.attachType := BPF_TRACE_ITER;

	assume {:axiom} s.maps.Length == 5;
	s.CreateMap(0, BPF_MAP_TYPE_QUEUE, 0, 4, 92, 0, 0);

	s.spin_lock_meta.isLocked := false;
	s.r1.regType := CTXMEM;
	s.r1.regVal := AnyBv64();
	assume {:axiom} (!0) & s.r1.regVal == 0;
	s.r1.regVal := s.r1.regVal + 0;
	s.r1.memId := 0;

	s.r10.regType := STACKMEM;
	s.r10.regVal := AnyBv64();
	assume {:axiom} (!0) & s.r10.regVal == 0;
	s.r10.regVal := s.r10.regVal + 0;
	s.r10.memId := 0;
	
	var immReg := new RegState(Rn);
	var anybv8 := AnyBv8();
	s.Mov64_IMM(s.r6, 1451040705); // Instruction 0
	s.SMod32_IMM(s.r6, 64); // Instruction 1
	assert s.r4.regType != UNINT;
	s.Mov64_REG(s.r3, s.r4); // Instruction 2
// size of stack_branches: 0
	

}


/*
method testMain2() {
	var s := new State();
	s.progType := BPF_PROG_TYPE_SOCKET_FILTER;
	s.attachType := BPF_CGROUP_INET_INGRESS;
	s.strict_alignment := false;

	assume {:axiom} s.maps.Length == 5;
	s.CreateMap(0, BPF_MAP_TYPE_LPM_TRIE, 64, 32, 143049592, 0, 0);

	s.spin_lock.isLocked := false;
	s.r1.regVal := AnyBv64();
	s.r1.memId := AnyInt64();
	// type is: 2
	s.r1.regType := CTXMEM;
	assume {:axiom} (!0) & s.r1.regVal == 0;
	s.r1.regVal := s.r1.regVal + 0;
	s.r1.memId := 0;
	// type is: 1
	s.r2.regType := SCALAR;
	assume {:axiom} (!0) & s.r2.regVal == 3004496375;
	s.r2.regVal := s.r2.regVal + 0;
	// type is: 1
	s.r5.regType := SCALAR;
	assume {:axiom} (!0) & s.r5.regVal == 18446744072292350253;
	s.r5.regVal := s.r5.regVal + 0;
	// type is: 1
	s.r8.regType := SCALAR;
	assume {:axiom} (!0) & s.r8.regVal == 18446744073241021639;
	s.r8.regVal := s.r8.regVal + 0;
	s.r10.regVal := AnyBv64();
	s.r10.memId := AnyInt64();
	// type is: 6
	s.r10.regType := STACKMEM;
	assume {:axiom} (!0) & s.r10.regVal == 0;
	s.r10.regVal := s.r10.regVal + 0;
	s.r10.memId := 0;
	var immReg := new RegState(Rn);
	var anybv8 := AnyBv8();
	s.Bv2swap64(s.r8, s.r0); // Instruction 4
	s.Mov32_REG(s.r4, s.r8); // Instruction 5
	s.EXIT(); // Instruction 6

}

method testMain() {
	var s := new State();
	s.progType := BPF_PROG_TYPE_SOCK_OPS;
	s.attachType := BPF_CGROUP_INET_INGRESS;
	s.strict_alignment := false;

	assume {:axiom} s.maps.Length == 5;
	s.CreateMap(0, BPF_MAP_TYPE_STACK, 0, 4, 39, 0, 0);
	s.CreateMap(3, BPF_MAP_TYPE_PROG_ARRAY, 0, 0, 0, 0, 0);

	s.spin_lock.isLocked := false;
	// type is: 1
	s.r0.regType := SCALAR;
	assume {:axiom} (!0) & s.r0.regVal == 3978114433;
	s.r0.regVal := s.r0.regVal + 0;
	s.r1.regVal := AnyBv64();
	s.r1.memId := AnyInt64();
	// type is: 2
	s.r1.regType := CTXMEM;
	assume {:axiom} (!0) & s.r1.regVal == 0;
	s.r1.regVal := s.r1.regVal + 0;
	s.r1.memId := 0;
	// type is: 1
	s.r2.regType := SCALAR;
	assume {:axiom} (!255) & s.r2.regVal == 0;
	s.r2.regVal := s.r2.regVal + 0;
	// type is: 1
	s.r3.regType := SCALAR;
	assume {:axiom} (!255) & s.r3.regVal == 0;
	s.r3.regVal := s.r3.regVal + 0;
	// type is: 1
	s.r4.regType := SCALAR;
	assume {:axiom} (!0) & s.r4.regVal == 9377;
	s.r4.regVal := s.r4.regVal + 0;
	// type is: 1
	s.r5.regType := SCALAR;
	assume {:axiom} (!0) & s.r5.regVal == 1033053345;
	s.r5.regVal := s.r5.regVal + 0;
	// type is: 1
	s.r6.regType := SCALAR;
	assume {:axiom} (!0) & s.r6.regVal == 18446744073146724465;
	s.r6.regVal := s.r6.regVal + 0;
	// type is: 1
	s.r7.regType := SCALAR;
	assume {:axiom} (!0) & s.r7.regVal == 4013934595;
	s.r7.regVal := s.r7.regVal + 0;
	// type is: 1
	s.r9.regType := SCALAR;
	assume {:axiom} (!0) & s.r9.regVal == 13697;
	s.r9.regVal := s.r9.regVal + 0;
	s.r10.regVal := AnyBv64();
	s.r10.memId := AnyInt64();
	// type is: 6
	s.r10.regType := STACKMEM;
	assume {:axiom} (!0) & s.r10.regVal == 0;
	s.r10.regVal := s.r10.regVal + 0;
	s.r10.memId := 0;
	var immReg := new RegState(Rn);
	var anybv8 := AnyBv8();
	s.Bv2be64(s.r6, s.r0); // Instruction 23
immReg.regVal := 1373958239; immReg.regType := SCALAR;
	if s.r10.regType == PTR_TO_ARENA {  s.Store_ARENA(s.r10, immReg, -168, 4); // Instruction 24
	} else if s.r10.regType == PTR_TO_TP_BUFFER {  s.Store_TPBUFFER(s.r10, immReg, -168, 4); // Instruction 24
	} else if s.r10.regType == PTR_TO_SOCK_COMMON {  s.Store_SOCK(s.r10, immReg, -168, 4); // Instruction 24
	} else if s.r10.regType == PTR_TO_TCP_SOCK {  s.Store_SOCK(s.r10, immReg, -168, 4); // Instruction 24
	} else if s.r10.regType == PTR_TO_PACKET_END {  s.Store_PACKET(s.r10, immReg, -168, 4); // Instruction 24
	} else if s.r10.regType == PTR_TO_PACKET {  s.Store_PACKET(s.r10, immReg, -168, 4); // Instruction 24
	} else if s.r10.regType == PTR_TO_SOCKET {  s.Store_SOCK(s.r10, immReg, -168, 4); // Instruction 24
	} else if s.r10.regType == PTR_TO_PACKET_META {  s.Store_PACKET(s.r10, immReg, -168, 4); // Instruction 24
	} else if s.r10.regType == PTR_TO_MAP_KEY {  s.Store_MAPKEY(s.r10, immReg, -168, 4); // Instruction 24
	} else if s.r10.regType == PTR_TO_MAP_VALUE {  s.Store_MAPVALUE(s.r10, immReg, -168, 4); // Instruction 24
	} else if s.r10.regType == PTR_TO_XDP_SOCK {  s.Store_SOCK(s.r10, immReg, -168, 4); // Instruction 24
	} else if s.r10.regType == MAP_PTR {  s.Store_MAPMEM(s.r10, immReg, -168, 4); // Instruction 24
	} else if s.r10.regType == PTR_TO_FLOW_KEYS {  s.Store_FLOWKEYS(s.r10, immReg, -168, 4); // Instruction 24
	} else if s.r10.regType == CTXMEM {  s.Store_CTXMEM(s.r10, immReg, -168, 4); // Instruction 24
	} else if s.r10.regType == STACKMEM {  s.Store_STACKMEM(s.r10, immReg, -168, 4); // Instruction 24
	} else { assert false; } // Instruction 24
	if s.r2.regType == PTR_TO_ARENA {  s.AtomicLS_ARENA(s.r2, s.r1, 0, 8, false); // Instruction 25
	} else if s.r2.regType == PTR_TO_TP_BUFFER {  s.AtomicLS_TPBUFFER(s.r2, s.r1, 0, 8, false); // Instruction 25
	} else if s.r2.regType == PTR_TO_SOCK_COMMON {  s.AtomicLS_SOCK(s.r2, s.r1, 0, 8, false); // Instruction 25
	} else if s.r2.regType == PTR_TO_TCP_SOCK {  s.AtomicLS_SOCK(s.r2, s.r1, 0, 8, false); // Instruction 25
	} else if s.r2.regType == PTR_TO_PACKET_END {  s.AtomicLS_PACKET(s.r2, s.r1, 0, 8, false); // Instruction 25
	} else if s.r2.regType == PTR_TO_PACKET {  s.AtomicLS_PACKET(s.r2, s.r1, 0, 8, false); // Instruction 25
	} else if s.r2.regType == PTR_TO_SOCKET {  s.AtomicLS_SOCK(s.r2, s.r1, 0, 8, false); // Instruction 25
	} else if s.r2.regType == PTR_TO_PACKET_META {  s.AtomicLS_PACKET(s.r2, s.r1, 0, 8, false); // Instruction 25
	} else if s.r2.regType == PTR_TO_MAP_KEY {  s.AtomicLS_MAPKEY(s.r2, s.r1, 0, 8, false); // Instruction 25
	} else if s.r2.regType == PTR_TO_MAP_VALUE {  s.AtomicLS_MAPVALUE(s.r2, s.r1, 0, 8, false); // Instruction 25
	} else if s.r2.regType == PTR_TO_XDP_SOCK {  s.AtomicLS_SOCK(s.r2, s.r1, 0, 8, false); // Instruction 25
	} else if s.r2.regType == MAP_PTR {  s.AtomicLS_MAPMEM(s.r2, s.r1, 0, 8, false); // Instruction 25
	} else if s.r2.regType == PTR_TO_FLOW_KEYS {  s.AtomicLS_FLOWKEYS(s.r2, s.r1, 0, 8, false); // Instruction 25
	} else if s.r2.regType == CTXMEM {  s.AtomicLS_CTXMEM(s.r2, s.r1, 0, 8, false); // Instruction 25
	} else if s.r2.regType == STACKMEM {  s.AtomicLS_STACKMEM(s.r2, s.r1, 0, 8, false); // Instruction 25
	} else { assert false; } // Instruction 25
// size of stack_branches: 0
	

}
*/



/*
method maintest()
    {
        var s:= new State();

        var regImm := new RegState(Rn);
        regImm.regVal := 1;
        regImm.regType := SCALAR;
        assert s.r10.memId == 0;
        s.Store_STACKMEM(s.r10, regImm, -4, 4);
        assert s.r10.memId == 0;
        assert s.stacks[0][508] == 1;
        assert s.stacks[0][509] == 0;
        assert s.stacks[0][510] == 0;
        assert s.stacks[0][511] == 0;

        s.Load_STACKMEM(s.r2, s.r10, -4, 4, false);


        assert s.r2.regType == SCALAR;
        assert s.r2.regNo == R2;
        // assert s.r2.regVal != 1;


        s.r0.regVal := 0;
        s.r0.regType := UNINT;

        s.r1.regType := SCALAR;
        s.r1.regVal := 8;
        
        s.r9.regType := SCALAR;
        s.r9.regVal := 10;

        print s.r0;

        test_pseudo_func(s);
        // reset_5_reg

        assert s.r1.regType == UNINT;
        assert s.r5.regType == UNINT;

        assert s.r9.regType == SCALAR;
        assert s.r9.regVal == 10;

        // assert s.r0.regType == SCALAR;
        // assert s.r0.regVal == 8;
    }
*/


/*    
method test_iter()
    {
        var anybv64 := AnyBv64();
        var anybv8 := AnyBv8();

        assert false;

        var s:= new State();

        // s.pseudo_local_call();

        
        {
            s.r1.regType := STACKMEM;
            s.r1.regVal := -8;
            s.r1.memId := 0;
        }
        

        s.r2.regType := SCALAR;
        s.r2.regVal := 0;

        s.r3.regType := SCALAR;
        s.r3.regVal := 100;

        s.bpf_iter_num_new();
        

        
        s.r1.regType := STACKMEM;
        s.r1.regVal := -8;
        s.r1.memId := 0;

        s.bpf_iter_num_next();


        assert s.stacks[0][504] == 1;
        assert s.stacks[0][505] == 0;
        assert s.stacks[0][506] == 0;
        assert s.stacks[0][507] == 0;

        assert s.stacks[0][508] == 100;
        assert s.stacks[0][509] == 0;
        assert s.stacks[0][510] == 0;
        assert s.stacks[0][511] == 0;
        
        // s.Load_STACKMEM(s.r2, s.r10, -8, 4, false);
        // var y := s.r2.regVal & 0x0000_0000_FFFF_FFFF;
        // assert y == 1;

        ghost var x: bv64 := 0;
        while (x < 100)
            {
                s.r1.regType := STACKMEM;
                s.r1.regVal := -8;
                s.r1.memId := 0;

                s.r2.regType := SCALAR;
                s.r2.regVal := 0;

                s.r3.regType := SCALAR;
                s.r3.regVal := 100;

                s.bpf_iter_num_next();
                
                x := x + 1;
                
                s.r1.regType := STACKMEM;
                s.r1.regVal := -8;

                s.r2.regType := SCALAR;
                s.r2.regVal := 0;

                s.r3.regType := SCALAR;
                s.r3.regVal := 100;
                s.bpf_iter_num_new();
                // assert false;
            }
    }
*/

/*
// r1-r5 are the register states of the caller, r0 and r6-r9 are uninitilized
// after returned to the caller, r6-r9 are not changed.
// TODO: global and static function
//  - global: verified seperately, only return a scalar value
//  - static: verified sequentially
method test_pseudo_func(s1:State)
    // Q2: requires r0-r5 regtype, and regval => recursively finds all requires from errors
    // requires s1.r0.regNo == R0 && s1.r0.regType == UNINT && s1.r0.regVal == 0
    // PTR: type, off, id (mapFd, memId)
    // Scalar: range
    // pre-condition: runtime state of r1-r5
    requires s1.r1.regNo == R1 && s1.r1.regType == SCALAR && s1.r1.regVal < 10 && s1.r1.regVal > 0
    //
    // Q3: requires previous stack frames => ?????????
    //     stack size, depth limit
    //
    // requires r6-r9 uninitialized => new S
    // requires r10 => new S
    // basic requires of other memory => new S
    // 
    modifies s1.r0, s1.r1, s1.r2, s1.r3, s1.r4, s1.r5
    //
    // ensures: runtime state of r0
    ensures s1.reset_5_reg()
    // post-condition:
    // Q1: extract the postcond on the return: data flow backtrack
    {
        // Init
        var s:= new State();
        s.r0.regType := s1.r0.regType;
        s.r0.regVal := s1.r0.regVal;
        s.r1 := s1.r1;
        s.r2 := s1.r2;
        s.r3 := s1.r3;
        s.r4 := s1.r4;
        s.r5 := s1.r5;
        //

        // function code
        s.Mov64_REG(s.r0, s.r1);
        s.Mov64_REG(s.r0, s.r1);
        s.Store_STACKMEM(s.r10, s.r0, -8, 8);
        //

        // Reset r1-r5
        s1.r1.regType := UNINT;
        s1.r2.regType := UNINT;
        s1.r3.regType := UNINT;
        s1.r4.regType := UNINT;
        s1.r5.regType := UNINT;
    }
*/