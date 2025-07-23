func#0 @0
0: R1=ctx() R10=fp0
0: (18) r2 = 0xffffffffc9253523       ; R2_w=0xffffffffc9253523
2: (6a) *(u16 *)(r10 -30) = 1758302811        ; R10=fp0 fp-32=????mm??
3: (b4) w4 = 997267067                ; R4_w=0x3b71167b
4: (d4) r4 = le32 r4                  ; R4_w=scalar()
5: (18) r7 = 0xffffffffcd210993       ; R7_w=0xffffffffcd210993
7: (18) r8 = 0xff1100016dc1d400       ; R8_w=map_ptr(ks=0,vs=1)
9: (18) r7 = 0xff1100016dc1dc00       ; R7_w=map_ptr(ks=4,vs=8)
11: (bf) r9 = r4                      ; R4_w=scalar(id=1) R9_w=scalar(id=1)
12: (44) w9 |= 32                     ; R9_w=scalar(smin=umin=umin32=32,smax=umax=0xffffffff,smin32=0x80000020,var_off=(0x20; 0xffffffdf))
13: (34) w9 s/= 64                    ; R9=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
14: (7e) if w8 s>= w8 goto pc+15      ; R8=map_ptr(ks=0,vs=1)
// not possible to execute this code here
15: (db) lock *(u64 *)(r1 +94) &= r1
BPF_ATOMIC stores into R1 ctx is not allowed
processed 12 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 1
include "spec.dfy"
method testMain() {
	var s := new State();
	s.progType := BPF_PROG_TYPE_CGROUP_SKB;
	s.attachType := BPF_CGROUP_INET_INGRESS;
	s.strict_alignment := true;

	assume s.maps.Length == 5;
	s.CreateMap(0, BPF_MAP_TYPE_BLOOM_FILTER, 0, 1, 71, 0, 0);

	s.spin_lock.isLocked := false;
	// type is: 2
	s.r1.regType := CTXMEM;
	assume {:axiom} (!0) & s.r1.regVal == 0;
	s.r1.regVal := s.r1.regVal + 0;
	s.r1.memId := 0;
	// type is: 1
	s.r2.regType := SCALAR;
	assume {:axiom} (!0) & s.r2.regVal == 18446744072789243171;
	s.r2.regVal := s.r2.regVal + 0;
	// type is: 1
	s.r4.regType := SCALAR;
	assume {:axiom} (!18446744073709551615) & s.r4.regVal == 0;
	s.r4.regVal := s.r4.regVal + 0;
	// type is: 3
	s.r7.regType := MAP_PTR;
	assume {:axiom} (!0) & s.r7.regVal == 0;
	s.r7.regVal := s.r7.regVal + 0;
	s.r7.memId := 0;
	s.r7.mapFd := 0;
	// type is: 3
	s.r8.regType := MAP_PTR;
	assume {:axiom} (!0) & s.r8.regVal == 0;
	s.r8.regVal := s.r8.regVal + 0;
	s.r8.memId := 0;
	s.r8.mapFd := 0;
	// type is: 1
	s.r9.regType := SCALAR;
	assume {:axiom} (!4294967263) & s.r9.regVal == 32;
	s.r9.regVal := s.r9.regVal + 0;
	var immReg := new RegState(Rn);
	var anybv8 := AnyBv8();
	s.SDiv32_IMM(s.r9, 64); // Instruction 13
	if (!s.LGJMP32_REG(s.r8, s.r8, JSGE)) { // Instruction 14
		if s.r1.regType == PTR_TO_ARENA {  s.AtomicLS_ARENA(s.r1, s.r1, 94, 8, false); // Instruction 15
		} else if s.r1.regType == PTR_TO_TP_BUFFER {  s.AtomicLS_TPBUFFER(s.r1, s.r1, 94, 8, false); // Instruction 15
		} else if s.r1.regType == PTR_TO_SOCK_COMMON {  s.AtomicLS_SOCK(s.r1, s.r1, 94, 8, false); // Instruction 15
		} else if s.r1.regType == PTR_TO_TCP_SOCK {  s.AtomicLS_SOCK(s.r1, s.r1, 94, 8, false); // Instruction 15
		} else if s.r1.regType == PTR_TO_PACKET_END {  s.AtomicLS_PACKET(s.r1, s.r1, 94, 8, false); // Instruction 15
		} else if s.r1.regType == PTR_TO_PACKET {  s.AtomicLS_PACKET(s.r1, s.r1, 94, 8, false); // Instruction 15
		} else if s.r1.regType == PTR_TO_SOCKET {  s.AtomicLS_SOCK(s.r1, s.r1, 94, 8, false); // Instruction 15
		} else if s.r1.regType == PTR_TO_PACKET_META {  s.AtomicLS_PACKET(s.r1, s.r1, 94, 8, false); // Instruction 15
		} else if s.r1.regType == PTR_TO_MAP_KEY {  s.AtomicLS_MAPKEY(s.r1, s.r1, 94, 8, false); // Instruction 15
		} else if s.r1.regType == PTR_TO_MAP_VALUE {  s.AtomicLS_MAPVALUE(s.r1, s.r1, 94, 8, false); // Instruction 15
		} else if s.r1.regType == PTR_TO_XDP_SOCK {  s.AtomicLS_SOCK(s.r1, s.r1, 94, 8, false); // Instruction 15
		} else if s.r1.regType == MAP_PTR {  s.AtomicLS_MAPMEM(s.r1, s.r1, 94, 8, false); // Instruction 15
		} else if s.r1.regType == PTR_TO_FLOW_KEYS {  s.AtomicLS_FLOWKEYS(s.r1, s.r1, 94, 8, false); // Instruction 15
		} else if s.r1.regType == CTXMEM {  s.AtomicLS_CTXMEM(s.r1, s.r1, 94, 8, false); // Instruction 15
		} else if s.r1.regType == STACKMEM {  s.AtomicLS_STACKMEM(s.r1, s.r1, 94, 8, false); // Instruction 15
		} else { assert false; } // Instruction 15
	}
}
