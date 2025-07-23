r0 should be 0 after `r0 = (s16)r3`.
However, due to the inaccurate range track in eBPF at (coerce_reg_to_size_sx and set_sext64_default_val),
the lower 16-bit of r0 becomes unknown, leading to false negatives when exit.

Similar example on module.

func#0 @0
0: R1=ctx() R10=fp0
0: (b7) r6 = -657948387               ; R6_w=0xffffffffd8c8811d
1: (94) w6 s%= 16                     ; R6_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
2: (18) r8 = 0xff11000279981800       ; R8_w=map_ptr(ks=4,vs=8)
4: (18) r9 = 0x19556057               ; R9_w=0x19556057
6: (bf) r3 = r10                      ; R3_w=fp0 R10=fp0
7: (bf) r3 = r6                       ; R3_w=scalar(id=1,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R6_w=scalar(id=1,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
8: (67) r3 <<= 38                     ; R3_w=scalar(smax=0x7fffffc000000000,umax=0xffffffc000000000,smin32=0,smax32=umax32=0,var_off=(0x0; 0xffffffc000000000))
9: (bf) r0 = r6                       ; R0_w=scalar(id=1,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R6_w=scalar(id=1,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
10: (bc) w0 = (s16)w3                 ; R0_w=0 R3_w=scalar(smax=0x7fffffc000000000,umax=0xffffffc000000000,smin32=0,smax32=umax32=0,var_off=(0x0; 0xffffffc000000000))
11: (bf) r0 = (s16)r3                 ; R0_w=scalar(smin=smin32=-32768,smax=smax32=32767) R3_w=scalar(smax=0x7fffffc000000000,umax=0xffffffc000000000,smin32=0,smax32=umax32=0,var_off=(0x0; 0xffffffc000000000))
12: (95) exit
mark_precise: frame0: last_idx 12 first_idx 0 subseq_idx -1 
mark_precise: frame0: regs=r0 stack= before 11: (bf) r0 = (s16)r3
mark_precise: frame0: regs=r3 stack= before 10: (bc) w0 = (s16)w3
mark_precise: frame0: regs=r3 stack= before 9: (bf) r0 = r6
mark_precise: frame0: regs=r3 stack= before 8: (67) r3 <<= 38
mark_precise: frame0: regs=r3 stack= before 7: (bf) r3 = r6
mark_precise: frame0: regs=r6 stack= before 6: (bf) r3 = r10
mark_precise: frame0: regs=r6 stack= before 4: (18) r9 = 0x19556057
mark_precise: frame0: regs=r6 stack= before 2: (18) r8 = 0xff11000279981800
mark_precise: frame0: regs=r6 stack= before 1: (94) w6 s%= 16
mark_precise: frame0: regs=r6 stack= before 0: (b7) r6 = -657948387
At program exit the register R0 has smin=-32768 smax=32767 should have been in [0, 1]
processed 11 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
include "spec.dfy"
method testMain() {
	var s := new State();
	s.progType := BPF_PROG_TYPE_CGROUP_SOCK;
	s.attachType := BPF_CGROUP_INET_INGRESS;
	s.strict_alignment := true;

	assume {:axiom} s.maps.Length == 5;
	s.CreateMap(0, BPF_MAP_TYPE_DEVMAP, 4, 8, 30584, 0, 0);
	s.CreateMap(3, BPF_MAP_TYPE_PERCPU_ARRAY, 0, 0, 0, 0, 0);

	s.spin_lock.isLocked := false;
	// type is: 1
	s.r0.regType := SCALAR;
	assume {:axiom} (!0) & s.r0.regVal == 0;
	s.r0.regVal := s.r0.regVal + 0;
	s.r1.regVal := AnyBv64();
	s.r1.memId := AnyInt64();
	// type is: 2
	s.r1.regType := CTXMEM;
	assume {:axiom} (!0) & s.r1.regVal == 0;
	s.r1.regVal := s.r1.regVal + 0;
	s.r1.memId := 0;
	// type is: 1
	s.r3.regType := SCALAR;
	assume {:axiom} (!18446743798831644672) & s.r3.regVal == 0;
	s.r3.regVal := s.r3.regVal + 0;
	// type is: 1
	s.r6.regType := SCALAR;
	assume {:axiom} (!4294967295) & s.r6.regVal == 0;
	s.r6.regVal := s.r6.regVal + 0;
	// type is: 3
	s.r8.regType := MAP_PTR;
	assume {:axiom} (!0) & s.r8.regVal == 0;
	s.r8.regVal := s.r8.regVal + 0;
	s.r8.memId := 0;
	s.r8.mapFd := 0;
	// type is: 1
	s.r9.regType := SCALAR;
	assume {:axiom} (!0) & s.r9.regVal == 425025623;
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
	s.Mov64SX16(s.r0, s.r3); // Instruction 11
	s.EXIT(); // Instruction 12

}



----------- another example on mod ----------------

func#0 @0
0: R1=ctx() R10=fp0
0: (b7) r0 = -2113129383              ; R0_w=0xffffffff820c3459
1: (94) w0 s%= 16                     ; R0_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
2: (73) *(u8 *)(r10 -208) = r0        ; R0_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R10=fp0 fp-208=???????scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
3: (94) w0 %= 16                      ; R0_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
4: (18) r2 = 0xffffffff8bce831b       ; R2_w=0xffffffff8bce831b
6: (95) exit
mark_precise: frame0: last_idx 6 first_idx 0 subseq_idx -1 
mark_precise: frame0: regs=r0 stack= before 4: (18) r2 = 0xffffffff8bce831b
mark_precise: frame0: regs=r0 stack= before 3: (94) w0 %= 16
mark_precise: frame0: regs=r0 stack= before 2: (73) *(u8 *)(r10 -208) = r0
mark_precise: frame0: regs=r0 stack= before 1: (94) w0 s%= 16
mark_precise: frame0: regs=r0 stack= before 0: (b7) r0 = -2113129383
At program exit the register R0 has smin=0 smax=4294967295 should have been in [0, 1]
processed 6 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
include "spec.dfy"
method testMain() {
	var s := new State();
	s.progType := BPF_PROG_TYPE_SOCK_OPS;
	s.attachType := BPF_CGROUP_INET_INGRESS;
	s.strict_alignment := false;

	assume {:axiom} s.maps.Length == 5;
	s.CreateMap(0, BPF_MAP_TYPE_LRU_HASH, 4, 64, 10881, 0, 0);
	s.CreateMap(3, BPF_MAP_TYPE_STACK_TRACE, 0, 0, 0, 0, 0);

	s.spin_lock.isLocked := false;
	// type is: 1
	s.r0.regType := SCALAR;
	assume {:axiom} (!4294967295) & s.r0.regVal == 0;
	s.r0.regVal := s.r0.regVal + 0;
	s.r1.regVal := AnyBv64();
	s.r1.memId := AnyInt64();
	// type is: 2
	s.r1.regType := CTXMEM;
	assume {:axiom} (!0) & s.r1.regVal == 0;
	s.r1.regVal := s.r1.regVal + 0;
	s.r1.memId := 0;
	s.r10.regVal := AnyBv64();
	s.r10.memId := AnyInt64();
	// type is: 6
	s.r10.regType := STACKMEM;
	assume {:axiom} (!0) & s.r10.regVal == 0;
	s.r10.regVal := s.r10.regVal + 0;
	s.r10.memId := 0;
	var immReg := new RegState(Rn);
	var anybv8 := AnyBv8();
	s.Mod32_IMM(s.r0, 16); // Instruction 3
	s.Load_Imm64(s.r2, -6244367589); // Instruction 4
	s.EXIT(); // Instruction 6

}
