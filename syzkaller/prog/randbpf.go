package prog

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"unsafe"

	"github.com/google/syzkaller/pkg/log"
)

/*
#cgo CXXFLAGS: -I/usr/lib/ -Wno-narrowing -Wint-to-pointer-cast -std=c++17
#cgo LDFLAGS: -L/usr/lib64 -lstdc++ -l:libbpf.a -l:libz.a -l:libelf.a -l:libzstd.a
#include <stdint.h>
#include <stdlib.h>
#include "genbpfcimport.hpp"
#include "mutbpfcimport.hpp"
*/
import "C"

type ProgAttrDef struct {
	Prog_type            [4]byte
	Insn_cnt             [4]byte
	Insns                *byte
	License              *byte
	Log_level            int32
	Log_size             int32
	Log_buf              *byte
	Kern_version         int32
	Prog_flags           [4]byte
	Prog_name            [16]byte
	Prog_ifindex         [4]byte
	Expected_attach_type [4]byte
	Prog_btf_fd          [4]byte
	Func_info_rec_size   int32
	Func_info            *byte
	Func_info_cnt        [4]byte
	Line_info_rec_size   int32
	Line_info            *byte
	Line_info_cnt        [4]byte
	Attach_btf_id        [4]byte
	Attach_prog_fd       [4]byte
	Core_relo_cnt        [4]byte
	Fd_array             *byte
	Core_relos           *byte
	Core_relo_rec_size   [4]byte
	Log_true_size        [4]byte
	// Save the corresponding slices
	Insns2      []byte
	License2    []byte
	Func_info2  []byte
	Line_info2  []byte
	Fd_array2   []byte
	Core_relos2 []byte
}

type btfAttrDef struct {
	btf               *byte
	btf_log_buf       *byte
	btf_size          [4]byte
	btf_log_size      int32
	btf_log_level     int32
	btf_log_true_size [4]byte
	// Save the corresponding slices
	btf2 []byte
}

type MapAttrDef struct {
	// only 72 bytes are used.
	All_fields [4096]byte
}

func SizeofStmState() uint64 {
	return uint64(C.ItmStateSize())
}

func (target *Target) EquivCFGMutate(p *Prog, rs rand.Source, ct *ChoiceTable) []*Prog {

	mutatedProgs := make([]*Prog, 0)
	condInsnIdxs := make([][]int, 0)

	var prog_size uint32 = binary.BigEndian.Uint32(p.ProgAttr.Insn_cnt[:])
	condInsnAllIdxs := make([]int, 0, prog_size)

	// How to fix this
	indxNum := int(C.get_branch_idx((*C.char)(unsafe.Pointer(p.ProgAttr.Insns)), (C.int)(prog_size), (*C.int)(unsafe.Pointer(&(condInsnAllIdxs[0])))))
	if indxNum < 0 {
		return nil
	}
	// Manually write the len
	*(*int)(unsafe.Pointer(uintptr(unsafe.Pointer(&condInsnAllIdxs)) + 8)) = indxNum
	condInsnIdxs = append(condInsnIdxs, condInsnAllIdxs)
	for _, i := range condInsnAllIdxs {
		condInsnIdxs = append(condInsnIdxs, []int{i})
	}
	for _, condInsnIdx := range condInsnIdxs {
		// Copy the struct
		newProg := p.Clone()

		// Prog
		newProg.ProgAttr = p.ProgAttr
		newProg.ProgAttr.Insns2 = append(make([]byte, 0), p.ProgAttr.Insns2...)
		newProg.ProgAttr.Insns = &(newProg.ProgAttr.Insns2[0])

		newProg.ProgAttr.License2 = append(make([]byte, 0), p.ProgAttr.License2...)
		newProg.ProgAttr.License = &(newProg.ProgAttr.License2[0])

		newProg.ProgAttr.Func_info2 = append(make([]byte, 0), p.ProgAttr.Func_info2...)
		newProg.ProgAttr.Func_info = &(newProg.ProgAttr.Func_info2[0])

		if C.MAXLINEINFOSIZE != 0 {
			newProg.ProgAttr.Line_info2 = append(make([]byte, 0), p.ProgAttr.Line_info2...)
			newProg.ProgAttr.Line_info = &(newProg.ProgAttr.Line_info2[0])
		}

		newProg.ProgAttr.Fd_array2 = append(make([]byte, 0), p.ProgAttr.Fd_array2...)
		newProg.ProgAttr.Fd_array = &(newProg.ProgAttr.Fd_array2[0])

		// Map
		copy(newProg.MapAttrs.All_fields[:], p.MapAttrs.All_fields[:])
		newProg.MapCnt = p.MapCnt

		// Btf
		newProg.BtfAttr = p.BtfAttr
		newProg.BtfAttr.btf2 = append(make([]byte, 0), p.BtfAttr.btf2...)
		newProg.BtfAttr.btf = &(newProg.BtfAttr.btf2[0])

		C.EquivCFGMutate((*C.char)(unsafe.Pointer(&newProg.ProgAttr)), (C.int)(len(condInsnIdx)))

		progArgLists, mapArgLists, btfArgLists := struct2ArgArray(&newProg.ProgAttr, &newProg.MapAttrs, &newProg.BtfAttr, newProg.MapCnt)

		prog := generateCalls(progArgLists, btfArgLists, mapArgLists, rs, target, ct)

		mutatedProgs = append(mutatedProgs, prog)
	}

	return mutatedProgs
}

func (target *Target) BPFGenerate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {

	var progAttr ProgAttrDef

	progAttr.Insns2 = make([]byte, int(C.MAXINSNSIZE))
	progAttr.Insns = &(progAttr.Insns2[0])

	progAttr.License2 = make([]byte, 32)
	progAttr.License = &(progAttr.License2[0])

	progAttr.Func_info2 = make([]byte, int(C.MAXFUNCINFOSIZE))
	progAttr.Func_info = &(progAttr.Func_info2[0])

	if C.MAXLINEINFOSIZE != 0 {
		progAttr.Line_info2 = make([]byte, int(C.MAXLINEINFOSIZE))
		progAttr.Line_info = &(progAttr.Line_info2)[0]
	}

	progAttr.Fd_array2 = make([]byte, int(C.MAXFDARRAYSIZE))
	progAttr.Fd_array = &(progAttr.Fd_array2[0])
	// Unused right now
	// core_relos

	var mapAttrs MapAttrDef
	if len(mapAttrs.All_fields) < int(C.MAXMAPNUM*C.UNIONSIZE) {
		log.Fatalf("Please enlarge the size of All_fields in mapAttrDef.")
	}

	var btfAttr btfAttrDef
	btfAttr.btf2 = make([]byte, C.MAXBTFSIZE)
	btfAttr.btf = &(btfAttr.btf2[0])

	mapCnt := C.GenBPFProg((*C.char)(unsafe.Pointer(&progAttr)),
		(*C.char)(unsafe.Pointer(&(mapAttrs.All_fields[0]))),
		(*C.char)(unsafe.Pointer(&btfAttr)))
	mapCntInt := int(mapCnt)

	progArgLists, mapArgLists, btfArgLists := struct2ArgArray(&progAttr, &mapAttrs, &btfAttr, mapCntInt)
	prog := generateCalls(progArgLists, btfArgLists, mapArgLists, rs, target, ct)

	log.Logf(0, "progAttr.insn_cnt: %v\n", progAttr.Insn_cnt)
	prog.ProgAttr = progAttr
	prog.MapAttrs = mapAttrs
	prog.BtfAttr = btfAttr
	prog.MapCnt = mapCntInt

	return prog
}

/*
func bytePtr2Slice(bytePtr *byte, size int) (data []byte) {
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	sh.Data = uintptr(unsafe.Pointer(bytePtr))
	sh.Len = size
	sh.Cap = size
}
*/

func struct2ArgArray(progAttr *ProgAttrDef, mapAttrs *MapAttrDef, btfAttr *btfAttrDef, mapCnt int) ([][][]byte, [][][][]byte, [][][]byte) {

	// Prog attr
	progArgLists := make([][]byte, 26)
	progArgLists[0] = progAttr.Prog_type[:]
	progArgLists[1] = progAttr.Insn_cnt[:]
	progArgLists[2] = progAttr.Insns2[:]
	progArgLists[3] = progAttr.License2[:]
	// log_level
	// log_size
	// log_buf
	// kernel_version
	progArgLists[8] = progAttr.Prog_flags[:]
	progArgLists[9] = progAttr.Prog_name[:]
	progArgLists[10] = progAttr.Prog_ifindex[:]
	progArgLists[11] = progAttr.Expected_attach_type[:]
	progArgLists[12] = progAttr.Prog_btf_fd[:]
	// func_info_rec_size
	progArgLists[14] = progAttr.Func_info2[:]
	progArgLists[15] = progAttr.Func_info_cnt[:]
	// line_info_rec_size
	progArgLists[17] = progAttr.Line_info2[:]
	progArgLists[18] = progAttr.Line_info_cnt[:]
	progArgLists[19] = progAttr.Attach_btf_id[:]
	progArgLists[20] = progAttr.Attach_prog_fd[:]
	progArgLists[21] = progAttr.Core_relo_cnt[:]
	progArgLists[22] = progAttr.Fd_array2[:]
	// core_relos
	progArgLists[24] = progAttr.Core_relo_rec_size[:]
	progArgLists[25] = progAttr.Log_true_size[:]
	empty := [][]byte{make([]byte, 0)}
	progArgListAll := [][][]byte{empty, progArgLists, empty}

	// Map attr
	mapArgListAll := make([][][][]byte, mapCnt)
	unionsize := int(C.UNIONSIZE)
	for idx := 0; idx < mapCnt; idx++ {
		empty := [][]byte{make([]byte, 0)}
		bpfAttr := mapAttrs.All_fields[unionsize*idx : unionsize*(idx+1)]
		tmp := [][][]byte{empty, [][]byte{bpfAttr[:72]}, empty}
		mapArgListAll[idx] = tmp
	}

	// BTF attr
	btfArgLists := make([][]byte, 6)
	btfArgLists[0] = btfAttr.btf2[:]
	// btf_log_buf
	btfArgLists[2] = btfAttr.btf_size[:]
	btfArgLists[5] = btfAttr.btf_log_true_size[:]
	btfArgListAll := [][][]byte{empty, btfArgLists, empty}

	return progArgListAll, mapArgListAll, btfArgListAll
}

func generateCalls(progArgLists [][][]byte, btfArgLists [][][]byte,
	mapArgLists [][][][]byte, rs rand.Source,
	target *Target, ct *ChoiceTable) *Prog {

	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	calls := make([]*Call, 0)

	// Generate BTF load call
	log.Logf(0, "Generating BTF load call")
	bpfcall := 92
	meta := r.target.Syscalls[bpfcall]
	calls3 := r.generateParticularBPFCall(s, meta, btfArgLists)
	calls = append(calls, calls3...)

	// Generate map creation calls
	log.Logf(0, "Generating map call")
	for i := 0; i < len(mapArgLists); i++ {
		mapCall := 121
		meta := r.target.Syscalls[mapCall]
		calls1 := r.generateParticularBPFCall(s, meta, mapArgLists[i])
		calls = append(calls, calls1...)
	}

	// Generate prog load call
	log.Logf(0, "Generating load call")
	loadCall := 135
	meta = r.target.Syscalls[loadCall]
	calls2 := r.generateParticularBPFCall(s, meta, progArgLists)
	calls = append(calls, calls2...)

	for _, c := range calls {
		s.analyze(c)
		p.Calls = append(p.Calls, c)
	}
	/*
			for len(p.Calls) > ncalls {
		        p.RemoveCall(ncalls - 1)
		    }
	*/
	p.sanitizeFix()
	p.debugValidate()
	return p
}

func (r *randGen) generateParticularBPFCall(s *state, meta *Syscall, argData [][][]byte) (calls []*Call) {
	if meta.Attrs.Disabled {
		panic(fmt.Sprintf("generating disabled call %v", meta.Name))
	}
	if meta.Attrs.NoGenerate {
		panic(fmt.Sprintf("generating no_generate call: %v", meta.Name))
	}
	c := MakeCall(meta, nil)
	c.Args, calls = r.generateBPFArgs(s, meta.Args, DirIn, argData)
	r.target.assignSizesCall(c)
	return append(calls, c)
}

func (r *randGen) generateBPFArgs(s *state, fields []Field, dir Dir, argData [][][]byte) ([]Arg, []*Call) {

	var calls []*Call
	args := make([]Arg, len(fields))

	for i, field := range fields {
		arg, calls1 := r.generateBPFArg(s, field.Type, field.Dir(dir), argData, i, -1)
		args[i] = arg
		calls = append(calls, calls1...)
	}
	return args, calls
}

func (r *randGen) generateBPFArg(s *state, typ Type, dir Dir, argData [][][]byte, i int, j int) (arg Arg, calls []*Call) {

	if typ1, ok := typ.(*PtrType); ok {
		arg, calls = typ1.generatePtrType(r, s, dir, argData, i, j)
	} else if typ1, ok := typ.(*BufferType); ok {
		arg, calls = typ1.generateBufferType(r, s, dir, argData, i, j)
	} else {
		arg, calls = typ.generate(r, s, dir)
		if arg == nil {
			panic(fmt.Sprintf("generated arg is nil for field '%v'", typ.Name()))
		}
	}

	return arg, calls
}

func (a *PtrType) generatePtrType(r *randGen, s *state, dir Dir, argData [][][]byte, i int, j int) (arg Arg, calls []*Call) {

	var inner Arg
	if _, ok := a.Elem.(*BufferType); ok {
		inner, calls = a.Elem.(*BufferType).generateBufferType(r, s, a.ElemDir, argData, i, j)

	} else if typ, ok := a.Elem.(*StructType); ok {
		args := make([]Arg, len(typ.Fields))
		for idx, field := range typ.Fields {
			arg, calls1 := r.generateBPFArg(s, field.Type, a.ElemDir, argData, i, idx)
			args[idx] = arg
			calls = append(calls, calls1...)
		}
		inner = MakeGroupArg(a.Elem, dir, args)

	} else {
		inner, calls = r.generateArg(s, a.Elem, a.ElemDir)
	}

	arg = r.allocAddr(s, a, dir, inner.Size(), inner)
	return arg, calls
}

func (a *BufferType) generateBufferType(r *randGen, s *state, dir Dir, argData [][][]byte, i int, j int) (arg Arg, calls []*Call) {
	switch a.Kind {
	case BufferBlobRand, BufferBlobRange:
		sz := r.randBufLen()
		if a.Kind == BufferBlobRange {
			sz = r.randRange(a.RangeBegin, a.RangeEnd)
		}
		if dir == DirOut {
			return MakeOutDataArg(a, dir, sz), nil
		}
		return MakeDataArg(a, dir, argData[i][j]), nil
	default:
		panic("unknown buffer kind")
	}
}
