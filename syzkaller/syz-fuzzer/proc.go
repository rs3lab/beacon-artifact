// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"
	// "strings"
	"unsafe"
	"C"

	// "golang.org/x/sys/unix"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	fuzzer          *Fuzzer
	pid             int
	env             *ipc.Env
	rnd             *rand.Rand
	execOpts        *ipc.ExecOpts
	execOptsCollide *ipc.ExecOpts
	execOptsCover   *ipc.ExecOpts
	execOptsComps   *ipc.ExecOpts
}

const (
	PRIV_UNPRIV = iota
	PRIV_CAP_BPF
	PRIV_CAP_PERFMON
	PRIV_CAP_NET_ADMIN
	PRIV_CAP_SYS_ADMIN
	/*
    PrivL0 = iota
    PrivL1
    PrivL2 // 
    PrivL3 // BPF_PERFMON -> allow_ptr_leak, bypass_spec_v1
	PrivL4 // BPF_SYS_ADMIN -> allow_ptr_leak, bypass_spec_v1, priv
	*/
)

const (
	NOTBUG = iota
	FNEG
	FPOS
)

var (
	itm_states []byte
)

func mmap_itm_states() {

	if itm_states != nil {
		return
	}

	// Open the file with read-write access
	file, err := os.OpenFile("/sys/kernel/debug/fuzz", os.O_RDWR, 0)
	if err != nil {
		log.SyzFatalf("open debug fuzz fails: %v\n", err)
	}

	size := prog.SizeofStmState()
	log.Logf(0, "mmap size: %d\n", size)
	itm_states, err = syscall.Mmap(int(file.Fd()), 0, int(size), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		log.SyzFatalf("fuzz states mmap: %v\n", err)
	}
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {

	mmap_itm_states();

	env, err := ipc.MakeEnv(fuzzer.config, pid)
	if err != nil {
		return nil, err
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
	execOptsCollide := *fuzzer.execOpts
	execOptsCollide.Flags &= ^ipc.FlagCollectSignal
	execOptsCover := *fuzzer.execOpts
	execOptsCover.Flags |= ipc.FlagCollectCover
	execOptsComps := *fuzzer.execOpts
	execOptsComps.Flags |= ipc.FlagCollectComps
	proc := &Proc{
		fuzzer:          fuzzer,
		pid:             pid,
		env:             env,
		rnd:             rnd,
		execOpts:        fuzzer.execOpts,
		execOptsCollide: &execOptsCollide,
		execOptsCover:   &execOptsCover,
		execOptsComps:   &execOptsComps,
	}
	return proc, nil
}

func (proc *Proc) loop() {
	generatePeriod := 100
	if proc.fuzzer.config.Flags&ipc.FlagSignal == 0 {
		// If we don't have real coverage signal, generate programs more frequently
		// because fallback signal is weak.
		generatePeriod = 2
	}

	proc.execOpts.Flags |= ipc.FlagCollectCover

	for i := 0; ; i++ {
		item := proc.fuzzer.workQueue.dequeue()
		if item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				proc.triageInput(item)
			case *WorkCandidate:
				proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
			case *WorkSmash:
				// proc.smashInput(item)
			default:
				log.SyzFatalf("unknown work type: %#v", item)
			}
			continue
		}

		ct := proc.fuzzer.choiceTable
		fuzzerSnapshot := proc.fuzzer.snapshot()
		if len(fuzzerSnapshot.corpus) == 0 || i%generatePeriod == 0 || true {
			// Generate a new prog.
			p := proc.fuzzer.target.BPFGenerate(proc.rnd, prog.RecommendedCalls, ct)
			log.Logf(1, "#%v: generated", proc.pid)
			// Execute with different privileges
			p.PrivL = PRIV_UNPRIV
			proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
			//
			p.PrivL = PRIV_CAP_BPF
			proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
			//
			p.PrivL = PRIV_CAP_PERFMON
			proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
			//
			p.PrivL = PRIV_CAP_SYS_ADMIN
			proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
			//proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatGenerate)
		} else {
			continue
			// Mutate an existing prog.
			p := fuzzerSnapshot.chooseProgram(proc.rnd).Clone()
			p.Mutate(proc.rnd, prog.RecommendedCalls, ct, proc.fuzzer.noMutate, fuzzerSnapshot.corpus)
			log.Logf(1, "#%v: mutated", proc.pid)
			proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatFuzz)
		}
	}
}

func (proc *Proc) triageInput(item *WorkTriage) {
	log.Logf(1, "#%v: triaging type=%x", proc.pid, item.flags)

	prio := signalPrio(item.p, &item.info, item.call)
	inputSignal := signal.FromRaw(item.info.Signal, prio)
	newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)
	if newSignal.Empty() {
		return
	}
	callName := ".extra"
	logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}
	log.Logf(3, "triaging input for %v (new signal=%v)", logCallName, newSignal.Len())
	var inputCover cover.Cover
	const (
		signalRuns       = 1 // It is enough to run once
		minimizeAttempts = 3
	)
	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	rawCover := []uint32{}
	for i := 0; i < signalRuns; i++ {
		info := proc.executeRaw(proc.execOptsCover, item.p, StatTriage)
		if !reexecutionSuccess(info, &item.info, item.call) {
			// The call was not executed or failed.
			notexecuted++
			if notexecuted > signalRuns/2+1 {
				return // if happens too often, give up
			}
			continue
		}
		thisSignal, thisCover := getSignalAndCover(item.p, info, item.call)
		if len(rawCover) == 0 && proc.fuzzer.fetchRawCover {
			rawCover = append([]uint32{}, thisCover...)
		}
		newSignal = newSignal.Intersection(thisSignal)
		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		if newSignal.Empty() && item.flags&ProgMinimized == 0 {
			return
		}
		inputCover.Merge(thisCover)
	}
	if false {
		//if item.flags&ProgMinimized == 0 {
		item.p, item.call = prog.Minimize(item.p, item.call, false,
			func(p1 *prog.Prog, call1 int) bool {
				for i := 0; i < minimizeAttempts; i++ {
					info := proc.execute(proc.execOpts, p1, ProgNormal, StatMinimize)
					if !reexecutionSuccess(info, &item.info, call1) {
						// The call was not executed or failed.
						continue
					}
					thisSignal, _ := getSignalAndCover(p1, info, call1)
					if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
						return true
					}
				}
				return false
			})
	}

	data := item.p.Serialize()
	sig := hash.Hash(data)

	// log.Logf(2, "added new input for %v to corpus:\n%s", logCallName, data)
	proc.fuzzer.sendInputToManager(rpctype.Input{
		Call:     callName,
		CallID:   item.call,
		Prog:     data,
		Signal:   inputSignal.Serialize(),
		Cover:    inputCover.Serialize(),
		RawCover: rawCover,
	})

	proc.fuzzer.addInputToCorpus(item.p, inputSignal, sig)

	if item.flags&ProgSmashed == 0 && false {
		proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
	}
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover
}

func (proc *Proc) smashInput(item *WorkSmash) {
	if proc.fuzzer.faultInjectionEnabled && item.call != -1 && false {
		proc.failCall(item.p, item.call)
	}
	if proc.fuzzer.comparisonTracingEnabled && item.call != -1 && false {
		proc.executeHintSeed(item.p, item.call)
	}
	fuzzerSnapshot := proc.fuzzer.snapshot()
	for i := 0; i < 100; i++ {
		p := item.p.Clone()
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, proc.fuzzer.noMutate, fuzzerSnapshot.corpus)
		log.Logf(1, "#%v: smash mutated", proc.pid)
		proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatSmash)
	}
}

func (proc *Proc) failCall(p *prog.Prog, call int) {
	for nth := 1; nth <= 100; nth++ {
		log.Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
		newProg := p.Clone()
		newProg.Calls[call].Props.FailNth = nth
		info := proc.executeRaw(proc.execOpts, newProg, StatSmash)
		if info != nil && len(info.Calls) > call && info.Calls[call].Flags&ipc.CallFaultInjected == 0 {
			break
		}
	}
}

func (proc *Proc) executeHintSeed(p *prog.Prog, call int) {
	log.Logf(1, "#%v: collecting comparisons", proc.pid)
	// First execute the original program to dump comparisons from KCOV.
	info := proc.execute(proc.execOptsComps, p, ProgNormal, StatSeed)
	if info == nil {
		return
	}

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(call, info.Calls[call].Comps, func(p *prog.Prog) {
		log.Logf(1, "#%v: executing comparison hint", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatHint)
	})
}

func (proc *Proc) bpfEquivTest(p *prog.Prog, orgInfo *ipc.ProgInfo) {

	log.Logf(0, "# Equivalence mutation state #\n")

	// Policies for deciding if we should do the equivalence testing.
	// check the orgInfo.BPFRet is 0 and existence of state pruning
	// in the verification log (orgInfo.BPFLog) and extract the pruned path.

	if orgInfo.BPFRet != 0 {
		log.Logf(0, "No mutation on invalid program \n")
		return
	}

	re := regexp.MustCompile("from (/d+) to /d+: safe\n")

	prunned := re.FindAllStringSubmatch(string(orgInfo.BPFLog), -1)

	// Check about this
	if prunned != nil {

		/*

			for _, line := range prunned {
				prunnedIdx, err := strconv.Atoi(line[1])
				if err != nil {
					condInsnIdx = append(condInsnIdx, prunnedIdx)
					} else {
						log.Logf(0, "Conversion error in prunnedIdx Atoi on string %s\n", line[1])
						panic(22)
					}
				}
		*/
		// Mutate this program
		ct := proc.fuzzer.choiceTable
		newProgs := proc.fuzzer.target.EquivCFGMutate(p, proc.rnd, ct)
		for _, newProg := range newProgs {
			info := proc.executeRaw(proc.execOpts, newProg, StatSmash)

			// If the return values from two executions differ, it's a bug.
			if info.BPFRet != orgInfo.BPFRet {
				log.Logf(0, "A bug found by equivalence testing.")
			}
		}
	} else {
		log.Logf(0, "No pruning for EquivCFGMutate\n")
	}

}

func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) *ipc.ProgInfo {

	if stat != StatCandidate && stat == StatGenerate {
		var arr2 [10]byte
	    for i := 0; i < 10; i++ {
		    arr2[i] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p.ProgAttr.Insns)) + uintptr(i)))
	    }
		log.Logf(0, "before execute: %v", arr2)
	}

	info := proc.executeRaw(execOpts, p, stat)
	if info == nil {
		return nil
	}
	calls, extra := proc.fuzzer.checkNewSignal(p, info)
	for _, callIndex := range calls {
		if p.Calls[callIndex].Meta.Name != "bpf$PROG_LOAD2" {
			continue
		}
		proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex], info)
	}
	if extra {
		proc.enqueueCallTriage(p, flags, -1, info.Extra, info)
	}

	// Equivalence testing
	// Skip equivalence testing on testcases loaded from corpus when starting a fuzzing instance.
	log.Logf(0, "info.BPFRet: %d\n", info.BPFRet);
	if stat != StatCandidate && stat == StatGenerate {

		// Reset the variable indicating the start of interm state copying.
		// proc.fuzzer.target.StateCPBegin()

		// go func() {

		// DEBUG
		var resultString string
		resultString += fmt.Sprintf("\nInsns debug:\n")
		for _, b := range p.ProgAttr.Insns2[:16] {
			resultString += fmt.Sprintf("%02X", b) // Convert to a zero-padded two-character hexadecimal string
		}
		resultString += fmt.Sprintf("\n")
		finalByteSlice := []byte(resultString)
		// DEBUG

		verifyArgs := &rpctype.OneProgVeriArgs{
			ProgAttr: p.ProgAttr,
			MapAttrs: p.MapAttrs,
			MapCnt: p.MapCnt,
			PrivL: p.PrivL,
			ItmState: itm_states,
			RunRes: info.BPFRet,
			VerifyLog: append(append(info.BPFLog), finalByteSlice...),
		}

		if err := proc.fuzzer.manager.Call("Manager.VerifyOneProgWrapper", verifyArgs, nil); err != nil {
			log.SyzFatalf("Manager.VerifyOneProgWrapper call failed: %v", err)
		}

			/*
			isBug, smtStr := proc.fuzzer.target.IsBug(p, info.BPFRet)

			if isBug != NOTBUG {

				title := ""
				if isBug == FNEG {
					title += "False negative (usibility): "
					lines := strings.Split(string(info.BPFLog), "\n")
					length := len(lines)
					if length > 3 {
						title += lines[length-3]
					}
				} else if isBug == FPOS {
					title += "False positive (security)"
				}

				a := &rpctype.NewBugRepArgs {
						Title: title,
						Log:  append(info.BPFLog, smtStr...),
						Input: rpctype.Input{
									Prog:   p.Serialize(),
						},
				}

				if err := proc.fuzzer.manager.Call("Manager.SaveBugReport", a, nil); err != nil {
					log.SyzFatalf("Manager.SaveBugReport call failed: %v", err)
				}
			}
			*/
		// }()

		// Sync/wait the finishing of interm state copying.
		// proc.fuzzer.target.StateCPDone()
	}
	return info
}

// proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex])
func (proc *Proc) MocktriageInput(item *WorkTriage, info *ipc.ProgInfo) {
	log.Logf(1, "#%v: triaging type=%x", proc.pid, item.flags)

	prio := signalPrio(item.p, &item.info, item.call)
	inputSignal := signal.FromRaw(item.info.Signal, prio)
	newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)
	if newSignal.Empty() {
		return
	}

	callName := ".extra"
	// logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		// logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}
	// log.Logf(3, "triaging input for %v (new signal=%v)", logCallName, newSignal.Len())


	var inputCover cover.Cover
	rawCover := []uint32{}
	_, thisCover := getSignalAndCover(item.p, info, item.call)
	if len(rawCover) == 0 && proc.fuzzer.fetchRawCover {
        rawCover = append([]uint32{}, thisCover...)
    }
	inputCover.Merge(thisCover)

	data := item.p.Serialize()
	sig := hash.Hash(data)

	// log.Logf(2, "added new input for %v to corpus:\n%s", logCallName, data)
	proc.fuzzer.sendInputToManager(rpctype.Input{
		Call:     callName,
		CallID:   item.call,
		Prog:     data,
		Signal:   inputSignal.Serialize(),
		Cover:    inputCover.Serialize(),
		RawCover: rawCover,
	})

	proc.fuzzer.addInputToCorpus(item.p, inputSignal, sig)
}

func (proc *Proc) enqueueCallTriage(p *prog.Prog, flags ProgTypes, callIndex int, info ipc.CallInfo, progInfo *ipc.ProgInfo) {
	// info.Signal points to the output shmem region, detach it before queueing.
	info.Signal = append([]uint32{}, info.Signal...)
	// None of the caller use Cover, so just nil it instead of detaching.
	// Note: triage input uses executeRaw to get coverage.
	info.Cover = nil
	oneItem := &WorkTriage{
		p:     p.Clone(),
		call:  callIndex,
		info:  info,
		flags: flags,
	}
	proc.MocktriageInput(oneItem, progInfo)
}

func (proc *Proc) executeAndCollide(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) {
	proc.execute(execOpts, p, flags, stat)

	if proc.execOptsCollide.Flags&ipc.FlagThreaded == 0 {
		// We cannot collide syscalls without being in the threaded mode.
		return
	}
	const collideIterations = 2
	for i := 0; i < collideIterations; i++ {
		proc.executeRaw(proc.execOptsCollide, proc.randomCollide(p), StatCollide)
	}
}

func (proc *Proc) randomCollide(origP *prog.Prog) *prog.Prog {
	if proc.rnd.Intn(5) == 0 {
		// Old-style collide with a 20% probability.
		p, err := prog.DoubleExecCollide(origP, proc.rnd)
		if err == nil {
			return p
		}
	}
	if proc.rnd.Intn(4) == 0 {
		// Duplicate random calls with a 20% probability (25% * 80%).
		p, err := prog.DupCallCollide(origP, proc.rnd)
		if err == nil {
			return p
		}
	}
	p := prog.AssignRandomAsync(origP, proc.rnd)
	if proc.rnd.Intn(2) != 0 {
		prog.AssignRandomRerun(p, proc.rnd)
	}
	return p
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat) *ipc.ProgInfo {
	proc.fuzzer.checkDisabledCalls(p)

	// Limit concurrency window and do leak checking once in a while.
	ticket := proc.fuzzer.gate.Enter()
	defer proc.fuzzer.gate.Leave(ticket)

	proc.logProgram(opts, p)
	for try := 0; ; try++ {
		atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
		output, info, hanged, err := proc.env.Exec(opts, p)
		if err != nil {
			if err == prog.ErrExecBufferTooSmall {
				// It's bad if we systematically fail to serialize programs,
				// but so far we don't have a better handling than counting this.
				// This error is observed a lot on the seeded syz_mount_image calls.
				atomic.AddUint64(&proc.fuzzer.stats[StatBufferTooSmall], 1)
				return nil
			}
			if try > 10 {
				log.SyzFatalf("executor %v failed %v times: %v", proc.pid, try, err)
			}
			log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
			debug.FreeOSMemory()
			time.Sleep(time.Second)
			continue
		}
		log.Logf(2, "result hanged=%v: %s", hanged, output)
		return info
	}
}

func (proc *Proc) logProgram(opts *ipc.ExecOpts, p *prog.Prog) {
	if proc.fuzzer.outputType == OutputNone {
		return
	}

	data := p.Serialize()

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.fuzzer.outputType {
	case OutputStdout:
		now := time.Now()
		proc.fuzzer.logMu.Lock()
		fmt.Printf("%02v:%02v:%02v executing program %v:\n%s\n",
			now.Hour(), now.Minute(), now.Second(),
			proc.pid, data)
		proc.fuzzer.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v:\n%s\n",
				proc.pid, data)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.fuzzer.name, proc.pid))
		if err == nil {
			f.Write(data)
			f.Close()
		}
	default:
		log.SyzFatalf("unknown output type: %v", proc.fuzzer.outputType)
	}
}
