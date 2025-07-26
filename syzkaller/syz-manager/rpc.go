// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
	"regexp"
	"unsafe"
	"bytes"
	"strings"
	"sort"
	"strconv"
	// "encoding/binary"

	"github.com/shirou/gopsutil/cpu"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/pkg/report"
)

/*
#cgo CXXFLAGS: -I/usr/lib/ -Wno-narrowing -Wint-to-pointer-cast -std=c++17
#include "trancimport.hpp"
*/
import "C"

type RPCServer struct {
	mgr                   RPCManagerView
	cfg                   *mgrconfig.Config
	modules               []host.KernelModule
	port                  int
	targetEnabledSyscalls map[*prog.Syscall]bool
	coverFilter           map[uint32]uint32
	stats                 *Stats
	batchSize             int
	canonicalModules      *cover.Canonicalizer

	mu            sync.Mutex
	fuzzers       map[string]*Fuzzer
	checkResult   *rpctype.CheckArgs
	maxSignal     signal.Signal
	corpusSignal  signal.Signal
	corpusCover   cover.Cover
	rotator       *prog.Rotator
	rnd           *rand.Rand
	checkFailures int
}

type Fuzzer struct {
	name          string
	rotated       bool
	inputs        []rpctype.Input
	newMaxSignal  signal.Signal
	rotatedSignal signal.Signal
	machineInfo   []byte
	instModules   *cover.CanonicalizerInstance
}

type BugFrames struct {
	memoryLeaks []string
	dataRaces   []string
}

// RPCManagerView restricts interface between RPCServer and Manager.
type RPCManagerView interface {
	fuzzerConnect([]host.KernelModule) (
		[]rpctype.Input, BugFrames, map[uint32]uint32, []byte, error)
	machineChecked(result *rpctype.CheckArgs, enabledSyscalls map[*prog.Syscall]bool)
	newInput(inp rpctype.Input, sign signal.Signal) bool
	candidateBatch(size int) []rpctype.Candidate
	rotateCorpus() bool
	saveCrash(crash *Crash) bool
}

func startRPCServer(mgr *Manager) (*RPCServer, error) {
	serv := &RPCServer{
		mgr:     mgr,
		cfg:     mgr.cfg,
		stats:   mgr.stats,
		fuzzers: make(map[string]*Fuzzer),
		rnd:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	serv.batchSize = 5
	if serv.batchSize < mgr.cfg.Procs {
		serv.batchSize = mgr.cfg.Procs
	}
	s, err := rpctype.NewRPCServer(mgr.cfg.RPC, "Manager", serv)
	if err != nil {
		return nil, err
	}
	log.Logf(0, "serving rpc on tcp://%v", s.Addr())
	serv.port = s.Addr().(*net.TCPAddr).Port
	go s.Serve()
	return serv, nil
}

func (serv *RPCServer) Connect(a *rpctype.ConnectArgs, r *rpctype.ConnectRes) error {
	log.Logf(1, "fuzzer %v connected", a.Name)
	serv.stats.vmRestarts.inc()

	corpus, bugFrames, coverFilter, coverBitmap, err := serv.mgr.fuzzerConnect(a.Modules)
	if err != nil {
		return err
	}
	serv.coverFilter = coverFilter
	serv.modules = a.Modules

	if serv.canonicalModules == nil {
		serv.canonicalModules = cover.NewCanonicalizer(a.Modules)
	}

	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := &Fuzzer{
		name:        a.Name,
		machineInfo: a.MachineInfo,
		instModules: serv.canonicalModules.NewInstance(a.Modules),
	}
	serv.fuzzers[a.Name] = f
	r.MemoryLeakFrames = bugFrames.memoryLeaks
	r.DataRaceFrames = bugFrames.dataRaces
	r.CoverFilterBitmap = coverBitmap
	r.EnabledCalls = serv.cfg.Syscalls
	r.NoMutateCalls = serv.cfg.NoMutateCalls
	r.GitRevision = prog.GitRevision
	r.TargetRevision = serv.cfg.Target.Revision
	if serv.mgr.rotateCorpus() && serv.rnd.Intn(5) == 0 && false {
		// We do rotation every other time because there are no objective
		// proofs regarding its efficiency either way.
		// Also, rotation gives significantly skewed syscall selection
		// (run prog.TestRotationCoverage), it may or may not be OK.
		r.CheckResult = serv.rotateCorpus(f, corpus)
	} else {
		r.CheckResult = serv.checkResult
		f.inputs = corpus
		f.newMaxSignal = serv.maxSignal.Copy()
	}
	return nil
}

func (serv *RPCServer) rotateCorpus(f *Fuzzer, corpus []rpctype.Input) *rpctype.CheckArgs {
	// Fuzzing tends to stuck in some local optimum and then it fails to cover
	// other state space points since code coverage is only a very approximate
	// measure of logic coverage. To overcome this we introduce some variation
	// into the process which should cause steady corpus rotation over time
	// (the same coverage is achieved in different ways).
	//
	// First, we select a subset of all syscalls for each VM run (result.EnabledCalls).
	// This serves 2 goals: (1) target fuzzer at a particular area of state space,
	// (2) disable syscalls that cause frequent crashes at least in some runs
	// to allow it to do actual fuzzing.
	//
	// Then, we remove programs that contain disabled syscalls from corpus
	// that will be sent to the VM (f.inputs). We also remove 10% of remaining
	// programs at random to allow to rediscover different variations of these programs.
	//
	// Then, we drop signal provided by the removed programs and also 10%
	// of the remaining signal at random (f.newMaxSignal). This again allows
	// rediscovery of this signal by different programs.
	//
	// Finally, we adjust criteria for accepting new programs from this VM (f.rotatedSignal).
	// This allows to accept rediscovered varied programs even if they don't
	// increase overall coverage. As the result we have multiple programs
	// providing the same duplicate coverage, these are removed during periodic
	// corpus minimization process. The minimization process is specifically
	// non-deterministic to allow the corpus rotation.
	//
	// Note: at no point we drop anything globally and permanently.
	// Everything we remove during this process is temporal and specific to a single VM.
	calls := serv.rotator.Select()

	var callIDs []int
	callNames := make(map[string]bool)
	for call := range calls {
		callNames[call.Name] = true
		callIDs = append(callIDs, call.ID)
	}

	f.inputs, f.newMaxSignal = serv.selectInputs(callNames, corpus, serv.maxSignal)
	// Remove the corresponding signal from rotatedSignal which will
	// be used to accept new inputs from this manager.
	f.rotatedSignal = serv.corpusSignal.Intersection(f.newMaxSignal)
	f.rotated = true

	result := *serv.checkResult
	result.EnabledCalls = map[string][]int{serv.cfg.Sandbox: callIDs}
	return &result
}

func (serv *RPCServer) selectInputs(enabled map[string]bool, inputs0 []rpctype.Input, signal0 signal.Signal) (
	inputs []rpctype.Input, signal signal.Signal) {
	signal = signal0.Copy()
	for _, inp := range inputs0 {
		calls, _, err := prog.CallSet(inp.Prog)
		if err != nil {
			panic(fmt.Sprintf("rotateInputs: CallSet failed: %v\n%s", err, inp.Prog))
		}
		for call := range calls {
			if !enabled[call] {
				goto drop
			}
		}
		if serv.rnd.Float64() > 0.9 {
			goto drop
		}
		inputs = append(inputs, inp)
		continue
	drop:
		for _, sig := range inp.Signal.Elems {
			delete(signal, sig)
		}
	}
	signal.Split(len(signal) / 10)
	return inputs, signal
}

func (serv *RPCServer) Check(a *rpctype.CheckArgs, r *int) error {
	serv.mu.Lock()
	defer serv.mu.Unlock()

	if serv.checkResult != nil {
		return nil // another VM has already made the check
	}
	// Note: need to print disbled syscalls before failing due to an error.
	// This helps to debug "all system calls are disabled".
	if len(serv.cfg.EnabledSyscalls) != 0 && len(a.DisabledCalls[serv.cfg.Sandbox]) != 0 {
		disabled := make(map[string]string)
		for _, dc := range a.DisabledCalls[serv.cfg.Sandbox] {
			disabled[serv.cfg.Target.Syscalls[dc.ID].Name] = dc.Reason
		}
		for _, id := range serv.cfg.Syscalls {
			name := serv.cfg.Target.Syscalls[id].Name
			if reason := disabled[name]; reason != "" {
				log.Logf(0, "disabling %v: %v", name, reason)
			}
		}
	}
	if a.Error != "" {
		log.Logf(0, "machine check failed: %v", a.Error)
		serv.checkFailures++
		if serv.checkFailures == 10 {
			log.Fatalf("machine check failing")
		}
		return fmt.Errorf("machine check failed: %v", a.Error)
	}
	serv.targetEnabledSyscalls = make(map[*prog.Syscall]bool)
	for _, call := range a.EnabledCalls[serv.cfg.Sandbox] {
		serv.targetEnabledSyscalls[serv.cfg.Target.Syscalls[call]] = true
	}
	log.Logf(0, "machine check:")
	log.Logf(0, "%-24v: %v/%v", "syscalls", len(serv.targetEnabledSyscalls), len(serv.cfg.Target.Syscalls))
	for _, feat := range a.Features.Supported() {
		log.Logf(0, "%-24v: %v", feat.Name, feat.Reason)
	}
    /*
    for i, call := range serv.cfg.Target.Syscalls {
        log.Logf(0, "%v %v", i, call)
    }
    */
	serv.mgr.machineChecked(a, serv.targetEnabledSyscalls)
	a.DisabledCalls = nil
	serv.checkResult = a
	serv.rotator = prog.MakeRotator(serv.cfg.Target, serv.targetEnabledSyscalls, serv.rnd)
	return nil
}

var (
	should_wait bool = false
	mu          sync.Mutex
)

func findLastErrorLineNo(log string) int {

	if strings.Contains(log, "processed 0 insn") || !strings.Contains(log, "processed ") {
		return -1
	}

	// Regular expression to match the line numbers at the start of each line
	re := regexp.MustCompile(`(?m)^(\d+):`)

	// Find all matches
	matches := re.FindAllStringSubmatch(log, -1)

	if len(matches) == 0 {
		fmt.Println("No line numbers found")
		return -1
	}

	// Get the last line number
	lastLineNumberStr := matches[len(matches)-1][1]

	// Convert the last line number to an integer
	lastLineNumber, err := strconv.Atoi(lastLineNumberStr)
	if err != nil {
		fmt.Println("Error converting line number:", err)
		return -1
	}

	return lastLineNumber
}

func dafny_err_insn(dafny_veri_log []byte) string {

	var log_len int
    index := bytes.IndexByte(dafny_veri_log[:], 0)
    if index != -1 {
        log_len = index;
    } else {
        log_len = len(dafny_veri_log)
    }

    // Define the regex pattern to capture the number inside the parentheses
    re := regexp.MustCompile(`/tmp/spec.dfy\((\d+),\d+\): Related location`)
    matches := re.FindAllStringSubmatch(string(dafny_veri_log[:log_len]), -1)
    linenos := []string{}
    for _, match := range matches {
		linenos = func(arr []string, new_elem string) []string {
			for _, elem := range arr {
				if elem == new_elem {
					return arr
				}
			}
			arr = append(arr, new_elem)
			return arr
		}(linenos, match[1])
		// linenos = append(linenos, match[1])
    }
    if (len(linenos) > 0) {
		sort.Strings(linenos)
		return "spec.dfy:" + strings.Join(linenos, ",")
	} else {
		return ""
	}
}

func runtime_err_insn(runtime_veri_log []byte) string {

	errmsg_re := regexp.MustCompile(`\d+: .*?\n(.*?)\nprocessed `)
    err_msgs := ""
    for _, match := range errmsg_re.FindAllStringSubmatch(string(runtime_veri_log), -1) {
        err_msgs += match[1]
    }

	mask_re := regexp.MustCompile(`\d+`)
	// Replace all numbers with "M"
	err_msgs = mask_re.ReplaceAllString(err_msgs, "M")
	return err_msgs
}


func (serv *RPCServer) VerifyOneProgWrapper(a *rpctype.OneProgVeriArgs, r *int) error {

	mu.Lock()
	for should_wait {
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		mu.Lock()
	}
	mu.Unlock()

	go func() {

		for {

			percentages, err := cpu.Percent(time.Millisecond*50, false)
	        if err != nil || len(percentages) <= 0 {
	            fmt.Println("Error fetching CPU usage:", err)
				mu.Lock()
				should_wait = false
				mu.Unlock()
		        return
			}
			if percentages[0] > 70 {
				mu.Lock()
				should_wait = true
				mu.Unlock()
				time.Sleep(10 * time.Millisecond)
			} else {
				mu.Lock()
				should_wait = false
				mu.Unlock()
				// log.Logf(0, "cpu usage: %.2f%%\n", percentages[0])
				break
			}
		}

		errLineNo := findLastErrorLineNo(string(a.VerifyLog))
		if errLineNo == -1 {
			return
		}

		var dafny_veri_log [4194304]byte // 4M

		// log.Logf(0, "Verification log with %v insns:\n%v\n", binary.LittleEndian.Uint32(a.ProgAttr.Insn_cnt[:]), string(a.VerifyLog))
		a.ProgAttr.Insns = &(a.ProgAttr.Insns2[0])
		isBug := int(C.VerifyOneProg(
						(*C.char)(unsafe.Pointer(&a.ProgAttr)),
						(*C.char)(unsafe.Pointer(&a.MapAttrs)),
						C.int(a.MapCnt),
						C.int(a.PrivL),
						(*C.char)(unsafe.Pointer(&(a.ItmState[0]))),
						C.int(a.RunRes),
						C.int(errLineNo),
						C.CString(serv.cfg.Workdir),
						(*C.char)(unsafe.Pointer(&dafny_veri_log[0])),
						(*C.char)(unsafe.Pointer(&a.VerifyLog[0])),
						C.bool(serv.cfg.Eval)))

		if isBug != 0 {

			var log_len int
            index := bytes.IndexByte(dafny_veri_log[:], 0)
            if index != -1 {
                log_len = index;
            } else {
                log_len = len(dafny_veri_log)
            }

			title := ""
			if (isBug == 1) {
				title = "False positive (security): " + dafny_err_insn(dafny_veri_log[:log_len])
			} else if (isBug == 2) {
				title = "False negative (usability): " + runtime_err_insn(a.VerifyLog)
			} else if (isBug == 3) {
				re := regexp.MustCompile(`\|\s*.*s\.AtomicLS_STACKMEM`)
				if re.MatchString(string(dafny_veri_log[:])) {
					return
				}
				title = "Inconsistency: " + dafny_err_insn(dafny_veri_log[:]) + ":" + runtime_err_insn(a.VerifyLog)
			} else if (isBug == -1) {
				title = "Dafny verification timeout"
			}

			/*

			// Define the regex pattern to capture the number inside the parentheses
			re := regexp.MustCompile(`/tmp/spec.dfy\((\d+),\d+\): Related location`)
			matches := re.FindAllStringSubmatch(string(dafny_veri_log[:log_len]), -1)
			title := "spec.dfy:"
			linenos := []string{}
			for _, match := range matches {
				linenos = append(linenos, match[1])
			}
			if (len(linenos) > 0) {
				sort.Strings(linenos)
				title += strings.Join(linenos, ",")
			} else {
				errmsg_re := regexp.MustCompile(`\d+: .*?\n(.*?)\nprocessed `)
				title = ""
				for _, match := range errmsg_re.FindAllStringSubmatch(string(a.VerifyLog), -1) {
					title += match[1]
					// title = errmsg_re.FindString(string(a.VerifyLog))
				}
				if title == "" {
					title = "bugs violating checks in the main method"
				} else {
				    mask_re := regexp.MustCompile(`\d+`)

				    // Replace all numbers with "M"
				    title = mask_re.ReplaceAllString(title, "M")
				}
			}
			*/

			bugInfo := Crash {
				vmIndex: 0,
				hub: false,
				Report: &report.Report {
					Title: title,
					Output: append(a.VerifyLog, dafny_veri_log[:log_len]...),
				},
				machineInfo: []byte("nothing"),
			}

			serv.mgr.saveCrash(&bugInfo)
		}
	}()

	return nil
}

func (serv *RPCServer) SaveBugReport(a *rpctype.NewBugRepArgs, r *int) error {

	re := regexp.MustCompile(`\d+`)
	a.Title = re.ReplaceAllString(a.Title, "N")

	bugInfo := Crash {
		vmIndex: 0,
		hub: false,
		Report: &report.Report {
			Title: a.Title,
			Output: append(a.Input.Prog, a.Log...),
		},
		machineInfo: []byte("nothing"),
	}

	serv.mgr.saveCrash(&bugInfo)
	return nil
}

func (serv *RPCServer) NewInput(a *rpctype.NewInputArgs, r *int) error {
	inputSignal := a.Signal.Deserialize()
	// log.Logf(0, "new input from %v for syscall %v (signal=%v, cover=%v)",
	// 	a.Name, a.Call, inputSignal.Len(), len(a.Cover))
	bad, disabled := checkProgram(serv.cfg.Target, serv.targetEnabledSyscalls, a.Input.Prog)
	if bad || disabled {
		log.Logf(0, "rejecting program from fuzzer (bad=%v, disabled=%v):\n%s", bad, disabled, a.Input.Prog)
		return nil
	}
	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := serv.fuzzers[a.Name]
	if f != nil {
		f.instModules.Canonicalize(a.Cover)
	}
	// Note: f may be nil if we called shutdownInstance,
	// but this request is already in-flight.
	genuine := !serv.corpusSignal.Diff(inputSignal).Empty()
	rotated := false
	if !genuine && f != nil && f.rotated {
		rotated = !f.rotatedSignal.Diff(inputSignal).Empty()
	}
	if !genuine && !rotated {
		return nil
	}
	if !serv.mgr.newInput(a.Input, inputSignal) {
		return nil
	}

	if f != nil && f.rotated {
		f.rotatedSignal.Merge(inputSignal)
	}
	diff := serv.corpusCover.MergeDiff(a.Cover)
	serv.stats.corpusCover.set(len(serv.corpusCover))
	if len(diff) != 0 && serv.coverFilter != nil {
		// Note: ReportGenerator is already initialized if coverFilter is enabled.
		rg, err := getReportGenerator(serv.cfg, serv.modules)
		if err != nil {
			return err
		}
		filtered := 0
		for _, pc := range diff {
			if serv.coverFilter[uint32(rg.RestorePC(pc))] != 0 {
				filtered++
			}
		}
		serv.stats.corpusCoverFiltered.add(filtered)
	}
	serv.stats.newInputs.inc()
	if rotated {
		serv.stats.rotatedInputs.inc()
	}

	if genuine {
		serv.corpusSignal.Merge(inputSignal)
		serv.stats.corpusSignal.set(serv.corpusSignal.Len())

		a.Input.Cover = nil // Don't send coverage back to all fuzzers.
		a.Input.RawCover = nil
		for _, other := range serv.fuzzers {
			if other == f || other.rotated {
				continue
			}
			other.inputs = append(other.inputs, a.Input)
		}
	}
	return nil
}

func (serv *RPCServer) Poll(a *rpctype.PollArgs, r *rpctype.PollRes) error {
	serv.stats.mergeNamed(a.Stats)

	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := serv.fuzzers[a.Name]
	if f == nil {
		// This is possible if we called shutdownInstance,
		// but already have a pending request from this instance in-flight.
		log.Logf(1, "poll: fuzzer %v is not connected", a.Name)
		return nil
	}
	newMaxSignal := serv.maxSignal.Diff(a.MaxSignal.Deserialize())
	if !newMaxSignal.Empty() {
		serv.maxSignal.Merge(newMaxSignal)
		serv.stats.maxSignal.set(len(serv.maxSignal))
		for _, f1 := range serv.fuzzers {
			if f1 == f || f1.rotated {
				continue
			}
			f1.newMaxSignal.Merge(newMaxSignal)
		}
	}
	if f.rotated {
		// Let rotated VMs run in isolation, don't send them anything.
		return nil
	}
	r.MaxSignal = f.newMaxSignal.Split(2000).Serialize()
	if a.NeedCandidates {
		r.Candidates = serv.mgr.candidateBatch(serv.batchSize)
	}
	if len(r.Candidates) == 0 {
		batchSize := serv.batchSize
		// When the fuzzer starts, it pumps the whole corpus.
		// If we do it using the final batchSize, it can be very slow
		// (batch of size 6 can take more than 10 mins for 50K corpus and slow kernel).
		// So use a larger batch initially (we use no stats as approximation of initial pump).
		const initialBatch = 50
		if len(a.Stats) == 0 && batchSize < initialBatch {
			batchSize = initialBatch
		}
		for i := 0; i < batchSize && len(f.inputs) > 0; i++ {
			last := len(f.inputs) - 1
			r.NewInputs = append(r.NewInputs, f.inputs[last])
			f.inputs[last] = rpctype.Input{}
			f.inputs = f.inputs[:last]
		}
		if len(f.inputs) == 0 {
			f.inputs = nil
		}
	}
	for _, inp := range r.NewInputs {
		f.instModules.Decanonicalize(inp.Cover)
	}
	log.Logf(4, "poll from %v: candidates=%v inputs=%v maxsignal=%v",
		a.Name, len(r.Candidates), len(r.NewInputs), len(r.MaxSignal.Elems))
	return nil
}

func (serv *RPCServer) shutdownInstance(name string) []byte {
	serv.mu.Lock()
	defer serv.mu.Unlock()

	fuzzer := serv.fuzzers[name]
	if fuzzer == nil {
		return nil
	}
	delete(serv.fuzzers, name)
	return fuzzer.machineInfo
}
