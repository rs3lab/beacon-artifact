// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"
	"regexp"
	"unicode"
	"strconv"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/pkg/log"
)

// Configuration flags for Config.Flags.
type EnvFlags uint64

// Note: New / changed flags should be added to parse_env_flags in executor.cc.
const (
	FlagDebug               EnvFlags = 1 << iota // debug output from executor
	FlagSignal                                   // collect feedback signals (coverage)
	FlagSandboxSetuid                            // impersonate nobody user
	FlagSandboxNamespace                         // use namespaces for sandboxing
	FlagSandboxAndroid                           // use Android sandboxing for the untrusted_app domain
	FlagExtraCover                               // collect extra coverage
	FlagEnableTun                                // setup and use /dev/tun for packet injection
	FlagEnableNetDev                             // setup more network devices for testing
	FlagEnableNetReset                           // reset network namespace between programs
	FlagEnableCgroups                            // setup cgroups for testing
	FlagEnableCloseFds                           // close fds after each program
	FlagEnableDevlinkPCI                         // setup devlink PCI device
	FlagEnableVhciInjection                      // setup and use /dev/vhci for hci packet injection
	FlagEnableWifi                               // setup and use mac80211_hwsim for wifi emulation
	FlagDelayKcovMmap                            // manage kcov memory in an optimized way
	FlagEnableNicVF                              // setup NIC VF device
)

// Per-exec flags for ExecOpts.Flags.
type ExecFlags uint64

const (
	FlagCollectSignal        ExecFlags = 1 << iota // collect feedback signals
	FlagCollectCover                               // collect coverage
	FlagDedupCover                                 // deduplicate coverage in executor
	FlagCollectComps                               // collect KCOV comparisons
	FlagThreaded                                   // use multiple threads to mitigate blocked syscalls
	FlagEnableCoverageFilter                       // setup and use bitmap to do coverage filter
)

type ExecOpts struct {
	Flags ExecFlags
}

// Config is the configuration for Env.
type Config struct {
	// Path to executor binary.
	Executor string

	UseShmem      bool // use shared memory instead of pipes for communication
	UseForkServer bool // use extended protocol with handshake

	// Flags are configuation flags, defined above.
	Flags      EnvFlags
	SandboxArg int

	Timeouts targets.Timeouts
}

type CallFlags uint32

const (
	CallExecuted      CallFlags = 1 << iota // was started at all
	CallFinished                            // finished executing (rather than blocked forever)
	CallBlocked                             // finished but blocked during execution
	CallFaultInjected                       // fault was injected into this call
)

type CallInfo struct {
	Flags  CallFlags
	Signal []uint32 // feedback signal, filled if FlagSignal is set
	Cover  []uint32 // per-call coverage, filled if FlagSignal is set and cover == true,
	// if dedup == false, then cov effectively contains a trace, otherwise duplicates are removed
	Comps prog.CompMap // per-call comparison operands
	Errno int          // call errno (0 if the call was successful)
}

type ProgInfo struct {
	Calls []CallInfo
	Extra CallInfo // stores Signal and Cover collected from background threads
    BPFLog []byte
    BPFRet int64
}

type Env struct {
	in   []byte
	out  []byte
	back []byte

	cmd       *command
	inFile    *os.File
	outFile   *os.File
	backFile  *os.File
	bin       []string
	linkedBin string
	pid       int
	config    *Config

	StatExecs    uint64
	StatRestarts uint64
}

const (
	outputSize = 16 << 20

	backflowSize = 16 << 20

	statusFail = 67

	// Comparison types masks taken from KCOV headers.
	compSizeMask  = 6
	compSize8     = 6
	compConstMask = 1

	extraReplyIndex = 0xffffffff // uint32(-1)
)

func SandboxToFlags(sandbox string) (EnvFlags, error) {
	switch sandbox {
	case "none":
		return 0, nil
	case "setuid":
		return FlagSandboxSetuid, nil
	case "namespace":
		return FlagSandboxNamespace, nil
	case "android":
		return FlagSandboxAndroid, nil
	default:
		return 0, fmt.Errorf("sandbox must contain one of none/setuid/namespace/android")
	}
}

func FlagsToSandbox(flags EnvFlags) string {
	if flags&FlagSandboxSetuid != 0 {
		return "setuid"
	} else if flags&FlagSandboxNamespace != 0 {
		return "namespace"
	} else if flags&FlagSandboxAndroid != 0 {
		return "android"
	}
	return "none"
}

func MakeEnv(config *Config, pid int) (*Env, error) {
	if config.Timeouts.Slowdown == 0 || config.Timeouts.Scale == 0 ||
		config.Timeouts.Syscall == 0 || config.Timeouts.Program == 0 {
		return nil, fmt.Errorf("ipc.MakeEnv: uninitialized timeouts (%+v)", config.Timeouts)
	}
	var inf, outf, backf *os.File
	var inmem, outmem, backmem []byte
	if config.UseShmem {
		var err error
		inf, inmem, err = osutil.CreateMemMappedFile(prog.ExecBufferSize)
		if err != nil {
			return nil, err
		}
		defer func() {
			if inf != nil {
				osutil.CloseMemMappedFile(inf, inmem)
			}
		}()
		outf, outmem, err = osutil.CreateMemMappedFile(outputSize)
		if err != nil {
			return nil, err
		}
		defer func() {
			if outf != nil {
				osutil.CloseMemMappedFile(outf, outmem)
			}
		}()
		backf, backmem, err = osutil.CreateMemMappedFile(backflowSize)
		if err != nil {
			return nil, err
		}
		defer func() {
			if backf != nil {
				osutil.CloseMemMappedFile(backf, backmem)
			}
		}()
	} else {
		inmem = make([]byte, prog.ExecBufferSize)
		outmem = make([]byte, outputSize)
		backmem = make([]byte, backflowSize)
	}
	env := &Env{
		in:      	inmem,
		out:     	outmem,
		back:	 	backmem,
		inFile:  	inf,
		outFile: 	outf,
		backFile: 	backf,
		bin:     	append(strings.Split(config.Executor, " "), "exec"),
		pid:     	pid,
		config:  	config,
	}
	if len(env.bin) == 0 {
		return nil, fmt.Errorf("binary is empty string")
	}
	env.bin[0] = osutil.Abs(env.bin[0]) // we are going to chdir
	// Append pid to binary name.
	// E.g. if binary is 'syz-executor' and pid=15,
	// we create a link from 'syz-executor.15' to 'syz-executor' and use 'syz-executor.15' as binary.
	// This allows to easily identify program that lead to a crash in the log.
	// Log contains pid in "executing program 15" and crashes usually contain "Comm: syz-executor.15".
	// Note: pkg/report knowns about this and converts "syz-executor.15" back to "syz-executor".
	base := filepath.Base(env.bin[0])
	pidStr := fmt.Sprintf(".%v", pid)
	const maxLen = 16 // TASK_COMM_LEN is currently set to 16
	if len(base)+len(pidStr) >= maxLen {
		// Remove beginning of file name, in tests temp files have unique numbers at the end.
		base = base[len(base)+len(pidStr)-maxLen+1:]
	}
	binCopy := filepath.Join(filepath.Dir(env.bin[0]), base+pidStr)
	if err := os.Link(env.bin[0], binCopy); err == nil {
		env.bin[0] = binCopy
		env.linkedBin = binCopy
	}
	inf = nil
	outf = nil
	backf = nil
	return env, nil
}

func (env *Env) Close() error {
	if env.cmd != nil {
		env.cmd.close()
	}
	if env.linkedBin != "" {
		os.Remove(env.linkedBin)
	}
	var err1, err2, err3 error
	if env.inFile != nil {
		err1 = osutil.CloseMemMappedFile(env.inFile, env.in)
	}
	if env.outFile != nil {
		err2 = osutil.CloseMemMappedFile(env.outFile, env.out)
	}
	if env.backFile != nil {
		err3 = osutil.CloseMemMappedFile(env.backFile, env.back)
	}
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	case err3 != nil:
		return err3
	default:
		return nil
	}
}

var rateLimit = time.NewTicker(1 * time.Second)

// Exec starts executor binary to execute program p and returns information about the execution:
// output: process output
// info: per-call info
// hanged: program hanged and was killed
// err0: failed to start the process or bug in executor itself.
func (env *Env) Exec(opts *ExecOpts, p *prog.Prog) (output []byte, info *ProgInfo, hanged bool, err0 error) {
	// Copy-in serialized program.
	progSize, err := p.SerializeForExec(env.in)
	if err != nil {
		err0 = err
		return
	}
	var progData []byte
	if !env.config.UseShmem {
		progData = env.in[:progSize]
	}
	// Zero out the first two words (ncmd and nsig), so that we don't have garbage there
	// if executor crashes before writing non-garbage there.
	for i := 0; i < 4; i++ {
		env.out[i] = 0
	}

	atomic.AddUint64(&env.StatExecs, 1)
	if env.cmd == nil {
		if p.Target.OS != targets.TestOS && targets.Get(p.Target.OS, p.Target.Arch).HostFuzzer {
			// The executor is actually ssh,
			// starting them too frequently leads to timeouts.
			<-rateLimit.C
		}
		tmpDirPath := "./"
		atomic.AddUint64(&env.StatRestarts, 1)
		env.cmd, err0 = makeCommand(env.pid, env.bin, env.config, env.inFile, env.outFile, env.backFile, env.back, env.out, tmpDirPath)
		if err0 != nil {
			return
		}
	}
	output, hanged, err0 = env.cmd.exec(opts, progData, p.PrivL)
	if err0 != nil {
		env.cmd.close()
		env.cmd = nil
		return
	}

	info, err0 = env.parseOutput(p, opts)
	if info != nil && env.config.Flags&FlagSignal == 0 {
		addFallbackSignal(p, info)
	}
	if !env.config.UseForkServer {
		env.cmd.close()
		env.cmd = nil
	}
	return
}

// addFallbackSignal computes simple fallback signal in cases we don't have real coverage signal.
// We use syscall number or-ed with returned errno value as signal.
// At least this gives us all combinations of syscall+errno.
func addFallbackSignal(p *prog.Prog, info *ProgInfo) {
	callInfos := make([]prog.CallInfo, len(info.Calls))
	for i, inf := range info.Calls {
		if inf.Flags&CallExecuted != 0 {
			callInfos[i].Flags |= prog.CallExecuted
		}
		if inf.Flags&CallFinished != 0 {
			callInfos[i].Flags |= prog.CallFinished
		}
		if inf.Flags&CallBlocked != 0 {
			callInfos[i].Flags |= prog.CallBlocked
		}
		callInfos[i].Errno = inf.Errno
	}
	p.FallbackSignal(callInfos)
	for i, inf := range callInfos {
		info.Calls[i].Signal = inf.Signal
	}
}

func findNearestNewline(s string, index int) int {
	if index > len(s) {
		return -1
	}
	substr := s[:index]
	return strings.LastIndex(substr, "\n")
}

type BpfRegType int

const (
	NOT_INIT BpfRegType = iota
	SCALAR_VALUE
	PTR_TO_CTX
	CONST_PTR_TO_MAP
	PTR_TO_MAP_VALUE
	PTR_TO_MAP_KEY
	PTR_TO_STACK
	PTR_TO_PACKET_META
	PTR_TO_PACKET
	PTR_TO_PACKET_END
	PTR_TO_FLOW_KEYS
	PTR_TO_SOCKET
	PTR_TO_SOCK_COMMON
	PTR_TO_TCP_SOCK
	PTR_TO_TP_BUFFER
	PTR_TO_XDP_SOCK
	PTR_TO_BTF_ID
	PTR_TO_MEM
	PTR_TO_BUF
	PTR_TO_FUNC
	CONST_PTR_TO_DYNPTR
)

var regTypeStr = map[BpfRegType]string{
	NOT_INIT: "?",
	SCALAR_VALUE: "scalar",
	PTR_TO_CTX: "ctx",
	CONST_PTR_TO_MAP: "map_ptr",
	PTR_TO_MAP_VALUE: "map_value",
	PTR_TO_STACK: "fp",
	PTR_TO_PACKET: "pkt",
	PTR_TO_PACKET_META: "pkt_meta",
	PTR_TO_PACKET_END: "pkt_end",
	PTR_TO_FLOW_KEYS: "flow_keys",
	PTR_TO_SOCKET: "sock",
	PTR_TO_SOCK_COMMON: "sock_common",
	PTR_TO_TCP_SOCK: "tcp_sock",
	PTR_TO_TP_BUFFER: "tp_buffer",
	PTR_TO_XDP_SOCK: "xdp_sock",
	PTR_TO_BTF_ID: "ptr_",
	PTR_TO_MEM: "mem",
	PTR_TO_BUF: "buf",
	PTR_TO_FUNC: "func",
	PTR_TO_MAP_KEY: "map_key",
	CONST_PTR_TO_DYNPTR: "dynptr_ptr",
}

type regState struct {
	regtype BpfRegType
	off int64
	preciseVal int64
	smin int64
	smax int64
	umin uint64
	umax uint64
	s32_min int
	s32_max int
	u32_min uint
	u32_max uint
	frameno int
	live bool
	id int
	ref_obj_id int
	tnum_val string
	tnum_mask string
	pktRange int
	map_uid int
	btf_id int
	mem_size int
	dynptr_id int
	subprogno int
	dynptr_type int
	first_slot int
}

func parseLog(bpfLog string) map[int]*regState {
    // Regex conds
	failCond := regexp.MustCompile(`processed`)
	exitCond := regexp.MustCompile(`btf_total_size`)
	emptyCond := regexp.MustCompile(`processed 0`)
	insnCond := regexp.MustCompile(`[0123456789]*: \([0123456789abcdefABCDEF]*\).*?;( frame[0123456789]: )?`)
	frameCond := regexp.MustCompile(`[0123456789]*: frame[0123456789]: `)
	regCond := regexp.MustCompile(`R.(_w)?=.*?;`)
	scalarCond := regexp.MustCompile(`scalar`)
	fpCond := regexp.MustCompile(`fp`)
	ctxCond := regexp.MustCompile(`ctx`)
	constScalarCond := regexp.MustCompile(`R.(_w)?=[0123456789]*;`)
	uminCond := regexp.MustCompile(`umin=`)
	umaxCond := regexp.MustCompile(`umax=`)
	sminCond := regexp.MustCompile(`smin=`)
	smaxCond := regexp.MustCompile(`smax=`)
	u32_minCond := regexp.MustCompile(`umin=`)
	u32_maxCond := regexp.MustCompile(`umax=`)
	s32_minCond := regexp.MustCompile(`smin=`)
	s32_maxCond := regexp.MustCompile(`smax=`)
	numCond := regexp.MustCompile(`[0123456789]*`)
	idCond := regexp.MustCompile(`id=[0123456789]*`)
	frameNoCond := regexp.MustCompile(`frame[0123456789]*`)
	refCond := regexp.MustCompile(`ref_obj_id=[0123456789]*`)
	tnumCond := regexp.MustCompile(`var_off=\([^|]*\|[^\)]*?\)`)
	varValCond := regexp.MustCompile(`=\([^|]*\|`)
	varMaskCond := regexp.MustCompile(`\|[^\)]*?\)`)
	rangeCond := regexp.MustCompile(`r=[0123456789]*`)
	mapUidCond := regexp.MustCompile(`map_uid=[0123456789]*`)
	btfIdCond := regexp.MustCompile(`ptr_btf_id=[0123456789]*`)
	memSizeCond := regexp.MustCompile(`mem_size=[0123456789]*`)
	dynPtrCond := regexp.MustCompile(`dynptr_id=[0123456789]*`)
	subprogCond := regexp.MustCompile(`subprogno=[0123456789]*`)
	dynPtrTypeCond := regexp.MustCompile(`dynptr_type=[0123456789]*`)
	firstSlotCond := regexp.MustCompile(`first_slot=[0123456789]*`)
	livenessCond := regexp.MustCompile(`_w`)

	rethmap := make(map[int]*regState)

	regArr := emptyCond.FindStringIndex(bpfLog)
	if len(regArr) > 0 {
		log.Logf(0, "Not an insn issue but a config issue\n")
		return nil
	}
	regArr = failCond.FindStringIndex(bpfLog)
	if len(regArr) == 0 {
		log.Logf(0, "Not a PROG_LOAD log\n")
		return nil
	}

	index := regArr[0]
	// Decrement it to get an index in the previous line
	index = findNearestNewline(bpfLog, index - 2)
	
	// We check if this is an instruction line
	// 3 cases possible:
	// 1: We find an instruction being verified
	// 2: We find the instruction, pre-verification (issues with the CFG, or the PROG_LOAD struct)
	// 3: We find some other kind of log, we must look above this line till we find the right one
	var checkString, insnString, stateString string
	errString := bpfLog[(index + 1) : index + strings.Index(bpfLog[(index + 1):], "\n") + 1]
	for {
		checkString = bpfLog[(index + 1) : index + strings.Index(bpfLog[(index + 1):], "\n") + 1]
		if len(exitCond.FindStringIndex(checkString)) > 0 {
			// Terminate
			log.Logf(0, "Not an insn issue but a config issue\n")
			break
		}
		if len(insnCond.FindStringIndex(checkString)) > 0 {
			// We will get the instruction being executed from here
			insnString = bpfLog[(index + 1) : index + strings.Index(bpfLog[(index + 1):], ";") + 1]

			// Now get the last state string
			index = findNearestNewline(bpfLog, index - 1)
			checkString = bpfLog[(index + 1) : index + strings.Index(bpfLog[(index + 1):], "\n") + 1]

			// Here we can have 2 cases
			insnRes := insnCond.FindStringIndex(checkString)
			frameRes := frameCond.FindStringIndex(checkString)
			if len(insnRes) > 0 {
				stateString = checkString[insnRes[1]:]
			} else if len(frameRes) > 0 {
				stateString = checkString[frameRes[1]:]
			} else {
				// We shouldn't have reached here
				// For now we will just abort
				log.Logf(0, "Unknown Error - couldn't fins stateString from failed program's verifier log\n")
			}
			break
		} else {
			// Look at the line above us
			index = findNearestNewline(bpfLog, index - 1)
		}
	}

	if len(errString) > 0 {
		log.Logf(0, "The errString %s\n", errString)
	}
	if len(insnString) > 0 {
		log.Logf(0, "The insnString %s\n", insnString)
	}
	if len(stateString) > 0 {
		log.Logf(0, "The stateString %s\n", stateString)
	}

	tempStateStr := stateString
	stateInd := 0
	var occurence []int
	indSum := stateInd
	var frameN int
	frameInfo := frameNoCond.FindStringIndex(stateString) 
	if len(frameInfo) > 0 {
		frameN, _ = strconv.Atoi(stateString[(frameInfo[0] + 5) : frameInfo[1]])
	}
	var val, regId, refId int
	for {
		tempStateStr = tempStateStr[stateInd:]
		val = 0
		regId = 0
		refId = 0
		occurence = regCond.FindStringIndex(tempStateStr)
		if len(occurence) == 0 { break }
		ind, err := strconv.Atoi(string(tempStateStr[occurence[0] + 1]))
		if err != nil {
			log.Logf(0, "Invalid string to int conversion")
			return rethmap
		}
		idArr := idCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]])
		if len(idArr) > 0 {
			regId, _ = strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][(idArr[0] + 3) : idArr[1]])
		}
		idNextArr := refCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]])
		if len(idNextArr) > 0 {
			refId, _ = strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][(idNextArr[0] + 11) : idNextArr[1]])
		}
	 	if (len(scalarCond.FindStringIndex((tempStateStr[occurence[0] : occurence[1]]))) > 0) || (unicode.IsDigit(rune(tempStateStr[occurence[1] - 2])) && (len(fpCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]])) == 0)) {
			rethmap[ind] = &regState{ regtype: SCALAR_VALUE, }
			if len(constScalarCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]])) > 0 {
				val, _ = strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][(strings.Index(tempStateStr, "=") + 1) : ((occurence[1] - occurence[0]) - 1)])
				rethmap[ind].preciseVal = int64(val)
			} else {
				regRes := umaxCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]]) 
				if len(regRes) > 0 {
					val, _ = strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][regRes[1] : regRes[1] + numCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]][regRes[1]:])[1]])
					rethmap[ind].umax = uint64(val)
				}
				regRes = uminCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]]) 
				if len(regRes) > 0 {
					val, _ = strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][regRes[1] : regRes[1] + numCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]][regRes[1]:])[1]])
					rethmap[ind].umin = uint64(val)
				}
				regRes = smaxCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]]) 
				if len(regRes) > 0 {
					val, _ = strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][regRes[1] : regRes[1] + numCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]][regRes[1]:])[1]])
					rethmap[ind].smax = int64(val)
				}
				regRes = sminCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]]) 
				if len(regRes) > 0 {
					val, _ = strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][regRes[1] : regRes[1] + numCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]][regRes[1]:])[1]])
					rethmap[ind].smin = int64(val)
				}
				regRes = u32_maxCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]]) 
				if len(regRes) > 0 {
					val, _ = strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][regRes[1] : regRes[1] + numCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]][regRes[1]:])[1]])
					rethmap[ind].u32_max = uint(val)
				}
				regRes = u32_minCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]]) 
				if len(regRes) > 0 {
					val, _ = strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][regRes[1] : regRes[1] + numCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]][regRes[1]:])[1]])
					rethmap[ind].u32_min = uint(val)
				}
				regRes = s32_maxCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]]) 
				if len(regRes) > 0 {
					val, _ = strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][regRes[1] : regRes[1] + numCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]][regRes[1]:])[1]])
					rethmap[ind].s32_max = val
				}
				regRes = s32_minCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]]) 
				if len(regRes) > 0 {
					val, _ = strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][regRes[1] : regRes[1] + numCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]][regRes[1]:])[1]])
					rethmap[ind].s32_min = val
				}
				regRes = s32_minCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]]) 
				if len(regRes) > 0 {
					val, _ = strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][regRes[1] : regRes[1] + numCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]][regRes[1]:])[1]])
					rethmap[ind].s32_min = val
				}
				regRes = tnumCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]])
				if len(regRes) > 0 {
					valArr := varValCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]][regRes[0] : regRes[1]])
					rethmap[ind].tnum_val = tempStateStr[occurence[0] : occurence[1]][regRes[0] : regRes[1]][(valArr[0] + 2) : (valArr[1] - 1)]
					maskArr := varMaskCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]][regRes[0] : regRes[1]])
					rethmap[ind].tnum_mask = tempStateStr[occurence[0] : occurence[1]][regRes[0] : regRes[1]][(maskArr[0] + 1) : (maskArr[1] - 1)]
				}
			}
		} else if len(fpCond.FindStringIndex((tempStateStr[occurence[0] : occurence[1]]))) > 0 {
			rethmap[ind] = &regState{ regtype: PTR_TO_STACK, }
			if (occurence[1] - strings.Index(tempStateStr, "f")) > 4 {
				val, _ = strconv.Atoi(tempStateStr[(strings.Index(tempStateStr, "f") + 2) : (occurence[1] - 1)])
				rethmap[ind].off = int64(val)
			}
		} else if len(ctxCond.FindStringIndex((tempStateStr[occurence[0] : occurence[1]]))) > 0 {
			rethmap[ind] = &regState{ regtype: PTR_TO_CTX, }
			// Not adding additional info as appaently we do not change this for now
		}
		if _, ok := rethmap[ind]; ok {
			rethmap[ind].frameno = frameN
			rethmap[ind].id = regId
			rethmap[ind].ref_obj_id = refId
			rangeArr := rangeCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]])
			if len(rangeArr) > 0 {
				rangeId, _ := strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][(rangeArr[0] + 2) : rangeArr[1]])
				rethmap[ind].pktRange = rangeId
			}
			mapUidArr := mapUidCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]])
			if len(mapUidArr) > 0 {
				mapUidId, _ := strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][(mapUidArr[0] + 8) : mapUidArr[1]])
				rethmap[ind].map_uid = mapUidId 
			}
			btfIdArr := btfIdCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]])
			if len(btfIdArr) > 0 {
				btfIdNum, _ := strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][(btfIdArr[0] + 11) : btfIdArr[1]])
				rethmap[ind].btf_id = btfIdNum 
			}
			memSizeArr := memSizeCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]])
			if len(memSizeArr) > 0 {
				memSizeNum, _ := strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][(memSizeArr[0] + 9) : memSizeArr[1]])
				rethmap[ind].mem_size = memSizeNum
			}
			dynPtrArr := dynPtrCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]])
			if len(dynPtrArr) > 0 {
				dynPtrId, _ := strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][(dynPtrArr[0] + 10) : dynPtrArr[1]])
				rethmap[ind].dynptr_id = dynPtrId
			}
			sProgArr := subprogCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]])
			if len(sProgArr) > 0 {
				sProgNo, _ := strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][(sProgArr[0] + 10) : sProgArr[1]])
				rethmap[ind].subprogno = sProgNo
			}
			dPtrTypArr := dynPtrTypeCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]])
			if len(dPtrTypArr) > 0 {
				dPtrTyp, _ := strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][(dPtrTypArr[0] + 12) : dPtrTypArr[1]])
				rethmap[ind].dynptr_type = dPtrTyp
			}
			firstSlotArr := firstSlotCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]])
			if len(firstSlotArr) > 0 {
				fSlot, _ := strconv.Atoi(tempStateStr[occurence[0] : occurence[1]][(firstSlotArr[0] + 11) : firstSlotArr[1]])
				rethmap[ind].first_slot = fSlot
			}
			liveArr := livenessCond.FindStringIndex(tempStateStr[occurence[0] : occurence[1]])
			if len(liveArr) > 0 {
				rethmap[ind].live = true
			}
		}
		stateInd = occurence[1]
		indSum += stateInd
		fmt.Fprintf(os.Stderr, "%d %d\n", stateInd, len(stateString))
		if indSum >= len(stateString) { break }
	}
	for k, v := range rethmap {
		s := fmt.Sprintf("Key: %v, Value: %v\n", k, v)
		fmt.Fprintf(os.Stderr, "%s\n", s)
	}

	return rethmap
}

func (env *Env) parseOutput(p *prog.Prog, opts *ExecOpts) (*ProgInfo, error) {
	out := env.out
	back := env.back
	ncmd, ok := readUint32(&out)
	if !ok {
		return nil, fmt.Errorf("failed to read number of calls")
	}

	info := &ProgInfo{Calls: make([]CallInfo, len(p.Calls))}
	extraParts := make([]CallInfo, 0)
    // Read out BPF log and program upload ret value
    retval, _ := readUint64(&back)
    info.BPFRet = int64(retval)
    logSz, _ := readUint32(&back)
	log.Logf(0, "DEBUG ret: %lx, %x\n", info.BPFRet, logSz)
    //bpfLog := strings.Replace(string(back), "\x00", "", -1)
	info.BPFLog = append(make([]byte,0), back[:logSz]...)
	//parseLog(bpfLog)
	for i := uint32(0); i < ncmd; i++ {
		if len(out) < int(unsafe.Sizeof(callReply{})) {
			return nil, fmt.Errorf("failed to read call %v reply", i)
		}
		reply := *(*callReply)(unsafe.Pointer(&out[0]))
		out = out[unsafe.Sizeof(callReply{}):]
		var inf *CallInfo
		if reply.magic != outMagic {
			return nil, fmt.Errorf("bad reply magic 0x%x", reply.magic)
		}
		if reply.index != extraReplyIndex {
			if int(reply.index) >= len(info.Calls) {
				return nil, fmt.Errorf("bad call %v index %v/%v", i, reply.index, len(info.Calls))
			}
			if num := p.Calls[reply.index].Meta.ID; int(reply.num) != num {
				return nil, fmt.Errorf("wrong call %v num %v/%v", i, reply.num, num)
			}
			inf = &info.Calls[reply.index]
			if inf.Flags != 0 || inf.Signal != nil {
				return nil, fmt.Errorf("duplicate reply for call %v/%v/%v", i, reply.index, reply.num)
			}
			inf.Errno = int(reply.errno)
			inf.Flags = CallFlags(reply.flags)
		} else {
			extraParts = append(extraParts, CallInfo{})
			inf = &extraParts[len(extraParts)-1]
		}
		if inf.Signal, ok = readUint32Array(&out, reply.signalSize); !ok {
			return nil, fmt.Errorf("call %v/%v/%v: signal overflow: %v/%v",
				i, reply.index, reply.num, reply.signalSize, len(out))
		}
		if inf.Cover, ok = readUint32Array(&out, reply.coverSize); !ok {
			return nil, fmt.Errorf("call %v/%v/%v: cover overflow: %v/%v",
				i, reply.index, reply.num, reply.coverSize, len(out))
		}
		comps, err := readComps(&out, reply.compsSize)
		if err != nil {
			return nil, err
		}
		inf.Comps = comps
	}
	if len(extraParts) == 0 {
		return info, nil
	}
	info.Extra = convertExtra(extraParts, opts.Flags&FlagDedupCover > 0)
	return info, nil
}

func convertExtra(extraParts []CallInfo, dedupCover bool) CallInfo {
	var extra CallInfo
	if dedupCover {
		extraCover := make(cover.Cover)
		for _, part := range extraParts {
			extraCover.Merge(part.Cover)
		}
		extra.Cover = extraCover.Serialize()
	} else {
		for _, part := range extraParts {
			extra.Cover = append(extra.Cover, part.Cover...)
		}
	}
	extraSignal := make(signal.Signal)
	for _, part := range extraParts {
		extraSignal.Merge(signal.FromRaw(part.Signal, 0))
	}
	extra.Signal = make([]uint32, len(extraSignal))
	i := 0
	for s := range extraSignal {
		extra.Signal[i] = uint32(s)
		i++
	}
	return extra
}

func readComps(outp *[]byte, compsSize uint32) (prog.CompMap, error) {
	if compsSize == 0 {
		return nil, nil
	}
	compMap := make(prog.CompMap)
	for i := uint32(0); i < compsSize; i++ {
		typ, ok := readUint32(outp)
		if !ok {
			return nil, fmt.Errorf("failed to read comp %v", i)
		}
		if typ > compConstMask|compSizeMask {
			return nil, fmt.Errorf("bad comp %v type %v", i, typ)
		}
		var op1, op2 uint64
		var ok1, ok2 bool
		if typ&compSizeMask == compSize8 {
			op1, ok1 = readUint64(outp)
			op2, ok2 = readUint64(outp)
		} else {
			var tmp1, tmp2 uint32
			tmp1, ok1 = readUint32(outp)
			tmp2, ok2 = readUint32(outp)
			op1, op2 = uint64(tmp1), uint64(tmp2)
		}
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("failed to read comp %v op", i)
		}
		if op1 == op2 {
			continue // it's useless to store such comparisons
		}
		compMap.AddComp(op2, op1)
		if (typ & compConstMask) != 0 {
			// If one of the operands was const, then this operand is always
			// placed first in the instrumented callbacks. Such an operand
			// could not be an argument of our syscalls (because otherwise
			// it wouldn't be const), thus we simply ignore it.
			continue
		}
		compMap.AddComp(op1, op2)
	}
	return compMap, nil
}

func readUint32(outp *[]byte) (uint32, bool) {
	out := *outp
	if len(out) < 4 {
		return 0, false
	}
	v := prog.HostEndian.Uint32(out)
	*outp = out[4:]
	return v, true
}

func readUint64(outp *[]byte) (uint64, bool) {
	out := *outp
	if len(out) < 8 {
		return 0, false
	}
	v := prog.HostEndian.Uint64(out)
	*outp = out[8:]
	return v, true
}

func readUint32Array(outp *[]byte, size uint32) ([]uint32, bool) {
	if size == 0 {
		return nil, true
	}
	out := *outp
	if int(size)*4 > len(out) {
		return nil, false
	}
	var res []uint32
	hdr := (*reflect.SliceHeader)((unsafe.Pointer(&res)))
	hdr.Data = uintptr(unsafe.Pointer(&out[0]))
	hdr.Len = int(size)
	hdr.Cap = int(size)
	*outp = out[size*4:]
	return res, true
}

type command struct {
	pid      int
	config   *Config
	timeout  time.Duration
	cmd      *exec.Cmd
	dir      string
	readDone chan []byte
	exited   chan error
	inrp     *os.File
	outwp    *os.File
	outmem   []byte
	backmem  []byte
}

const (
	inMagic  = uint64(0xbadc0ffeebadface)
	outMagic = uint32(0xbadf00d)
)

type handshakeReq struct {
	magic      uint64
	flags      uint64 // env flags
	pid        uint64
	sandboxArg uint64
}

type handshakeReply struct {
	magic uint32
}

type executeReq struct {
	magic            uint64
	envFlags         uint64 // env flags
	execFlags        uint64 // exec flags
	pid              uint64
	syscallTimeoutMS uint64
	programTimeoutMS uint64
	slowdownScale    uint64
	progSize         uint64
	// This structure is followed by a serialized test program in encodingexec format.
	// Both when sent over a pipe or in shared memory.
}

type executeReply struct {
	magic uint32
	// If done is 0, then this is call completion message followed by callReply.
	// If done is 1, then program execution is finished and status is set.
	done   uint32
	status uint32
}

type callReply struct {
	magic      uint32
	index      uint32 // call index in the program
	num        uint32 // syscall number (for cross-checking)
	errno      uint32
	flags      uint32 // see CallFlags
	signalSize uint32
	coverSize  uint32
	compsSize  uint32
	// signal/cover/comps follow
}

func makeCommand(pid int, bin []string, config *Config, inFile, outFile, backFile *os.File, backmem, outmem []byte,
	tmpDirPath string) (*command, error) {
	dir, err := os.MkdirTemp(tmpDirPath, "syzkaller-testdir")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %v", err)
	}
	dir = osutil.Abs(dir)

	timeout := config.Timeouts.Program
	if config.UseForkServer {
		// Executor has an internal timeout and protects against most hangs when fork server is enabled,
		// so we use quite large timeout. Executor can be slow due to global locks in namespaces
		// and other things, so let's better wait than report false misleading crashes.
		timeout *= 10
	}

	c := &command{
		pid:     pid,
		config:  config,
		timeout: timeout,
		dir:     dir,
		outmem:  outmem,
		backmem: backmem,
	}
	defer func() {
		if c != nil {
			c.close()
		}
	}()

	if err := os.Chmod(dir, 0777); err != nil {
		return nil, fmt.Errorf("failed to chmod temp dir: %v", err)
	}

	// Output capture pipe.
	rp, wp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	defer wp.Close()

	// executor->ipc command pipe.
	inrp, inwp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	defer inwp.Close()
	c.inrp = inrp

	// ipc->executor command pipe.
	outrp, outwp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	defer outrp.Close()
	c.outwp = outwp

	c.readDone = make(chan []byte, 1)

	cmd := osutil.Command(bin[0], bin[1:]...)
	if inFile != nil && outFile != nil && backFile != nil {
		cmd.ExtraFiles = []*os.File{inFile, outFile, backFile}
	}
	cmd.Dir = dir
	// Tell ASAN to not mess with our NONFAILING.
	cmd.Env = append(append([]string{}, os.Environ()...), "ASAN_OPTIONS=handle_segv=0 allow_user_segv_handler=1")
	cmd.Stdin = outrp
	cmd.Stdout = inwp
	if config.Flags&FlagDebug != 0 {
		close(c.readDone)
		cmd.Stderr = os.Stdout
	} else {
		cmd.Stderr = wp
		go func(c *command) {
			// Read out output in case executor constantly prints something.
			const bufSize = 128 << 10
			output := make([]byte, bufSize)
			var size uint64
			for {
				n, err := rp.Read(output[size:])
				if n > 0 {
					size += uint64(n)
					if size >= bufSize*3/4 {
						copy(output, output[size-bufSize/2:size])
						size = bufSize / 2
					}
				}
				if err != nil {
					rp.Close()
					c.readDone <- output[:size]
					close(c.readDone)
					return
				}
			}
		}(c)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start executor binary: %v", err)
	}
	c.exited = make(chan error, 1)
	c.cmd = cmd
	go func(c *command) {
		err := c.cmd.Wait()
		c.exited <- err
		close(c.exited)
		// Avoid a livelock if cmd.Stderr has been leaked to another alive process.
		rp.SetDeadline(time.Now().Add(5 * time.Second))
	}(c)
	wp.Close()
	// Note: we explicitly close inwp before calling handshake even though we defer it above.
	// If we don't do it and executor exits before writing handshake reply,
	// reading from inrp will hang since we hold another end of the pipe open.
	inwp.Close()

	if c.config.UseForkServer {
		if err := c.handshake(); err != nil {
			return nil, err
		}
	}
	tmp := c
	c = nil // disable defer above
	return tmp, nil
}

func (c *command) close() {
	if c.cmd != nil {
		c.cmd.Process.Kill()
		c.wait()
	}
	osutil.RemoveAll(c.dir)
	if c.inrp != nil {
		c.inrp.Close()
	}
	if c.outwp != nil {
		c.outwp.Close()
	}
}

// handshake sends handshakeReq and waits for handshakeReply.
func (c *command) handshake() error {
	req := &handshakeReq{
		magic:      inMagic,
		flags:      uint64(c.config.Flags),
		pid:        uint64(c.pid),
		sandboxArg: uint64(c.config.SandboxArg),
	}
	reqData := (*[unsafe.Sizeof(*req)]byte)(unsafe.Pointer(req))[:]
	if _, err := c.outwp.Write(reqData); err != nil {
		return c.handshakeError(fmt.Errorf("failed to write control pipe: %v", err))
	}

	read := make(chan error, 1)
	go func() {
		reply := &handshakeReply{}
		replyData := (*[unsafe.Sizeof(*reply)]byte)(unsafe.Pointer(reply))[:]
		if _, err := io.ReadFull(c.inrp, replyData); err != nil {
			read <- err
			return
		}
		if reply.magic != outMagic {
			read <- fmt.Errorf("bad handshake reply magic 0x%x", reply.magic)
			return
		}
		read <- nil
	}()
	// Sandbox setup can take significant time.
	timeout := time.NewTimer(time.Minute * c.config.Timeouts.Scale)
	select {
	case err := <-read:
		timeout.Stop()
		if err != nil {
			return c.handshakeError(err)
		}
		return nil
	case <-timeout.C:
		return c.handshakeError(fmt.Errorf("not serving"))
	}
}

func (c *command) handshakeError(err error) error {
	c.cmd.Process.Kill()
	output := <-c.readDone
	err = fmt.Errorf("executor %v: %v\n%s", c.pid, err, output)
	c.wait()
	return err
}

func (c *command) wait() error {
	return <-c.exited
}

func (c *command) exec(opts *ExecOpts, progData []byte, PrivL uint64) (output []byte, hanged bool, err0 error) {
	req := &executeReq{
		magic:            inMagic,
		envFlags:         uint64(c.config.Flags),
		execFlags:        uint64(opts.Flags) | (PrivL << 6),
		pid:              uint64(c.pid),
		syscallTimeoutMS: uint64(c.config.Timeouts.Syscall / time.Millisecond),
		programTimeoutMS: uint64(c.config.Timeouts.Program / time.Millisecond),
		slowdownScale:    uint64(c.config.Timeouts.Scale),
		progSize:         uint64(len(progData)),
	}
	reqData := (*[unsafe.Sizeof(*req)]byte)(unsafe.Pointer(req))[:]
	if _, err := c.outwp.Write(reqData); err != nil {
		output = <-c.readDone
		err0 = fmt.Errorf("executor %v: failed to write control pipe: %v", c.pid, err)
		return
	}
	if progData != nil {
		if _, err := c.outwp.Write(progData); err != nil {
			output = <-c.readDone
			err0 = fmt.Errorf("executor %v: failed to write control pipe: %v", c.pid, err)
			return
		}
	}
	// At this point program is executing.

	done := make(chan bool)
	hang := make(chan bool)
	go func() {
		t := time.NewTimer(c.timeout)
		select {
		case <-t.C:
			c.cmd.Process.Kill()
			hang <- true
		case <-done:
			t.Stop()
			hang <- false
		}
	}()
	exitStatus := -1
	completedCalls := (*uint32)(unsafe.Pointer(&c.outmem[0]))
	outmem := c.outmem[4:]
	for {
		reply := &executeReply{}
		replyData := (*[unsafe.Sizeof(*reply)]byte)(unsafe.Pointer(reply))[:]
		if _, err := io.ReadFull(c.inrp, replyData); err != nil {
			break
		}
		if reply.magic != outMagic {
			fmt.Fprintf(os.Stderr, "executor %v: got bad reply magic 0x%x\n", c.pid, reply.magic)
			os.Exit(1)
		}
		if reply.done != 0 {
			exitStatus = int(reply.status)
			break
		}
		callReply := &callReply{}
		callReplyData := (*[unsafe.Sizeof(*callReply)]byte)(unsafe.Pointer(callReply))[:]
		if _, err := io.ReadFull(c.inrp, callReplyData); err != nil {
			break
		}
		if callReply.signalSize != 0 || callReply.coverSize != 0 || callReply.compsSize != 0 {
			// This is unsupported yet.
			fmt.Fprintf(os.Stderr, "executor %v: got call reply with coverage\n", c.pid)
			os.Exit(1)
		}
		copy(outmem, callReplyData)
		outmem = outmem[len(callReplyData):]
		*completedCalls++
	}
	close(done)
	if exitStatus == 0 {
		// Program was OK.
		<-hang
		return
	}
	c.cmd.Process.Kill()
	output = <-c.readDone
	if err := c.wait(); <-hang {
		hanged = true
		if err != nil {
			output = append(output, err.Error()...)
			output = append(output, '\n')
		}
		return
	}
	if exitStatus == -1 {
		exitStatus = osutil.ProcessExitStatus(c.cmd.ProcessState)
	}
	// Ignore all other errors.
	// Without fork server executor can legitimately exit (program contains exit_group),
	// with fork server the top process can exit with statusFail if it wants special handling.
	if exitStatus == statusFail {
		err0 = fmt.Errorf("executor %v: exit status %d\n%s", c.pid, exitStatus, output)
	}
	return
}
