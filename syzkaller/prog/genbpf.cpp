#include "genbpf.hpp"
#include "genrand.hpp"
#include "genmap.hpp"
#include "bpf_insn_constraint.hpp"
#include "genbpfcimport.hpp"
#include "genbpfsuppress.hpp"
#include "bpf-info/helper_to_map.h"

// Need this to propagate map->types
union bpf_attr *mapAttrs;

int MAXINSNSIZE = (MAX_CFG_VERTS * BBMAX) * sizeof(struct bpf_insn);
int MAXFUNCINFOSIZE = (MAX_PSEUDO_FUNCS + 1) * sizeof(struct bpf_func_info);
int MAXLINEINFOSIZE = 0;
int MAXBTFSIZE = 1024;
int MAXMAPNUM = 5;
int MAXFDARRAYSIZE = (MAXMAPNUM + 1) * sizeof(int);
int UNIONSIZE = sizeof(union bpf_attr);

char genProgFlags(bpf_attr *progAttr) {
    char res = 0;
    if (rand() % 2)
        res |= (rand() % 2 ? BPF_F_STRICT_ALIGNMENT : BPF_F_ANY_ALIGNMENT);
    res |= (rand() % 2 ? BPF_F_TEST_RND_HI32 : 0);
    res |= (rand() % 2 ? BPF_F_TEST_STATE_FREQ : 0);
    if (progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_SYSCALL ||
		progType == BPF_PROG_TYPE_STRUCT_OPS || progType == BPF_PROG_TYPE_KPROBE)
		res |= BPF_F_SLEEPABLE;
    if (progType == BPF_PROG_TYPE_TRACING &&
		(progAttr->expected_attach_type == BPF_TRACE_ITER || progAttr->expected_attach_type == BPF_MODIFY_RETURN ||
		 progAttr->expected_attach_type == BPF_TRACE_FEXIT || progAttr->expected_attach_type == BPF_TRACE_FENTRY)
	)
		res |= BPF_F_SLEEPABLE;
    return res;
}

int GenBPFProg(char *bpfProgAttr, char *bpfMapAttrs, char *bpfBtfAttr) {

    struct btf *btf = btf__new_empty();
    __u32 *sz = new __u32;

    // Setup type id for types 
    // Add int as type type_id 1
    btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
    // add ptr type_id 2
    btf__add_ptr(btf, 1);
    // Add int as type type_id 3
    btf__add_int(btf, "char", 1, BTF_INT_CHAR);
    // type_id 4
    btf__add_float(btf, "octal", 2);
    // type_id 5
	btf__add_float(btf,"long double", 16);
    // type_id 6
	btf__add_struct(btf, "int_32", 32);
    // type_id 7
	btf__add_struct(btf, "int_64", 64);
    // type_id 8
	btf__add_struct(btf, "int_128", 128);
    // TODO: try int with bit_offset != 0 for more coverage ?

    int type_id = btf__add_func_proto(btf, 1);

    if( type_id <= 0){
        fprintf(stderr, "invalid type id %d generated for main func proto\n", type_id);
        // TODO: better error values
        return -1;
    }

    type_id = btf__add_func(btf, "main", BTF_FUNC_STATIC, type_id);
    if( type_id <= 0){
        fprintf(stderr, "invalid type id %d generated for main func\n", type_id);
        // TODO: better error values
        return -1;
    } 
    func_type_id[0] = type_id;
    // Number of basic blocks
    int verts = randRange(1, MAX_PROG_BLOCKS);
    // number of sub functions
    pseudoFuncs = randRange(0, MAX_PSEUDO_FUNCS);


    union bpf_attr *btfAttrs = (union bpf_attr *)bpfBtfAttr;
	union bpf_attr *progAttr = (union bpf_attr *)bpfProgAttr;
    mapAttrs = (union bpf_attr *)bpfMapAttrs;

    progType = (rand() % NO_OF_PROGTYPE);
    // Don't want to handle 'Tracing programs must provide btf_id' for now 
    while(progType == BPF_PROG_TYPE_TRACING || progType == BPF_PROG_TYPE_LSM || progType == BPF_PROG_TYPE_EXT){
        progType = (rand() % NO_OF_PROGTYPE);
    }

    progAttr->prog_type = progType;

    memcpy((void*)progAttr->license, licenseString, sizeof(licenseString));

	progAttr->log_level = 2;
	progAttr->log_size = 1024 * 1024;
    progAttr->prog_btf_fd = BTF_FD_IDX;

    if ((rand() % 100) < RARE_CHANCE) {
        switch(rand() % 4) {
            case 0:
                progAttr->expected_attach_type = BPF_TRACE_FENTRY;
                break;
            case 1:
                progAttr->expected_attach_type = BPF_TRACE_FEXIT;
                break;
            case 2:
                progAttr->expected_attach_type = BPF_MODIFY_RETURN;
                break;
            case 3:
                progAttr->expected_attach_type = BPF_TRACE_ITER;
                break;
        }
    }
    progAttr->prog_flags = genProgFlags(progAttr);

    if ((progAttr->prog_type == BPF_PROG_TYPE_UNSPEC) || (progAttr->prog_type == BPF_PROG_TYPE_STRUCT_OPS) || (progAttr->prog_type == BPF_PROG_TYPE_EXT))
        progtype_allows_helpers = false;
    else progtype_allows_helpers = true;

    // Initialize bpf map attributes

    for (int i = 0; i < MAXMAPNUM; i++) {
        union bpf_attr *mapAttr = mapAttrs + i;
        createOneMap(mapAttr, i);
    }

    initCFG();

    for (int i = 0; i < MAX_PROG_BLOCKS; i++) {
        populationBB[i] = randRange(MININSNS, NINSNS) + 3;
        for (int j = 0; j < sizeof(regs); j++)
            basicBlockStates[i][j].type = NOT_INIT;
    }

    for (int i = 0; i < MAX_PSEUDO_FUNCS; i++) {
        populationPseudo[i] = randRange(MININSNS, NINSNS) + 3;
        for (int j = 0; j < sizeof(regs); j++)
            protoStates[i][j].type = NOT_INIT;
    };

    struct bpf_insn progBytecode[MAX_CFG_VERTS][BBMAX];
    memset(progBytecode, 0, BBMAX * MAX_CFG_VERTS * sizeof(struct bpf_insn));
    genCFG(cfg, verts);

    for (int i = 0; i < MAX_PSEUDO_FUNCS; i++) isFuncUsed[i] = false;

    fprintf(stderr, "generating %d pseudo functions\n", pseudoFuncs);
    makePseudoFuncs(btf, progBytecode, verts, pseudoFuncs, MAXMAPNUM);
    rearrangeProg(progBytecode, cfg, verts, MAXMAPNUM);

    int final_insn_cnt = 0, final_ind = 0;
    for (int i = 0; i < verts; i++)
        final_insn_cnt += populationBB[i];
        
    int actual_funcs = 0; 
    for (int i = 0; i < MAX_PSEUDO_FUNCS; i++) {
        actual_funcs += isFuncUsed[i];
		if (!isFuncUsed[i]){
            memset(&(progBytecode[MAX_PROG_BLOCKS+i][0]), 0, BBMAX * sizeof(struct bpf_insn));
        }
    }
	
    
    // main function
    struct bpf_func_info* func_proto_info =  (struct bpf_func_info*) progAttr->func_info;
    func_proto_info[0].insn_off = 0;
    func_proto_info[0].type_id = func_type_id[0];
    
    int cumsum = 0;
    for (int i = 0; i < verts; i++) cumsum += populationBB[i];
    
    int func_ind = 0;
    for (int i = 0; i < MAX_PSEUDO_FUNCS; i++) {
        if (isFuncUsed[i]) {
            func_proto_info[i+1].insn_off = cumsum;
            func_proto_info[i+1].type_id = func_type_id[i+1];
            cumsum += populationPseudo[i];
            func_ind++;
        } else {
            break;
        }
    }
    progAttr->func_info_rec_size = sizeof(struct bpf_func_info);
    //progAttr->func_info = (__u64)((struct bpf_func_info *)progAttr->func_info);

    progAttr->func_info_cnt = func_ind + 1 ;
    // fprintf(stderr, "The progtype is %d\n", progType);
    // fprintf(stderr, "actual_funcs is %d\n", actual_funcs);
    // fprintf(stderr, "func_info_cnt is %d\n", func_ind + 1);

    // funcInfoSize = progAttr->func_info_cnt * sizeof(struct bpf_func_info);

    bool forceNext = false;
    // Copy non null instructions
    for (int i = 0; i < (MAX_CFG_VERTS * BBMAX); i++) {
        if (progBytecode[i / BBMAX][i % BBMAX].code == 0x0 && !forceNext)
            continue;
        progBytecode[final_ind / BBMAX][final_ind % BBMAX] = progBytecode[i / BBMAX][i % BBMAX];
        final_ind++;
        if (progBytecode[i / BBMAX][i % BBMAX].code == 0x18) forceNext = true; else forceNext = false;
    }
    /*
    for (int i = 0; i < progAttr->func_info_cnt; i++)
    {
        fprintf(stderr, "func_proto_info %d has offset %d and type_id %d\n", i, func_proto_info[i].insn_off, func_proto_info[i].type_id);
    }
    */

    const void *fPtr = btf__raw_data(btf, sz);
    memcpy((void *)btfAttrs->btf, fPtr, *sz);
    btf__free(btf);
    //btfAttrs->btf = (__u64)(fPtr);
    btfAttrs->btf_size = *sz;
    btfAttrs->btf_log_size = 1024 * 1024;
    btfAttrs->btf_log_level = 2;

    // printProg(final_ind, progBytecode);
    memcpy((void *) progAttr->insns, progBytecode, final_ind * sizeof(bpf_insn));

    progAttr->insn_cnt = final_ind;

    // Indicate how many maps there are in fd_array 0 for the executor 
    ((int *)progAttr->fd_array)[0] = MAXMAPNUM;

    return MAXMAPNUM;
}

void shuffle(int *arr, int num) {
    for (int i = 0; i < num - 1; i++) {
        int j = i + rand() / (RAND_MAX / (num - i) + 1);
        swap(arr + j, arr + i);
    }
}

bool isLeaf(int cfgMat[][MAX_PROG_BLOCKS], int idx) {
    for (int i = 0; i < MAX_PROG_BLOCKS; i++) {
        if (cfgMat[idx][i])
            return false;
    }

    return true;
}

bool isConditional(int cfgMat[][MAX_PROG_BLOCKS], int idx) {
    int res = 0;
    for (int i = 0; i < MAX_PROG_BLOCKS; i++)
        res += cfgMat[idx][i];

    return (res == 2);
}

int genCFG(int cfgMat[][MAX_PROG_BLOCKS], int vert) {
    if (vert > MAX_PROG_BLOCKS || vert < 2)
        return -1;
    
    if (vert == 2) {
        cfgMat[0][1] = 1;
        return -1;
    }
    
    int vertices[vert - 1];
    for (int i = 0; i < vert - 1; i++)
        vertices[i] = i + 1;
    
    shuffle(vertices, vert - 1);

    int parents[vert - 1];
    int parents_size = 1;
    parents[0] = 0;

    for (int i = 0; i < vert - 1; i++) {
        int parent = parents[0];
        for (int j = 0; j < parents_size-1; j++)
            parents[j] = parents[j+1];
        parents_size--;
        
        int vertex = vertices[i];
        cfgMat[parent][vertex] = SET_EDGE;
        
        parents[parents_size++] = vertex;
        parents[parents_size++] = vertex;
    }

    // todo: remove test

    int firstLeaf = 0;  // 0 can never be the leaf as it is the root
    for (int i = 0; i < vert; i++) {
        if (!firstLeaf && isLeaf(cfgMat, i)) {
            firstLeaf = i;
            continue;
        }

        if (isLeaf(cfgMat, i))
            cfgMat[i][firstLeaf] = SET_EDGE;
    }

    return firstLeaf;   // returns the end BB
}

void findIncoming(int idx, int *res) {
    for (int i = 0; i < MAX_PROG_BLOCKS; i++)
        res[i] = -1;
    
    int arrI = 0;

    for (int i = 0; i < MAX_PROG_BLOCKS; i++) {
        if (cfg[i][idx])
            res[arrI++] = i;
    }
}

void findOutgoing(int idx, int *stack, int &stack_cnt) {
    for (int i = 0; i < MAX_PROG_BLOCKS; i++) {
        if (cfg[idx][i])
            stack[stack_cnt++] = i;
    }
}

struct regState *genInputState(int bbIdx, struct regState *regStates) {
    // Root node special case
    if (!bbIdx) {
        for (int i = 0; i < 11; i++)
            regStates[i].type = NOT_INIT;
        regStates[BPF_REG_1].type = PTR_TO_CTX;
        regStates[BPF_REG_10].type = PTR_TO_STACK;
        return regStates;
    }

    for (int i = 0; i < 11; i++)
        regStates[i].type = SCALAR_VALUE;

    int inEdges[MAX_PROG_BLOCKS];
    int inEdgeNum = 0;;
    findIncoming(bbIdx, inEdges);

    for (int i = 0; i < MAX_PROG_BLOCKS; i++) {
        if (inEdges[i] == -1) {
            // This works, as inEdges will never be fully populated
            inEdgeNum = i;
            break;
        }
    }

    // If just one incoming edge, input state for this is the output state for that BB
    // Deep copy
    if (inEdgeNum == 1) {
        for (int i = 0; i < 11; i++)
            regStates[i].type = basicBlockStates[inEdges[0]][i].type;
    
        return regStates;
    }
    
    // Check for mismatches and mark them NOT_INIT (These are up for grabs - Their state is inconsistent)
    for (int i = 1; i < inEdgeNum; i++) {
        for (int j = 0; j < 11; j++) {
            if (basicBlockStates[inEdges[i - 1]][j].type == basicBlockStates[inEdges[i]][j].type && regStates[j].type != NOT_INIT)
                regStates[j].type = basicBlockStates[inEdges[i]][j].type;
            else
                regStates[j].type = NOT_INIT;
        }
    }   

    return regStates;
}

void makePseudoFuncs(struct btf *btf, struct bpf_insn progBytecode[][BBMAX], int verts, int pseudoNum, int maxMaps) {
    // We are not allowed to touch R7 - R9
    struct regState reggaeStates[sizeof(regs)];
    int cnt, max_cnt;
    for (int funcNum = 0; funcNum < pseudoNum; funcNum++) {
        //can assume initial state of regs
        for (int j = 0; j < 10; j++) {
            reggaeStates[j].type = NOT_INIT;
        }
        reggaeStates[1].type = PTR_TO_CTX;
        reggaeStates[10].type = PTR_TO_STACK;

        int type_id = btf__add_func_proto(btf, 1);
        if( type_id <= 0){
            fprintf(stderr, "invalid type id %d generated for %s func proto\n", type_id, funcNames[funcNum]);
            // TODO: better error values 
            return;
        }

        // First arg is PTR_TO_CTX
        int argTyp;
        switch (rand() % 100) {
            case 95 ... 99:
                argTyp = rand() % 3;
                switch (argTyp) {
                    case 0:
                        reggaeStates[BPF_REG_5].type = SCALAR_VALUE;
                        break;
                    case 1:
                        reggaeStates[BPF_REG_5].type = PTR_TO_STACK;
                        break;
                    case 2:
                        reggaeStates[BPF_REG_5].type = PTR_TO_CTX;
                        break;
                }
            case 80 ... 94:
                argTyp = rand() % 3;
                switch (argTyp) {
                    case 0:
                        reggaeStates[BPF_REG_4].type = SCALAR_VALUE;
                        break;
                    case 1:
                        reggaeStates[BPF_REG_4].type = PTR_TO_STACK;
                        break;
                    case 2:
                        reggaeStates[BPF_REG_4].type = PTR_TO_CTX;
                        break;
                }
            case 60 ... 79:
                argTyp = rand() % 3;
                switch (argTyp) {
                    case 0:
                        reggaeStates[BPF_REG_3].type = SCALAR_VALUE;
                        break;
                    case 1:
                        reggaeStates[BPF_REG_3].type = PTR_TO_STACK;
                        break;
                    case 2:
                        reggaeStates[BPF_REG_3].type = PTR_TO_CTX;
                        break;
                }
            case 30 ... 59:
                argTyp = rand() % 3;
                switch (argTyp) {
                    case 0:
                        reggaeStates[BPF_REG_2].type = SCALAR_VALUE;
                        break;
                    case 1:
                        reggaeStates[BPF_REG_2].type = PTR_TO_STACK;
                        break;
                    case 2:
                        reggaeStates[BPF_REG_2].type = PTR_TO_CTX;
                        break;
                }
            case 0 ... 29:
                break;
        }

        for (int j = BPF_REG_1; j < BPF_REG_6; j++) {
            if (!reggaeStates[j].type) break;
            switch (j) {
                case BPF_REG_1:
                    if (reggaeStates[j].type == SCALAR_VALUE) btf__add_func_param(btf, "p1", 1);
                    else btf__add_func_param(btf, "p1", 2);
                    break;
                case BPF_REG_2:
                    if (reggaeStates[j].type == SCALAR_VALUE) btf__add_func_param(btf, "p2", 1);
                    else btf__add_func_param(btf, "p2", 2);
                    break;
                case BPF_REG_3:
                    if (reggaeStates[j].type == SCALAR_VALUE) btf__add_func_param(btf, "p3", 1);
                    else btf__add_func_param(btf, "p3", 2);
                    break;
                case BPF_REG_4:
                    if (reggaeStates[j].type == SCALAR_VALUE) btf__add_func_param(btf, "p4", 1);
                    else btf__add_func_param(btf, "p4", 2);
                    break;
                case BPF_REG_5:
                    if (reggaeStates[j].type == SCALAR_VALUE) btf__add_func_param(btf, "p5", 1);
                    else btf__add_func_param(btf, "p5", 2);
                    break;
            }
        }

        // Making the btf_func entry for this
        // Needs to be after we added all the func param
        type_id = btf__add_func(btf, funcNames[funcNum], BTF_FUNC_STATIC, type_id);
        if( type_id <= 0){
            fprintf(stderr, "invalid type id %d generated for %s func\n", type_id, funcNames[funcNum]);
            // TODO: better error values
            return;
        }
        func_type_id[funcNum+1] = type_id ;

        for (int j = 0; j < sizeof(regs); j++) {
            protoStates[funcNum][j].type = reggaeStates[j].type;
        }

        // Now fill the block
        fprintf(stderr, "generating pseudo function\n");
        max_cnt = populationPseudo[funcNum];
        for (cnt = 0; cnt < (max_cnt - 3); ) {
            switch(rand() % 3) {
            case ALUOP:
                genALUOP(reggaeStates, progBytecode[MAX_PROG_BLOCKS + funcNum], &cnt, max_cnt - 3, true);
                break;
            case LSOP:
                genLSOP(reggaeStates, progBytecode[MAX_PROG_BLOCKS + funcNum], &cnt, maxMaps, max_cnt - 3, true);
                break;
            case CALLOP:
                if ((cnt < 8) && progtype_allows_helpers)
                    genCallOP(reggaeStates, progBytecode[MAX_PROG_BLOCKS + funcNum], &cnt, max_cnt - 3, maxMaps, -1, verts, true, funcNum);
                    // Supplied -1 as posIdx above as it will never be evaluated ino ur case and must produce error if it does
                break;
            }
        }
        initRegScalar(BPF_REG_0, Bit64Value, reggaeStates, progBytecode[MAX_PROG_BLOCKS + funcNum], &cnt, 0, max_cnt - 3, true);
        DEUBG_LOC("initRegScalar");
        initRegScalar(BPF_REG_0, Bit64Value, reggaeStates, progBytecode[MAX_PROG_BLOCKS + funcNum], &cnt, 0, max_cnt - 3, true);
        DEUBG_LOC("initRegScalar");
        progBytecode[MAX_PROG_BLOCKS + funcNum][cnt] = BPF_EXIT_INSN();
        printInsn("BPF_EXIT_INSN", 0, 0, 0, 0, 0);
        cnt += 1;
    }
}

void genBasicBlock(struct regState *regStates, struct bpf_insn progBytecode[][BBMAX], int maxMaps, int idx, bool isEnd, int *visited, int verts) {
    // Check block position in program
    int posIdx;
    for (int i = 0; i < MAX_PROG_BLOCKS; i++)
        // We will always find a match
        if (visited[i] == idx)
            posIdx = i;

    int cnt;
    int max_cnt = populationBB[posIdx];
    for (int i = 0; i < 5; i++) stackHasDeps[i] = false;

    // Recalcuate the number of instructions except jmp instruction of each basic block
    int child = getFirstChild(idx);
    int final_max_cnt = 0;
    if (isConditional(cfg, idx))
        final_max_cnt = max_cnt - 1;
    else if (( posIdx > MAX_PROG_BLOCKS - 2 || visited[posIdx + 1] != child))
        final_max_cnt = max_cnt - 1;
    else if (isEnd)
        final_max_cnt = max_cnt - 2;
    else
        final_max_cnt = max_cnt;

    for(cnt = 0; cnt < final_max_cnt; ){
        switch(rand() % 3) {
            case ALUOP:
                genALUOP(regStates, progBytecode[posIdx], &cnt, final_max_cnt);
                break;
            case LSOP:
                genLSOP(regStates, progBytecode[posIdx], &cnt, maxMaps, final_max_cnt);
                break;
            case CALLOP:
                break;
                if ((cnt < 8) && progtype_allows_helpers)
                    genCallOP(regStates, progBytecode[posIdx], &cnt, final_max_cnt, maxMaps, posIdx, verts);
                break;
        }
    }

    if (isEnd) {
        // Add r0 = 0 and BPF_EXIT;
        initRegScalar(BPF_REG_0, Bit64Value, regStates, progBytecode[posIdx], &cnt, 0, final_max_cnt);
        DEUBG_LOC("initRegScalar");
        progBytecode[posIdx][cnt] = BPF_EXIT_INSN();
        printInsn("BPF_EXIT_INSN", 0, 0, 0, 0, 0);
        cnt += 1;

        for (int i = 0; i < 11; i++)
            basicBlockStates[idx][i].type = regStates[i].type;
        return;
    }

    int src = findAnyInitReg(regStates);
    int dst = findAnyInitReg(regStates);

    // Last instruction of each non-leaf basic block
    if (isConditional(cfg, idx)) {
        // DFS is guaranteed to have a fallthrough just below the parent (the right edge)
        // We just need to find the other block (the left edge)
        int child_ind = getChildIndex(getFirstChild(idx), visited);
        int offsetJmp = 0;
        if (child_ind > posIdx) {
            for (int temp = posIdx; temp < child_ind; temp++)
                offsetJmp += populationBB[temp];
            offsetJmp -= max_cnt;
        } else {
            for (int temp = child_ind; temp < posIdx; temp++)
                offsetJmp -= populationBB[temp];
            offsetJmp -= max_cnt;
        }
        genCondJMP(regStates, progBytecode[posIdx], &cnt, offsetJmp, dst, src, (rand() % 2), true);
    }
    else {
        if ( posIdx > MAX_PROG_BLOCKS - 2 || visited[posIdx + 1] != child) {
            int child_ind = getChildIndex(child, visited);
            int offsetJmp = 0;
            if (child_ind > posIdx) {
                for (int temp = posIdx; temp < child_ind; temp++)
                    offsetJmp += populationBB[temp];
                offsetJmp -= (max_cnt - 1);
            } else {
                for (int temp = child_ind; temp < posIdx; temp++)
                    offsetJmp -= populationBB[temp];
                offsetJmp -= max_cnt;
            }
            genJA(regStates, progBytecode[posIdx], &cnt, offsetJmp, true);
        }
    }
    // We need to save the endState of each BB to generate input for the next one
    // Deep copy
    for (int i = 0; i < 11; i++)
        basicBlockStates[idx][i].type = regStates[i].type;
}

void rearrangeProg(struct bpf_insn progBytecode[][BBMAX], int cfgMat[][MAX_PROG_BLOCKS], int verts, int maxMaps) {
    
    // moves the Basic Blocks according to their order and fills in the offset to JMP
    // Will check for different JMP types (reg, imm) and fill offsets
    // We order BBs with FCFS and then fill in offsets for the branch (kind of DFS)


    // Walk the CFG and generate BBs
    int idx = 0;
    int stack[MAX_PROG_BLOCKS], visited[MAX_PROG_BLOCKS];

    for (int i = 0; i < MAX_PROG_BLOCKS; i++)
        stack[i] = visited[i] = -1;

    stack[0] = 0;
    int stack_cnt = 1, visit_cnt = 0;

    // Not doing a check for negatives as stack_cnt is decremented by one at a time
    while (stack_cnt) {

        // Pop
        int bbIdx = stack[--stack_cnt];

        // If explored, skip
        if (isVisited(visited, bbIdx))
            continue;
        
        // Mark explored
        visited[visit_cnt++] = bbIdx;

        // Put children in stack
        findOutgoing(bbIdx, stack, stack_cnt);
    }

    int gen_cnt = 0;
    // Have a to-generate and generated array
    int toGen[visit_cnt], generated[visit_cnt];

    // Create a deep copy of the visited array
    for (int i = 0; i < visit_cnt; i++) {
        toGen[i] = visited[i];
        generated[i] = -1;
    }

    // Now we have the visited array, generate and fill the basic blocks accordingly
    while (gen_cnt < visit_cnt) {

        // Check dependencies 
        int deps[MAX_PROG_BLOCKS], depIdx = 0;
        findIncoming(toGen[gen_cnt], deps);
        bool unmet = false;

        while (deps[depIdx] != -1) {

            for (int i = 0; i < visit_cnt; i++) {

                // If finds the dep as already generated, check the next dep
                if (generated[i] == deps[depIdx])
                    break;

                if (generated[i] == -1) {
                    // This means we have an unmet dependency
                    // Else it would have broken out of loop earlier
                    unmet = true;

                    // Shuffle the toGen array
                    int temp = toGen[gen_cnt];
                    for (int j = gen_cnt; j < visit_cnt - 1; j++)
                        toGen[j] = toGen[j + 1];
                    
                    toGen[visit_cnt - 1] = temp;
                    break;
                }
            }

            if (unmet)
                break;
            
            depIdx++;
        }

        if (unmet)
            continue;

        // I hope that dependencies are taken care of by now

        struct regState regStates[11];
        // Get the begining state of this block
        genInputState(toGen[gen_cnt], regStates);
        
        // Generate the main body
        genBasicBlock(regStates, progBytecode, maxMaps, toGen[gen_cnt], isLeaf(cfg, toGen[gen_cnt]), visited, verts);
        generated[gen_cnt] = toGen[gen_cnt];
        gen_cnt++;
    }
}

bool set_ALUreg(u_int8_t * reg, int bit, bpf_insn * bpfBytecode, int * cnt, int max_cnt) {
    if( bit != Bit32 && bit != Bit64){
        return false;
    }
    u_int8_t dst = findReg(regStates, false);
    if (dst == 0xff) {
        dst = regs[rand() % sizeof(regs)];
        while (dst == 1 || dst == 10) dst = regs[rand() % sizeof(regs)];
        DEUBG_LOC("initRegScalar");
        if (!initRegScalar(dst, bit, regStates, bpfBytecode, cnt, 0, max_cnt)) return false;
    }
    *reg = dst;
    return true;

}

void genALUOP(struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int max_cnt = NINSNS, bool isPseudoFunc) {
    
    /*
        BPF_ALU64_REG(OP, DST, SRC);
        BPF_ALU32_REG(OP, DST, SRC);
        BPF_ALU64_IMM(OP, DST, IMM)
        BPF_ALU32_IMM(OP, DST, IMM)

        BPF_MOV64_REG(DST, SRC)
        BPF_MOV32_REG(DST, SRC)
        BPF_MOV64_IMM(DST, IMM)
        BPF_MOV32_IMM(DST, IMM)
    */

    __u8 op = aluops[rand() % sizeof(aluops)];
    __u8 Sop = aluSops[rand() % sizeof(aluSops)];
    u_int8_t dst = regs[rand() % (sizeof(regs)-1)], src = regs[rand() % sizeof(regs)];
    int32_t imm32 = randNum32(), imm64 = randNum64();
    struct bpf_insn insn;

    while(dst == BPF_REG_1) dst = regs[rand() % (sizeof(regs)-1)];

    switch (rand() % 100) {
        case 0 ... 49:{ // weight 8, maybe 16?
            while ((dst == BPF_REG_1) || (dst == BPF_REG_10)) dst = regs[rand() % sizeof(regs)];
            int offset = ENDIMMs[rand() % sizeof(ENDIMMs)]>>1;
            switch (rand() % 6) {
                case 0: 
                    while (regStates[src].type == NOT_INIT) src = regs[rand() % sizeof(regs)];
                    insn = BPF_MOV64_REG(dst, src);
                    printInsn("BPF_MOV64_REG", 0, dst, src, 0, 0);
                    break;
                case 1:
                    while (regStates[src].type == NOT_INIT) src = regs[rand() % sizeof(regs)];
                    insn = BPF_MOV32_REG(dst, src);
                    printInsn("BPF_MOV32_REG", 0, dst, src, 0, 0);
                    break;
                case 2:
                    insn = BPF_MOV64_IMM(dst, imm64);
                    printInsn("BPF_MOV64_IMM", 0, dst, 0, imm64, 0);
                    break;
                case 3:
                    insn = BPF_MOV32_IMM(dst, imm32);
                    printInsn("BPF_MOV32_IMM", 0, dst, 0, imm32, 0);
                    break;
                case 4:
                    while (regStates[src].type == NOT_INIT) src = regs[rand() % sizeof(regs)];
                    insn = BPF_MOVS64_REG(dst, src, offset);
                    printInsn("BPF_MOVS64_REG", 0, dst, src, 0, offset);
                    break;
                case 5:
                    while (regStates[src].type == NOT_INIT) src = regs[rand() % sizeof(regs)];
                    offset = (offset % 16) + 8;
                    insn = BPF_MOVS32_REG(dst, src, offset);
                    printInsn("BPF_MOVS32_REG", 0, dst, src, 0, offset);
                    break;
            }
            break;
        }
        case 50 ... 63: //Bit64
            if(!set_ALUreg(&dst, Bit64,  bpfBytecode, cnt, max_cnt)) return;
            //fprintf(stderr, "ALU32 OP trying with %02x and Sop %02x\n", op, Sop);
            switch(rand() % 5){
                case 0:
                    insn = BPF_NEG64_REG(dst);
                    printInsn("BPF_NEG64_REG", 0, dst, 0, 0, 0);
                    break;
                case 1:
                    insn = BPF_ALU64_IMM(op, dst, imm64);
                    printInsn("BPF_ALU64_IMM", op, dst, 0, imm64, 0);
                    break;
                case 2:
                    if(!set_ALUreg(&src, Bit64,  bpfBytecode, cnt, max_cnt)) return;
                    insn = BPF_ALU64_REG(op, dst, src);
                    printInsn("BPF_ALU64_REG", op, dst, src, 0, 0);
                    break;
                case 3:
                    insn = BPF_ALUS64_IMM(Sop, dst, imm64);
                    printInsn("BPF_ALUS64_IMM", Sop, dst, 0, imm64, 0);
                    break;
                case 4:
                    if(!set_ALUreg(&src, Bit64,  bpfBytecode, cnt, max_cnt)) return;
                    insn = BPF_ALUS64_REG(Sop, dst, src);
                    printInsn("BPF_ALUS64_REG", Sop, dst, src, 0, 0);
                    break;
            }
            break;
        case 64 ... 99: // Bit32
            if(!set_ALUreg(&dst, Bit32,  bpfBytecode, cnt, max_cnt)) return;
            imm32 = ENDIMMs[rand() % sizeof(ENDIMMs)];
            //fprintf(stderr, "ALU64 OP trying with %02x and Sop %02x\n", op, Sop);
            switch(rand() % 8) {
                case 0:// BPF_ALU32_IMM
                    insn = BPF_ALU32_IMM(op, dst, imm32);
                    printInsn("BPF_ALU32_IMM", op, dst, 0, imm32, 0);
                    break; 
                case 1:// BPF_ALU32_REG
                    if(!set_ALUreg(&src, Bit32,  bpfBytecode, cnt, max_cnt)) return;
                    insn = BPF_ALU32_REG(op, dst, src);
                    printInsn("BPF_ALU32_REG", op, dst, src, 0, 0);
                    break;
                case 2: //BPF_NEG32_REG
                    insn = BPF_NEG32_REG(dst);
                    printInsn("BPF_NEG32_REG", 0, dst, 0, 0, 0);
                    break;
                case 3: //BPF_ENDBE_REG
                    insn = BPF_ENDBE_REG(dst, imm32);
                    printInsn("BPF_ENDBE_REG", 0, dst, 0, 0, 0);
                    break;
                case 4: //BPF_ENDLE_REG
                    insn = BPF_ENDLE_REG(dst, imm32);
                    printInsn("BPF_ENDLE_REG", 0, dst, 0, 0, 0);
                    break;
                case 5:// BPF_ALUS32_IMM
                    insn = BPF_ALUS32_IMM(Sop, dst, imm32);
                    printInsn("BPF_ALUS32_IMM", op, dst, 0, imm32, 0);
                    break; 
                case 6:// BPF_ALUS32_REG
                    if(!set_ALUreg(&src, Bit32,  bpfBytecode, cnt, max_cnt)) return;
                    insn = BPF_ALUS32_REG(Sop, dst, src);
                    printInsn("BPF_ALUS32_REG", op, dst, src, 0, 0);
                    break;
                case 7:
                    insn = BPF_ENDSWAP_REG(dst, imm32);
                    printInsn("BPF_ENDSWAP_REG", 0, dst, 0, 0, 0);
                    break;
            }
           break;
		default:
			return;
    }

    if (!commonALUCons(&insn, regStates, bpfBytecode, cnt, max_cnt)) return;
    updateByteCode(bpfBytecode, cnt, insn, false, __LINE__, max_cnt);
}

void genLSOP (struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int maxMaps, int max_cnt = NINSNS, bool isPseudoFunc) {
    
    /*
        BPF_LDX_MEM(SIZE, DST, SRC, OFF)           dst_reg = *(uint *) (src_reg + off16)
        BPF_STX_MEM(SIZE, DST, SRC, OFF)           *(uint *) (dst_reg + off16) = src_reg
        BPF_ST_MEM(SIZE, DST, OFF, IMM)            *(uint *) (dst_reg + off16) = imm32
        BPF_ATOMIC_OP(SIZE, OP, DST, SRC, OFF)     
        BPF_LD_IMM64(DST, IMM) 2 insns
        BPF_LD_ABS(SIZE, IMM)                      R0 = *(uint *) (skb->data + imm32)
        BPF_LD_MAP_FD(DST, MAP_FD) 2 insns
    */

    int size = SIZE[rand() % sizeof(SIZE)];
    u_int8_t dst, src, op = 0;
    int64_t imm64 = randNum64(), fdIdx, off = 0;
    struct bpf_insn insn = {0}, insns[2];
    bool isDoubleInsns = false;
    regState dstState = {NOT_INIT};

    switch(rand() % 10) {
        case 0:
            dst = one_writable_reg;
            src = findAnyPtrReg(regStates);
            off = get_off(&regStates[src], size);
            insn = BPF_LDX_MEM(size, dst, src, off);
            break;
        case 1:
            dst = one_writable_reg;
            src = findAnyPtrReg(regStates);
            off = get_off(&regStates[src], size);
            size =  SIZE[rand() % (sizeof(SIZE) - 1)]; // Except BPF_DW
            insn = BPF_LDX_MEMSX(size, dst, src, off);
            break;
        case 2:
            dst = findAnyPtrReg(regStates);
            src = findAnyInitReg(regStates);
            off = get_off(&regStates[dst], size);
            insn = BPF_STX_MEM(size, dst, src, off);
            break;
        case 3:
            dst = findAnyPtrReg(regStates);
            off = get_off(&regStates[dst], size);
            insn = BPF_ST_MEM(size, dst, off, imm64);
            break;
        case 4:
            dst = findAnyWritableReg(regStates);
            src = findAnyPtrReg(regStates);
            size = get_atomic_size;
            off = get_off(&regStates[dst], size);
            op = atomicOps[rand() % sizeof(atomicOps)];
            if (op == BPF_CMPXCHG && regStates[BPF_REG_0].type == NOT_INIT) {
                if (*cnt + 1 >= max_cnt) return;
                initReg(regStates, BPF_REG_0, bpfBytecode, cnt, max_cnt);
            }
            insn = BPF_ATOMIC_OP(size, op, dst, src, off);
            // dstState.type = SCALAR_VALUE;
            break;
        case 5: {
            if (*cnt + 1 >= max_cnt) return;
            //
            dst = one_writable_reg;
            //
            struct bpf_insn insns1[2] = {
                BPF_LD_IMM64(dst, imm64),
            };
            memcpy(insns, insns1, sizeof(struct bpf_insn)*2);
            // dstState.type=SCALAR_VALUE;
            isDoubleInsns = true;
            break;
        } case 6:{
            if (*cnt + 1 >= max_cnt) return;
            if(maxMaps==0)
                return;
            dst = one_writable_reg;
            fdIdx =  rand() % maxMaps;
            struct bpf_insn insns2[2] = {
                BPF_LD_MAP_FD(dst, fdIdx),
            };
            memcpy(insns, insns2, sizeof(struct bpf_insn)*2);
            dstState.type = CONST_PTR_TO_MAP;
            isDoubleInsns = true;
            break;
        } case 7:{
            if (*cnt + 1 >= max_cnt) return;
            if(maxMaps==0)
                return;
            dst = one_writable_reg;
            fdIdx =  rand() % maxMaps;
            struct bpf_insn insns2[2] = {
                BPF_LD_FDIDX(dst, fdIdx),
            };
            memcpy(insns, insns2, sizeof(struct bpf_insn)*2);
            dstState.type = CONST_PTR_TO_MAP;
            isDoubleInsns = true;
            break;
        } case 8:{
            if (*cnt + 1 >= max_cnt) return;
            if(maxMaps==0)
                return;
            dst = one_writable_reg;
            fdIdx =  rand() % maxMaps;
            for (int i = 0; i <= MAP_TRY_TO_FIND; i++)
            {
                // We do a 100 attempts (arbitrary limit)
                if(isMapWritable(mapAttrs, fdIdx, maxMaps)){
                    break;
                }
                fdIdx =  rand() % maxMaps;
                if(i == MAP_TRY_TO_FIND) {
                    return; // no valid map found
                }
            }
            int off = rand() >> 1;
            struct bpf_insn insns4[2] = {
                BPF_LD_FD_MAPVALUE(dst, fdIdx, off),
            };
            memcpy(insns, insns4, sizeof(struct bpf_insn)*2);
            dstState.type = SCALAR_VALUE;
            isDoubleInsns = true;
            break;
        } case 9: {
            if (*cnt + 1 >= max_cnt) return;
            if(maxMaps==0)
                return;
            dst = one_writable_reg;
            fdIdx =  rand() % maxMaps;
            for (int i = 0; i <= MAP_TRY_TO_FIND; i++)
            {
                // We do a 100 attempts (arbitrary limit)
                if(isMapWritable(mapAttrs, fdIdx, maxMaps)){
                    break;
                }
                fdIdx =  rand() % maxMaps;
                if(i == MAP_TRY_TO_FIND) {
                    return; // no valid map found
                }
            }
            int off = rand() >> 1;
            struct bpf_insn insns4[2] = {
                BPF_LD_FDIDX_MAPVALUE(dst, fdIdx, off),
            };
            memcpy(insns, insns4, sizeof(struct bpf_insn)*2);
            dstState.type = SCALAR_VALUE;
            isDoubleInsns = true;
            break;
        }
        case 10: {
            // Disabled now
            dst = one_writable_reg;
            // TODO: function offset
            insn = BPF_LD_PSEUDO_FUNC(dst, 0);
            dstState.type = PTR_TO_FUNC;
            break;
        }
        default:
            // TODO BPF_LD_PLAT_VAR
            fprintf(stderr, "default reached in genLSOP\n");
            return;
    }

    if ((isDoubleInsns && *cnt < (max_cnt - 1)) || !isDoubleInsns) {
        if (isDoubleInsns) {
            updateByteCode(bpfBytecode, cnt, insns[0], false, __LINE__, max_cnt);
            updateByteCode(bpfBytecode, cnt, insns[1], false, __LINE__, max_cnt);
        } else if (!isDoubleInsns) {
            updateByteCode(bpfBytecode, cnt, insn, false, __LINE__, max_cnt);
        }
        if(dstState.type != NOT_INIT){
            regStates[dst] = dstState;
        }
    }
}

void genJA(struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int off, bool force) {
    struct bpf_insn insn;
    // if too big for 16 bit offset, use 32 bit imm
    if (off >= 1<<16 || off <= -1<<16 || rand() % 2 ) { 
        insn = BPF_JA32_INSN(off);
        printInsn("BPF_JA32_INSN", 0, 0, 0, off, 0);
    } else {
        insn = BPF_JA_INSN(off);
        printInsn("BPF_JA_INSN", 0, 0, 0, 0, off);
    }
    // if(!checkJA(&insn)) return;     // It will pass this test nevertheless
    updateByteCode(bpfBytecode, cnt, insn, force, __LINE__);
    // fprintf(stderr, "confirmed\n"); // FIXME
}

void genCondJMP(struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int off, int dst, int src, int bit, bool force) {
    u_int8_t op = jmpops[rand() % sizeof(jmpops)];

    int32_t imm32 = randNum32();
    int32_t imm64 = randNum64();
    struct bpf_insn insn;

    if (bit) {
        switch (rand() % 2) {
            case 0:
                insn = BPF_JMP32_REG(op, dst, src, off);
                printInsn("BPF_JMP32_REG", op, dst, src, 0, off);
                break;
            case 1:
                insn = BPF_JMP32_IMM(op, dst, imm32, off);
                printInsn("BPF_JMP32_IMM", op, dst, 0, imm32, off);
                break;
        }
    } else {
        switch (rand() % 2) {
            case 0:
                insn = BPF_JMP_REG(op, dst, src, off);
                printInsn("BPF_JMP_REG", op, dst, src, 0, off);
                break;
            case 1:
                insn = BPF_JMP_IMM(op, dst, imm64, off);
                printInsn("BPF_JMP_IMM", op, dst, 0, imm32, off);
                break;
        }
    }

    // if(!commonJMPCons(&insn, regStates, bpfBytecode, cnt)) return;
    updateByteCode(bpfBytecode, cnt, insn, force, __LINE__);
}

void printProg(int ind, struct bpf_insn** progBytecode)
{
    for (int i = 0; i < ind; i++) {
        struct bpf_insn j = progBytecode[i / BBMAX][i % BBMAX];
        fprintf(stderr, "(struct bpf_insn){ .code = %02x, .dst_reg = %d, .src_reg = %d, .off = %d, .imm = %d },\n", j.code, j.dst_reg, j.src_reg, j.off, j.imm);
    }
}

bool callerSpillRegs(regState* regStates, bpf_insn* bpfByteCode, int* cnt, int max_cnt)
{
    struct bpf_insn insn;
    
    // We save at -440 in the stack
    // Bypassing constraints as this is correct
    for (char src = BPF_REG_1; src < BPF_REG_6; src++) {
        if (regStates[src].type != NOT_INIT) {
            insn = BPF_STX_MEM(BPF_DW, BPF_REG_10, src, - (440 + (8 * src)));
            updateByteCode(bpfByteCode, cnt, insn, false, __LINE__, max_cnt);
        }

        spilledRegs[src - 1] = regStates[src].type;
    }

    return true;
}

bool callerPopRegs(regState* regStates, bpf_insn* bpfByteCode, int* cnt, int max_cnt)
{
    struct bpf_insn insn;
    
    // We pop from -440 in the stack
    // Bypassing constraints as this is correct
    for (char src = BPF_REG_1; src < BPF_REG_6; src++) {
        if (spilledRegs[src - 1]) {
            insn = BPF_LDX_MEM(BPF_DW, src, BPF_REG_10, - (440 + (8 * src)));
            updateByteCode(bpfByteCode, cnt, insn, false, __LINE__, max_cnt);
        }

        regStates[src].type = spilledRegs[src - 1];
    }

    return true;
}

bool fillArg(regState* regStates, bpf_insn* bpfByteCode, int* cnt, int max_cnt, char reg, const char *type, int maxMaps, proto_addr helper_func)
{
    bool updt = false, doubleInsn = false, tripleInsn = false;
    struct bpf_insn insn, insns[2], insnthree[3];
    if (!strcmp(type, "PTR_TO_CTX")) {
        if (regStates[reg].type != PTR_TO_CTX) {
            insn = BPF_MOV64_REG(reg, BPF_REG_1);
            updt = true;
        }
    }
    else if (!strcmp(type, "PTR_TO_STACK")) {
        if (regStates[reg].type != PTR_TO_STACK) {
            insnthree[0] = BPF_MOV64_REG(reg, BPF_REG_10);
            int off = randRange(-200, -8);
            off -= (off % 4);
            insnthree[1] = BPF_ALU64_IMM(BPF_ADD, reg, off);;
            insnthree[2] = BPF_ST_MEM(4, BPF_REG_10, off, urandNum32());
            updt = true;
            tripleInsn = true;
        }
    }
    else if (!strcmp(type, "SCALAR_VALUE")) {
        if (regStates[reg].type != SCALAR_VALUE) {
            insn = BPF_MOV64_IMM(reg, randRange(1, 4));
            updt = true;
        }
    }
    else if (!strcmp(type, "CONST_PTR_TO_MAP")) {
        if (regStates[reg].type != CONST_PTR_TO_MAP) {
            if(maxMaps==0){return false;}
            // try to find the correct map
            __u64 fdIdx =  rand() % maxMaps;
            for (int i = 0; i <= MAP_TRY_TO_FIND; i++)
            {
                if (doesHelperAllowMapType(helper_func, getMapType(mapAttrs, fdIdx, maxMaps)))
                {
                    fprintf(stderr, "func %i allows map type %d\n", helper_func, getMapType(mapAttrs, fdIdx, maxMaps));
                    break;
                }
                fdIdx =  rand() % maxMaps;
                
                if(i == MAP_TRY_TO_FIND){
                    return false;
                }
            }
            

            struct bpf_insn insns2[2] = {
                BPF_LD_MAP_FD(reg, fdIdx),
            };
            memcpy(insns, insns2, sizeof(struct bpf_insn)*2);
            updt = doubleInsn = true;
        }
    }
    else if (!strcmp(type, "ARG_PTR_TO_STACK_OR_NULL")) {
        if (regStates[reg].type != PTR_TO_STACK) {
            insnthree[0] = BPF_MOV64_REG(reg, BPF_REG_10);
            int off = randRange(-200, -8);
            off -= (off % 4);
            insnthree[1] = BPF_ALU64_IMM(BPF_ADD, reg, off);;
            insnthree[2] = BPF_ST_MEM(4, BPF_REG_10, off, urandNum32());
            updt = true;
            tripleInsn = true;
        }
    }
    else if (!strcmp(type, "ARG_ANYTHING")) {
        if (regStates[reg].type == NOT_INIT) {
            switch (rand() % 2) {
                case 0:
                    insn = BPF_MOV64_IMM(reg, urandNum32());
                    break;
                case 1:
                {
                    insns[0] = BPF_MOV64_REG(reg, BPF_REG_10);
                    insns[1] = BPF_ALU64_IMM(BPF_ADD, reg, randRange(1, 200));
                    doubleInsn = true;
                    break;
                }
            }
            updt = true;
        }
    }
    // todo add more 
    if (updt && tripleInsn) {
        updateByteCode(bpfByteCode, cnt, insnthree[0], false, __LINE__, max_cnt);
        updateByteCode(bpfByteCode, cnt, insnthree[1], false, __LINE__, max_cnt);
        updateByteCode(bpfByteCode, cnt, insnthree[2], false, __LINE__, max_cnt);

    }
    else if (updt && doubleInsn) {
        updateByteCode(bpfByteCode, cnt, insns[0], false, __LINE__, max_cnt);
        updateByteCode(bpfByteCode, cnt, insns[1], false, __LINE__, max_cnt);
    }
    else if (updt)
        updateByteCode(bpfByteCode, cnt, insn, false, __LINE__, max_cnt);
    return true;
}

void genCallOP(struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int max_cnt = NINSNS,
                    int maxMaps = 0, int posIdx = -1, int verts = -1, bool isPseudoFunc, int pseudoNum) {

    // We choose a call func, pass the constraints, and then initiate spilling
    struct bpf_insn insn;
    const char *ret_str = nullptr;
    char ret_type = NOT_INIT;
    int funcIdx;
    bool foundFunc = false;
    bool wasSubProg = false;
    int subProg;
    struct bit_field {
        __u64 lo;
        __u32 hi;
    } indep_vect;
    indep_vect.hi = indep_vect.lo = 0;
    proto_addr found_helper_func;
    switch(rand() % 3) {
        case 0:
            // Having helper functions with independent arguments
            // Now this is always going to pass NOPE!!!!
            // TODO: This is O(n * m). If this is a problem, sort the indep_helper array and progtype_helpers
            // and make it O(n + m) 
            while ((!foundFunc) && (!((indep_vect.lo >= 0xFFFFFFFFFFFFFFFF) && (indep_vect.hi >= 0x7FFFF)))) {
                funcIdx = randRange(0, MAX_INDEP_HELPER_PROTO_ARR_SIZE - 1);
                if (((funcIdx > 63) && (indep_vect.hi & (1 << (funcIdx - 64)))) || ((funcIdx < 64) && (indep_vect.lo & (1 << funcIdx))))
                    break;
                if (funcIdx > 63)
                    indep_vect.hi |= (1 << funcIdx - 64);
                else
                    indep_vect.lo |= (1 << funcIdx);
                for (int i = 0; i < progType2Helpers[progType].siz; i++)
                {
                    if (progType2Helpers[progType].helpers[i] == indep_helper_proto[funcIdx].funcName) {
                        //fprintf_h(stderr, "I found a func my progtype %d my func %d\n", progType, funcIdx);
                        foundFunc = true;
                        break;
                    }
                }
            }
            if (!foundFunc) return;

            found_helper_func = indep_helper_proto[funcIdx].funcName;
            insn = BPF_HELPER_CALL(found_helper_func);
            printInsn("BPF_HELPER_CALL", 0, 0, 0, found_helper_func, 0);

            callerSpillRegs(regStates, bpfBytecode, cnt, max_cnt);
            // Now we fill in the args
            for (char i = 0; i < indep_helper_proto[funcIdx].argNum; i++) {
                if (indep_helper_proto[funcIdx].argTypes[i].num == 1) {
                    if( !fillArg(regStates, bpfBytecode, cnt, max_cnt, i + 1, indep_helper_proto[funcIdx].argTypes[i].types[0], maxMaps, found_helper_func)){
                        return;
                    }
                } else {
                    int type_idx = -1;
                    for (int j = 0; j < indep_helper_proto[funcIdx].argTypes[i].num; j++) {
                        bool flg = false;
                        for (int k = 0; k < MAX_INDEP_ARGS; k++)
                        {
                            if (!strcmp(indep_helper_proto[funcIdx].argTypes[i].types[j], indep_args_enum[k])) {
                                flg = true;
                                break;
                            }
                        }
                        if (flg) {
                            type_idx = j;
                            break;
                        }
                    }
                    if(!fillArg(regStates, bpfBytecode, cnt, max_cnt, i + 1, indep_helper_proto[funcIdx].argTypes[i].types[type_idx], maxMaps, found_helper_func)){
                        fprintf(stderr, "Triggered return with arg filled?\n");
                        return;
                    }
                }
            }

            if (indep_helper_proto[funcIdx].retTypeLength) ret_str = indep_helper_proto[funcIdx].retTypes[0];
            if (ret_str) {
                for (int i = 0; i < MAX_RET_LEN; i++)
                    if (!strcmp(retTypeEnum[i].str, ret_str)) ret_type = retTypeEnum[i].type;
            }
            break;
        
        case 1:
            // dep helper call
            {
                while ((!foundFunc) && (!((indep_vect.lo >= 0xFFFFFFFFFFFFFFFF)))) {
                    funcIdx = randRange(0, MAX_DEP_HELPER_PROTO_ARR_SIZE - 1);
                    if (((funcIdx > 63) && (indep_vect.hi & (1 << (funcIdx - 64)))) || ((funcIdx < 64) && (indep_vect.lo & (1 << funcIdx))))
                        break;
                    if (funcIdx > 63)
                        indep_vect.hi |= (1 << funcIdx - 64);
                    else
                        indep_vect.lo |= (1 << funcIdx);
                    for (int i = 0; i < progType2Helpers[progType].siz; i++)
                    {
                        if (progType2Helpers[progType].helpers[i] == indep_helper_proto[funcIdx].funcName) {
                            foundFunc = canFulfilArgs(funcIdx, regStates, bpfBytecode, cnt, max_cnt, maxMaps);
                            break;
                        }
                    }
                }
                if (!foundFunc) return;
                found_helper_func = dep_helper_proto[funcIdx].funcName;
                insn = BPF_HELPER_CALL(found_helper_func);
                printInsn("BPF_HELPER_CALL", 0, 0, 0, found_helper_func, 0);
                if (dep_helper_proto[funcIdx].retTypeLength) ret_str = dep_helper_proto[funcIdx].retTypes[0];
                if (ret_str) {
                    for (int i = 0; i < MAX_RET_LEN; i++)
                        if (!strcmp(retTypeEnum[i].str, ret_str)) ret_type = retTypeEnum[i].type;
                }

            }
            break;
            
        case 2:
            // This is for pseudoFuncs
            {
                // prevents calling from one pseudo function to another
                //if (isPseudoFunc) return;
                int curr_used = 0;
                if(isPseudoFunc){
                    if(pseudoNum == 0){ return; } // 1st pseudo func
                    // Always smaller pseudo func
                    curr_used = pseudoNum;
                } else {
                    for (int i = 0; i < MAX_PSEUDO_FUNCS; i++)
                    {
                        if (!isFuncUsed[curr_used] || curr_used + 1 == MAX_PSEUDO_FUNCS) {
                            break;
                        }
                        curr_used ++;
                    }
                    curr_used++;
                }

                subProg = rand() % curr_used;
                callerSpillRegs(regStates, bpfBytecode, cnt, max_cnt);
                // I don't know what args to pass
                for (int i = BPF_REG_1; i < BPF_REG_6; i++) {
                    switch(protoStates[subProg][i].type) {
                        case SCALAR_VALUE:
                            fillArg(regStates, bpfBytecode, cnt, max_cnt, i, "SCALAR_VALUE", maxMaps, unspec);
                            break;
                        case PTR_TO_CTX:
                            fillArg(regStates, bpfBytecode, cnt, max_cnt, i, "PTR_TO_CTX", maxMaps, unspec);
                            break;
                        case PTR_TO_STACK:
                            fillArg(regStates, bpfBytecode, cnt, max_cnt, i, "PTR_TO_STACK", maxMaps, unspec);
                            break;
                        default:
                            break;
                    }
                }
                int offci = -(*cnt) - 1;
                if (!isPseudoFunc){
                    for (int j = posIdx; j < verts; j++) offci += populationBB[j];
                    for (int j = 0; j < subProg; j++) offci += populationPseudo[j];
                } else {
                    // Only smaller then current subprog
                    for (int j = subProg; j < pseudoNum; j++) offci -= populationPseudo[j];
                }
                fprintf(stderr, "pseudo func call isPseudoFunc %d off %d cnt %d from pseudo func %d to pseudo func %d\n", isPseudoFunc, offci, *cnt, pseudoNum,subProg);
                insn = BPF_CALL_PSEUDO_FUNC(offci);
                ret_type = SCALAR_VALUE;
                wasSubProg = true;
                if(!isPseudoFunc){ isFuncUsed[subProg] = true;}
            }
            break;
    }

    // Success
    bool success = updateByteCode(bpfBytecode, cnt, insn, false, __LINE__, max_cnt);
    if (!success && wasSubProg) {
        isFuncUsed[subProg] = false;
    }
    callerPopRegs(regStates, bpfBytecode, cnt, max_cnt);
    regStates[BPF_REG_0].type = ret_type;
    // Check if we must save the return value in stack
    if (!wasSubProg) {
        for (int i = 0; i < MAX_DEP_ARGS; i++) {
            if (!strcmp(ret_str, dep_args_enum[i])) {
                insn = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, - (320 + (8 * i)));
                updateByteCode(bpfBytecode, cnt, insn, false, __LINE__, max_cnt);
                stackHasDeps[i] = true;
            }
        }
    }
}

bool canFulfilArgs(int funcIdx, regState *regStates, bpf_insn *bpfByteCode, int *cnt, int max_cnt, int maxMaps) {
    bool isTrivial = false;
    bool canResolve = false;
    int funcArgs[5] = {-1, -1, -1, -1, -1};

    for (int i = 0; i < dep_helper_proto[funcIdx].argNum; i++) {
        isTrivial = canResolve = false;
        for (int j = 0; j < dep_helper_proto[funcIdx].argTypes[i].num; j++) {
            for (int k = 0; k < MAX_INDEP_ARGS; k++) {
                if (!strcmp(dep_helper_proto[funcIdx].argTypes[i].types[j], indep_args_enum[k])) {
                    isTrivial = canResolve = true;
                    break;
                }
            }
            if (isTrivial) break;
        }
        if (!isTrivial) {
            // We found the dependency, let's see if we can resolve
            // big ugly if-else block
            for (int j = 0; j < dep_helper_proto[funcIdx].argTypes[i].num; j++) {
                for (int k = 0; k < MAX_DEP_ARGS; k++) {
                    if (!strcmp(dep_helper_proto[funcIdx].argTypes[i].types[j], dep_args_enum[k])) {
                        __u64 bitVect = 0;
                        int argFuncIdx;
                        switch (k) {
                            case 0:
                                while (bitVect < 0x3) {
                                    argFuncIdx = rand() % MAX_PTR_TO_MEM_RET_ARR_SIZE;
                                    if (bitVect & (1 << argFuncIdx)) continue;
                                    bitVect |= (1 << argFuncIdx);
                                    for (int l = 0; l < progType2Helpers[progType].siz; l++)
                                    {
                                        if (progType2Helpers[progType].helpers[l] == PTR_TO_MEM_ret[argFuncIdx].funcName) {
                                            funcArgs[i] = PTR_TO_MEM_ret[argFuncIdx].funcName;
                                            canResolve = true;
                                            break;
                                        }
                                    }
                                    if (canResolve) break;
                                }
                                break;
                            case 1:
                                while (bitVect < 0x3) {
                                    argFuncIdx = rand() % MAX_PTR_TO_SOCKET_RET_ARR_SIZE;
                                    if (bitVect & (1 << argFuncIdx)) continue;
                                    bitVect |= (1 << argFuncIdx);
                                    for (int l = 0; l < progType2Helpers[progType].siz; l++)
                                    {
                                        if (progType2Helpers[progType].helpers[l] == PTR_TO_SOCKET_ret[argFuncIdx].funcName) {
                                            funcArgs[i] = PTR_TO_SOCKET_ret[argFuncIdx].funcName;
                                            canResolve = true;
                                            break;
                                        }
                                    }
                                    if (canResolve) break;
                                }
                                break;
                            case 2:
                                while (bitVect < 0x1) {
                                    argFuncIdx = rand() % MAX_PTR_TO_SOCK_COMMON_RET_ARR_SIZE;
                                    if (bitVect & (1 << argFuncIdx)) continue;
                                    bitVect |= (1 << argFuncIdx);
                                    for (int l = 0; l < progType2Helpers[progType].siz; l++)
                                    {
                                        if (progType2Helpers[progType].helpers[l] == PTR_TO_SOCK_COMMON_ret[argFuncIdx].funcName) {
                                            funcArgs[i] = PTR_TO_SOCK_COMMON_ret[argFuncIdx].funcName;
                                            canResolve = true;
                                            break;
                                        }
                                    }
                                    if (canResolve) break;
                                }
                                break;
                            case 3:
                                break;
                                // //fprintf_h(stderr, "three\n");
                                // while (bitVect < 0x1) {
                                //     argFuncIdx = rand() % MAX_PTR_TO_BTF_ID_RET_ARR_SIZE;
                                //     if (bitVect & (1 << argFuncIdx)) continue;
                                //     bitVect |= (1 << argFuncIdx);
                                //     for (int l = 0; l < progType2Helpers[progType].siz; l++)
                                //     {
                                //         if (progType2Helpers[progType].helpers[l] == PTR_TO_BTF_ID_ret[argFuncIdx].funcName) {
                                //             //fprintf_h(stderr, "I found a func my progtype %d my func %d\n", progType, argFuncIdx);
                                //             funcArgs[i] = PTR_TO_BTF_ID_ret[argFuncIdx].funcName;
                                //             canResolve = true;
                                //             break;
                                //         }
                                //     }
                                //     if (canResolve) break;
                                // }
                                // break;
                            case 4:
                                while (bitVect < 0x7) {
                                    argFuncIdx = rand() % MAX_PTR_TO_MAP_VALUE_RET_ARR_SIZE;
                                    if (bitVect & (1 << argFuncIdx)) continue;
                                    bitVect |= (1 << argFuncIdx);
                                    for (int l = 0; l < progType2Helpers[progType].siz; l++)
                                    {
                                        if (progType2Helpers[progType].helpers[l] == PTR_TO_MAP_VALUE_ret[argFuncIdx].funcName) {
                                            //fprintf_h(stderr, "I found a func my progtype %d my func %d\n", progType, argFuncIdx);
                                            funcArgs[i] = PTR_TO_MAP_VALUE_ret[argFuncIdx].funcName;
                                            canResolve = true;
                                            break;
                                        }
                                    }
                                    if (canResolve) break;
                                }
                                break;
                            case 5:
                                //fprintf_h(stderr, "five\n");
                                // if (rand() % 2) {
                                //     canResolve = true;
                                //     break;
                                // }
                                // while (bitVect < 0x1) {
                                //     argFuncIdx = rand() % MAX_PTR_TO_BTF_ID_RET_ARR_SIZE;
                                //     if (bitVect & (1 << argFuncIdx)) continue;
                                //     bitVect |= (1 << argFuncIdx);
                                //     for (int l = 0; l < progType2Helpers[progType].siz; l++)
                                //     {
                                //         if (progType2Helpers[progType].helpers[l] == PTR_TO_BTF_ID_ret[argFuncIdx].funcName) {
                                //             //fprintf_h(stderr, "I found a func my progtype %d my func %d\n", progType, argFuncIdx);
                                //             funcArgs[i] = PTR_TO_BTF_ID_ret[argFuncIdx].funcName;
                                //             canResolve = true;
                                //             break;
                                //         }
                                //     }
                                //     if (canResolve) break;
                                // }
                                canResolve = true;
                                break;
                            case 6:
                                if (rand() % 2) {
                                    canResolve = true;
                                    break;
                                }
                                while (bitVect < 0x3) {
                                    argFuncIdx = rand() % MAX_PTR_TO_MEM_RET_ARR_SIZE;
                                    if (bitVect & (1 << argFuncIdx)) continue;
                                    bitVect |= (1 << argFuncIdx);
                                    for (int l = 0; l < progType2Helpers[progType].siz; l++)
                                    {
                                        if (progType2Helpers[progType].helpers[l] == PTR_TO_MEM_ret[argFuncIdx].funcName) {
                                            funcArgs[i] = PTR_TO_MEM_ret[argFuncIdx].funcName;
                                            canResolve = true;
                                            break;
                                        }
                                    }
                                    if (canResolve) break;
                                }
                                break;
                            case 7:
                                if (rand() % 2) {
                                    canResolve = true;
                                    break;
                                }
                                while (bitVect < 0x7) {
                                    argFuncIdx = rand() % MAX_PTR_TO_MAP_VALUE_RET_ARR_SIZE;
                                    if (bitVect & (1 << argFuncIdx)) continue;
                                    bitVect |= (1 << argFuncIdx);
                                    for (int l = 0; l < progType2Helpers[progType].siz; l++)
                                    {
                                        if (progType2Helpers[progType].helpers[l] == PTR_TO_MAP_VALUE_ret[argFuncIdx].funcName) {
                                            funcArgs[i] = PTR_TO_MAP_VALUE_ret[argFuncIdx].funcName;
                                            canResolve = true;
                                            break;
                                        }
                                    }
                                    if (canResolve) break;
                                }
                                break;
                        }
                    }
                    if (canResolve) break;
                }
                if (canResolve) continue;
            }
        }
        // Halt everything if even one rgument can't be satisfied
        if (!canResolve && !isTrivial) return false;
    }

    // Call the dependencies
    for (int ic = 0; ic < 5; ic++) {
        if (funcArgs[ic] == -1) continue;
        int arrInd = -1;
        for (int j = 0; j < MAX_INDEP_HELPER_PROTO_ARR_SIZE; j++) {
            if (funcArgs[ic] == indep_helper_proto[j].funcName) arrInd = j;
        }
        bool foundOnStack = false;
        for (int j = 0; j < MAX_DEP_ARGS; j++) {
            if (!strcmp(indep_helper_proto[arrInd].retTypes[0], dep_args_enum[j]) && stackHasDeps[j]) {
                foundOnStack = true;
                break;
            }
        }
        if (foundOnStack) continue;
        if (arrInd < 0) return false;
        callerSpillRegs(regStates, bpfByteCode, cnt, max_cnt);
        // Now we fill in the args
        for (char j = 0; j < indep_helper_proto[arrInd].argNum; j++) {
            if (indep_helper_proto[arrInd].argTypes[j].num == 1) {
                if(!fillArg(regStates, bpfByteCode, cnt, max_cnt, j + 1, indep_helper_proto[arrInd].argTypes[j].types[0], maxMaps,indep_helper_proto[arrInd].funcName)){
                    return false;
                }
            } else {
                int type_idx = -1;
                for (int k = 0; k < indep_helper_proto[arrInd].argTypes[j].num; k++) {
                    bool flg = false;
                    for (int l = 0; l < MAX_INDEP_ARGS; l++)
                    {
                        //fprintf_h(stderr, "%s\n", indep_helper_proto[arrInd].argTypes[j].types[k]);
                        if (!strcmp(indep_helper_proto[arrInd].argTypes[j].types[k], indep_args_enum[l])) {
                            flg = true;
                            break;
                        }
                    }
                    if (flg) {
                        type_idx = k;
                        break;
                    }
                }
                if (!fillArg(regStates, bpfByteCode, cnt, max_cnt, j + 1, indep_helper_proto[arrInd].argTypes[j].types[type_idx], maxMaps, indep_helper_proto[arrInd].funcName)){
                    fprintf(stderr, "Triggered false return with arg filled?\n");
                    return false;
                }
            }
        }
        struct bpf_insn insn = BPF_HELPER_CALL(indep_helper_proto[arrInd].funcName);
        updateByteCode(bpfByteCode, cnt, insn, false, __LINE__, max_cnt);
        callerPopRegs(regStates, bpfByteCode, cnt, max_cnt);
        insn = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, - (400 + (8 * ic)));
        updateByteCode(bpfByteCode, cnt, insn, false, __LINE__, max_cnt);
        // Store the return type on stack pls
        const char *ret_str = nullptr;
        if (indep_helper_proto[funcIdx].retTypeLength) ret_str = indep_helper_proto[funcIdx].retTypes[0];
        if (ret_str) {
            for (int koko = 0; koko < MAX_DEP_ARGS; koko++) {
                if (!strcmp(ret_str, dep_args_enum[koko])) {
                    insn = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, - (320 + (8 * koko)));
                    updateByteCode(bpfByteCode, cnt, insn, false, __LINE__, max_cnt);
                    stackHasDeps[koko] = true;
                }
            }
        }
    }
    for (char j = 0; j < dep_helper_proto[funcIdx].argNum; j++) {
        if (funcArgs[j] == -1) {
            if (dep_helper_proto[funcIdx].argTypes[j].num == 1) {
                if(!fillArg(regStates, bpfByteCode, cnt, max_cnt, j + 1, dep_helper_proto[funcIdx].argTypes[j].types[0], maxMaps, dep_helper_proto[funcIdx].funcName)){
                    return false;
                }
            } else {
                int type_idx = -1;
                for (int k = 0; k < dep_helper_proto[funcIdx].argTypes[j].num; k++) {
                    bool flg = false;
                    for (int l = 0; l < MAX_INDEP_ARGS; l++)
                    {
                        if (!strcmp(dep_helper_proto[funcIdx].argTypes[j].types[k], dep_args_enum[l])) {
                            flg = true;
                            break;
                        }
                    }
                    if (flg) {
                        type_idx = k;
                        break;
                    }
                }
                if(!fillArg(regStates, bpfByteCode, cnt, max_cnt, j + 1, dep_helper_proto[funcIdx].argTypes[j].types[type_idx], maxMaps, dep_helper_proto[funcIdx].funcName)){
                 fprintf(stderr, "Triggered false 2 return with arg filled?\n");
                    return false;
                }
            }
        } else {
            int arrInd = -1;
            for (int k = 0; k < MAX_INDEP_HELPER_PROTO_ARR_SIZE; k++) {
                if (funcArgs[j] == indep_helper_proto[k].funcName) arrInd = k;
            }
            bool deedDone = false;
            for (int k = 0; k < MAX_DEP_ARGS; k++) {
                if (!strcmp(indep_helper_proto[arrInd].retTypes[0], dep_args_enum[k]) && stackHasDeps[k]) {
                    struct bpf_insn insn = BPF_LDX_MEM(BPF_DW, j + 1, BPF_REG_10, - (320 + (8 * k)));
                    updateByteCode(bpfByteCode, cnt, insn, false, __LINE__, max_cnt);
                    deedDone = true;
                    break;
                }
            }
            if (deedDone) continue;
            struct bpf_insn insn = BPF_LDX_MEM(BPF_DW, j + 1, BPF_REG_10, - (400 + (8 * j)));
            updateByteCode(bpfByteCode, cnt, insn, false, __LINE__, max_cnt);
        }
    }
    return true;
}

int bpfAttrSize() {
    return sizeof(union bpf_attr);
}

unsigned long long ItmStateSize() {
    return sizeof(struct interm_state) * MAX_INTERM_STATES + sizeof(struct state_hdr);
}
