#include "synth_cfg.hpp"
#include "mutbpfcimport.hpp"
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>


#define FALLTHROUGH_JMP  ((struct bpf_insn) {					\
        .code  = BPF_JMP | BPF_OP(BPF_JA) | BPF_K,		\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = 0 })


static inline int block_size(struct cfg_block block){
    return block.end_idx - block.start_idx + 1;
}

void printProg(struct bpf_insn * insns, int prog_size)
{
    for (int i = 0; i < prog_size; i++) {
        struct bpf_insn j = insns[i];
        fprintf(stderr, "%d: (struct bpf_insn){ .code = %02x, .dst_reg = %d, .src_reg = %d, .off = %d, .imm = %d },\n", i, j.code, j.dst_reg, j.src_reg, j.off, j.imm);
    }
}

void printCFGBlocklist(struct cfg_block *cfg_blocks_list[], int prog_size){
    for (int i = 0; i < prog_size; i++)
    {
        printf("i %d ptr %p\n", i, cfg_blocks_list[i]);
    }
}

int fillBlock(struct cfg_block* block, struct bpf_insn * insns, int prog_size, int start_idx){
    if(block == NULL || insns == NULL || prog_size <= 0 || start_idx < 0 || start_idx >= prog_size) {
        fprintf(stderr, "fillBlock invalid initial values\n");
        return -1;
    }

    block->start_idx = start_idx;
    // Do this for sanitizing
    block->type = UNDEF;
    bool found_end = false;
    int curr_idx = start_idx;
    while(true){
        struct bpf_insn curr_insn = insns[curr_idx];
        //printf("Idx %d has code %02x\n", curr_idx, curr_insn.code);
        __u8 curr_insn_class = BPF_CLASS(curr_insn.code);
        if(curr_insn_class == BPF_JMP || curr_insn_class == BPF_JMP32 ){
            switch (BPF_OP(curr_insn.code)){
            case BPF_CALL:
                fprintf(stderr, "Found call, calls are not supported for now\n");
                break;
            case BPF_EXIT:
                if (curr_insn_class != BPF_JMP){ // Only this allowed
                    fprintf(stderr, "Unknow or unhandeled jump %d\n", curr_insn.code);
                    return -1;
                }
                block->end_idx = curr_idx;
                block->type = EXIT;
                block->next_idx = -1;
                found_end = true;
                break;
            case BPF_JA:
                block->end_idx = curr_idx;
                block->type = JUMP;
                if (curr_insn_class == BPF_JMP){
                    block->next_idx = curr_idx + 1 + curr_insn.off;
                } else {
                    block->next_idx = curr_idx + 1 + curr_insn.imm;
                }
                found_end = true;
                break;
            case BPF_JEQ:
            case BPF_JGT:
            case BPF_JGE:
            case BPF_JSET:
            case BPF_JNE:
            case BPF_JSGT:
            case BPF_JSGE:
            case BPF_JLT:
            case BPF_JLE:
            case BPF_JSLT:
            case BPF_JSLE:
                block->end_idx = curr_idx;
                block->type = BRANCH;
                block->next_idx = curr_idx + 1 + curr_insn.off;
                found_end = true;
                break;
            default:
                fprintf(stderr, "Unknow or unhandeled jump %d\n", curr_insn.code);
                return -1;
            }
                // Only these instruction are of interest
        }
        
        if(found_end){
            break;
        }

        // Prepare for next instruction
        // Special 64 bit load instructions take 2 instruction index
        // https://docs.kernel.org/bpf/standardization/instruction-set.html#bit-immediate-instructions
        if (curr_insn.code == (BPF_IMM | BPF_DW | BPF_LD)){
            // skip next pseudo instruction
            ++curr_idx;
        }
        ++curr_idx;
        if (curr_idx >= prog_size){
            fprintf(stderr, "fillBlock No end found for block starting at %d\n", start_idx);
            return -1;
        }
    }

    if(block->type != EXIT && (block->next_idx < 0 || block->next_idx >= prog_size)){
        return -1;
    }

    return block->end_idx;
}

int splitBlock(struct cfg_block* block, struct cfg_block* new_block, int dst_idx){
    
    if(block == NULL || new_block == NULL || dst_idx < 0){
        fprintf(stderr, "splitBlock invalid initial values\n");
        return -1;
    }
    
    int split_block_idx = block->start_idx;
    block->start_idx = dst_idx;
        

    // Create new block by cutting the block in two
    // The old block will be the tail, while the new block is head
    new_block->start_idx = split_block_idx;
    new_block->end_idx = dst_idx - 1;
    new_block->type = FALLTHROUGH;
    new_block->next_idx = dst_idx;
    return 0;
}

int addJumps(struct block_llist* block_list, struct cfg_block *cfg_blocks_list[], struct bpf_insn * insns, int old_prog_size, struct bpf_insn * new_insns,  int* swap_idxs, int swap_idx_num){
    if(cfg_blocks_list == NULL || cfg_blocks_list[0] == NULL || insns == NULL || old_prog_size <= 0 || new_insns == NULL){
        fprintf(stderr, "addJumps invalid initial values\n");
        return -1;
    }

    /*
        first pass go through the cfg_blocks_list sequentially, creating the new program, along with idx_mapping 
        NOTE: idx_mapping[old_idx] = new_idx
        keep a added_offset, indicating at current_idx how much offset compared to original program (aka # of added instructions)

        for every block update start_idx and end_idx, and create map
        if fallthough: add goto, shift cfg_blocks_list, update added_offset

        /!\ next_idx will be wrong at this point

        second pass update the next_idx, doing next_idx=map[next_idx], and modify the offsets in the program(?)
    */
    
    // A mapping such that  idx_mapping[old_idx] = new_idx
    int idx_mapping[2*old_prog_size];
    memset(idx_mapping, 0, sizeof(int) * 2 * old_prog_size);

    // curr_idx in the new program, equal to old_curr_idx + added offset
    int curr_idx = 0;
    int added_offset = 0;

    while(curr_idx < added_offset + old_prog_size){
        /*
            Invariants: 
                - Upto curr_idx, cfg_blocks_list is updated, with blocks start and end updated, and no FALLTHROUGH
                - Upto curr_idx, new_insn is filled up
                - Upto curr_idx - added offset, idx_mapping is correct
        */

        struct cfg_block* curr_block_ptr = cfg_blocks_list[curr_idx];
        if (curr_block_ptr == NULL){
            fprintf(stderr, "addJumps invalid state of cfg_blocks_list\n");
            return -1;
        }
        assert(curr_block_ptr->start_idx + added_offset == curr_idx);
    
        // Copy program 
        memcpy(&(new_insns[curr_idx]), &(insns[curr_block_ptr->start_idx]), sizeof(struct bpf_insn) * block_size(*curr_block_ptr));
        
        // Create the idx_mapping
        for (size_t i = curr_block_ptr->start_idx; i <= curr_block_ptr->end_idx; i++) {
            idx_mapping[i] = i + added_offset;
        }
        
        // Adjust start and end for new instructions
        curr_block_ptr->start_idx += added_offset;
        curr_block_ptr->end_idx += added_offset;


        curr_idx = curr_block_ptr->end_idx + 1;
        /*
        if(curr_block_ptr->type == FALLTHROUGH){
            // Transform the fallthough
            // Adjust cfg_blocks_list
            memmove(&(cfg_blocks_list[curr_idx+1]), &(cfg_blocks_list[curr_idx]), sizeof(struct cfg_block *)*(old_prog_size -  curr_idx + added_offset));
            cfg_blocks_list[curr_idx] = NULL;

            // Modify fallthrough block
            new_insns[curr_idx] = FALLTHROUGH_JMP;
            curr_block_ptr->type = JUMP;
            ++ curr_block_ptr->end_idx;
            ++ added_offset;
            ++ curr_idx;

        } else 
        */
        if(curr_block_ptr->type == BRANCH) {
            // Add jump block after branch
            // Adjust cfg_blocks_list
            memmove(&(cfg_blocks_list[curr_idx+1]), &(cfg_blocks_list[curr_idx]), sizeof(struct cfg_block *)*(old_prog_size -  curr_idx + added_offset));
            //Create block
            struct cfg_block new_block;
            new_block.start_idx = curr_idx;
            new_block.end_idx = curr_idx;
            new_block.next_idx = curr_idx - added_offset;
            new_block.type = JUMP;
            struct cfg_block * new_block_ptr = insert(block_list, new_block);
            
            cfg_blocks_list[curr_idx] = new_block_ptr;

            // Modify fallthrough block
            new_insns[curr_idx] = FALLTHROUGH_JMP;
            ++ added_offset;
            ++ curr_idx;
        }
    }
    assert(curr_idx == added_offset + old_prog_size);

    
    curr_idx = 0;
    while (curr_idx < added_offset + old_prog_size){
        struct cfg_block* curr_block_ptr = cfg_blocks_list[curr_idx];
        if (curr_block_ptr == NULL){
            fprintf(stderr, "addJumps invalid state of cfg_blocks_list\n");
            return -1;
        }
        
        if(curr_block_ptr->type != EXIT){
            // We need difference in offset between current block and next_idx block
            int target_offset = idx_mapping[curr_block_ptr->next_idx] - curr_block_ptr->next_idx;
            // We use end in case of fallthrough
            int old_end_idx = 0;
            while(idx_mapping[old_end_idx] < curr_block_ptr->end_idx){++old_end_idx;}
            int curr_offset = idx_mapping[old_end_idx] - old_end_idx;
            
            int offset_diff = target_offset - curr_offset;
            // int offset_diff = idx_mapping[curr_block_ptr->end_idx - added_offset] - idx_mapping[curr_block_ptr->next_idx];
            

            // printf("At idx %d, we have diff %d\n", curr_idx, offset_diff);
            // printf("%d will become %d\n", curr_block_ptr->next_idx,  idx_mapping[curr_block_ptr->next_idx]);
            curr_block_ptr->next_idx = idx_mapping[curr_block_ptr->next_idx];
            
            // Modify the instruction
            struct bpf_insn * curr_insn_ptr = &(new_insns[curr_block_ptr->end_idx]);
            assert(BPF_CLASS(curr_insn_ptr->code) == BPF_JMP || BPF_CLASS(curr_insn_ptr->code)  == BPF_JMP32);
            assert(BPF_OP(curr_insn_ptr->code) != BPF_CALL);
            
            if(BPF_OP(curr_insn_ptr->code) == BPF_JA && BPF_CLASS(curr_insn_ptr->code) == BPF_JMP32){
                curr_insn_ptr->imm += offset_diff;
            } else {
                curr_insn_ptr->off += offset_diff;
            }
        }
        
        curr_idx = curr_block_ptr->end_idx + 1;
    }
    assert(curr_idx == added_offset + old_prog_size);
    for (size_t i = 0; i < swap_idx_num; i++)
    {
        swap_idxs[i] = idx_mapping[swap_idxs[i]];
    }
    
    return added_offset + old_prog_size;
}

int removeJumps(struct cfg_block *cfg_blocks_list[], struct bpf_insn * insns, int old_prog_size, struct bpf_insn * new_insns){
    if(cfg_blocks_list == NULL || cfg_blocks_list[0] == NULL || insns == NULL || old_prog_size <= 0 || new_insns == NULL){
        fprintf(stderr, "addJumps invalid initial values\n");
        return -1;
    }

    /*
        See addJumps, as this is very similar. Only difference is that we don't need to create intructions
    */
    // printCFGBlocklist(cfg_blocks_list, old_prog_size);
    // A mapping such that  idx_mapping[old_idx] = new_idx
    int idx_mapping[old_prog_size];
    memset(idx_mapping, 0, sizeof(int) * old_prog_size);

    // curr_idx in the new program, equal to old_curr_idx + added offset
    int curr_idx = 0;
    int removed_offset = 0;

    while(curr_idx < old_prog_size - removed_offset){
        /*
            Invariants: 
                - Upto curr_idx, cfg_blocks_list is updated, with blocks start and end updated, and no FALLTHROUGH
                - Upto curr_idx, new_insn is filled up
                - Upto curr_idx - added offset, idx_mapping is correct
        */
        struct cfg_block* curr_block_ptr = cfg_blocks_list[curr_idx];
        if (curr_block_ptr == NULL){
            fprintf(stderr, "addJumps invalid state of cfg_blocks_list\n");
            return -1;
        }
        assert(curr_block_ptr->start_idx - removed_offset == curr_idx);
    
        // Copy program 
        memcpy(&(new_insns[curr_idx]), &(insns[curr_block_ptr->start_idx]), sizeof(struct bpf_insn) * block_size(*curr_block_ptr));
        
        // Create the idx_mapping
        for (size_t i = curr_block_ptr->start_idx; i <= curr_block_ptr->end_idx; i++) {
            idx_mapping[i] = i - removed_offset;
        }

        bool is_fallthough = curr_block_ptr->type == JUMP && curr_block_ptr->end_idx + 1 == curr_block_ptr->next_idx;
        struct bpf_insn curr_insn = insns[curr_block_ptr->end_idx];
        // Adjust start and end for new instructions

        curr_block_ptr->start_idx -= removed_offset;
        curr_block_ptr->end_idx -= removed_offset;

        curr_idx = curr_block_ptr->end_idx + 1;
        if(!is_fallthough){
            continue;
        }

        assert(curr_insn.code == (BPF_JMP | BPF_OP(BPF_JA) | BPF_K) || curr_insn.code == (BPF_JMP32 | BPF_OP(BPF_JA) | BPF_K));
        assert(curr_insn.dst_reg == 0);
        assert(curr_insn.off == 0);
        assert(curr_insn.imm == 0);
        assert(curr_insn.src_reg == 0);
        
        // Adjust cfg_blocks_list
        memmove(&(cfg_blocks_list[curr_idx-1]), &(cfg_blocks_list[curr_idx]), sizeof(struct cfg_block *)*(old_prog_size -  curr_idx - removed_offset));
        
        cfg_blocks_list[curr_idx] = NULL;

        curr_block_ptr->type = FALLTHROUGH;
        -- curr_block_ptr->end_idx;
        ++ removed_offset;
        curr_block_ptr->next_idx -= removed_offset;
        -- curr_idx;
        if(!block_size(*curr_block_ptr)){
            curr_block_ptr->type = UNDEF;
        }
    }
    assert(curr_idx == old_prog_size - removed_offset);
    // printCFGBlocklist(cfg_blocks_list, old_prog_size - removed_offset);
    curr_idx = 0;
    while (curr_idx <  old_prog_size - removed_offset){
        struct cfg_block* curr_block_ptr = cfg_blocks_list[curr_idx];
        if (curr_block_ptr == NULL){
            fprintf(stderr, "addJumps invalid state of cfg_blocks_list\n");
            return -1;
        }
        
        if(curr_block_ptr->type != EXIT && curr_block_ptr->type != FALLTHROUGH){
            // We need difference in offset between current block and next_idx block
            int target_offset = idx_mapping[curr_block_ptr->next_idx] - curr_block_ptr->next_idx;
            // printf("%d will become %d\n", curr_block_ptr->next_idx,  idx_mapping[curr_block_ptr->next_idx]);
            curr_block_ptr->next_idx = idx_mapping[curr_block_ptr->next_idx];
            
            // Want to find offset of current block, we use end in case of fallthrough
            int old_end_idx = 0;
            while(idx_mapping[old_end_idx] < curr_block_ptr->end_idx){++old_end_idx;}
            int curr_offset = idx_mapping[old_end_idx] - old_end_idx;
            
            int offset_diff = target_offset - curr_offset;
                        
            // Modify the instruction
            struct bpf_insn * curr_insn_ptr = &(new_insns[curr_block_ptr->end_idx]);
            assert(BPF_CLASS(curr_insn_ptr->code) == BPF_JMP || BPF_CLASS(curr_insn_ptr->code)  == BPF_JMP32);
            assert(BPF_OP(curr_insn_ptr->code) != BPF_CALL);
            
            if(BPF_OP(curr_insn_ptr->code) == BPF_JA && BPF_CLASS(curr_insn_ptr->code) == BPF_JMP32){
                curr_insn_ptr->imm += offset_diff;
            } else {
                curr_insn_ptr->off += offset_diff;
            }
        }
        /*
        int type = curr_block_ptr->type; 
        printf("Block from %d to %d, of type %s with next idx %d\n", curr_block_ptr->start_idx, curr_block_ptr->end_idx, 
            (type == -1)? "UNSPEC":(type == 0) ? "EXIT" :(type == 1) ? "BRANCH" :(type == 2) ? "JUMP" : (type == 3) ? "FALLTHROUGH" : "UNKNOWN", 
            curr_block_ptr->next_idx);
        */

        assert(curr_block_ptr->type != FALLTHROUGH || curr_block_ptr->end_idx + 1 == curr_block_ptr->next_idx);
        
        curr_idx = curr_block_ptr->end_idx + 1;
    }
    assert(curr_idx == old_prog_size - removed_offset);

    return old_prog_size - removed_offset;
}

__u8 negateCode(__u8 code){
    __u8 bpf_class = BPF_CLASS(code);
    if(bpf_class != BPF_JMP && bpf_class != BPF_JMP){
        fprintf(stderr, "negateCode called with non-jump instruction\n");
        return -1;
    }
    __u8 is_imm = BPF_SRC(code);
    __u8 neg_op;
    switch(BPF_OP(code)){
        case BPF_JEQ:
            neg_op = BPF_JNE;
            break;
        case BPF_JGT:
            neg_op = BPF_JLE;
            break;
        case BPF_JGE:
            neg_op = BPF_JLT;
            break;
        case BPF_JSET:
            //neg_op = BPF_JLT; //Not sure how to negate thus
            fprintf(stderr, "negateCode called on BPF_JSET\n");

            neg_op = BPF_JSET;
            break;
        case BPF_JNE:
            neg_op = BPF_JEQ;
            break;
        case BPF_JSGT:
            neg_op = BPF_JSLE;
            break;
        case BPF_JSGE:
            neg_op = BPF_JSLT;
            break;
        case BPF_JLT:
            neg_op = BPF_JGE;
            break;
        case BPF_JLE:
            neg_op = BPF_JGT;
            break;
        case BPF_JSLT:
            neg_op = BPF_JSGE;
            break;
        case BPF_JSLE:
            neg_op = BPF_JSGT;
            break;
        default:
            fprintf(stderr, "Unknow or unhandeled jump %d\n", BPF_OP(code));
            return -1;
    }
    return bpf_class | neg_op | is_imm;
}

/*
    Swaps fallthough path and branch path in place, if possible

    Branch idx is the last instruction of the branch basic block

    Returns positive if success, and a negative number if error, and 0 if no change
*/
int swapBranch(struct cfg_block *cfg_blocks_list[], struct bpf_insn * insns, int prog_size, int branch_idx){
    if(cfg_blocks_list == NULL || cfg_blocks_list[0] == NULL || insns == NULL || prog_size <= 0 || branch_idx < 0 || branch_idx >= prog_size){
        fprintf(stderr, "swapBranch invalid initial values\n");
        return -1;
    }

    // Find branch block
    int branch_block_idx = branch_idx;
    while (cfg_blocks_list[branch_block_idx]==NULL){--branch_block_idx;}
    struct cfg_block * branch_block_ptr = cfg_blocks_list[branch_block_idx];
    if( branch_block_ptr->end_idx != branch_idx || branch_block_ptr->type != BRANCH){
        fprintf(stderr, "swapBranch invalid branch_idx given\n");
        return -1;
    }
    /*
    //TODO mark branch as examined (do we check if already examined)
    if(branch_block_ptr->next_idx >= branch_block_ptr->start_idx && branch_block_ptr->end_idx >= branch_block_ptr->next_idx){
        // Self loop, can't swap anything
        return 0;    
    }
    */

    int jump_idx = branch_idx + 1; 
    struct cfg_block * jump_block_ptr = cfg_blocks_list[jump_idx];
    if(jump_block_ptr == NULL || jump_block_ptr->type != JUMP || block_size(*jump_block_ptr) != 1){
        fprintf(stderr, "fallthrough jump is invalid\n");
        return -1;
    }


    int new_code = negateCode(insns[branch_idx].code);
    
    if (new_code == -1 || new_code == insns[branch_idx].code){
        fprintf(stderr, "negateCode identical return value\n");
        return 0;
    }
    // Negate jump condition
    insns[branch_idx].code = new_code;
    
    // Swap in instructions
    int old_jmp_off = insns[jump_idx].off;
    insns[jump_idx].off = insns[branch_idx].off - 1;
    insns[branch_idx].off = old_jmp_off + 1;

    // Swap next in block
    int old_jump_next_idx = jump_block_ptr->next_idx;
    jump_block_ptr->next_idx = branch_block_ptr->next_idx;
    branch_block_ptr->next_idx = old_jump_next_idx;

    return 1;
}

/*
    Create all block that end with a jump
    Does not modify instructions

    Returns 0 if success, and a negative number if error
*/
int createBranchBlocks(struct block_llist* block_list, struct cfg_block *cfg_blocks_list[], struct bpf_insn * insns, int prog_size){
    if(block_list == NULL || cfg_blocks_list == NULL || insns == NULL || prog_size <= 0 ) {
        fprintf(stderr, "createBranchBlocks invalid initial values\n");
        return -1;
    }
    
    int curr_idx = 0;
    while(curr_idx < prog_size){
        struct cfg_block new_block;
        curr_idx = fillBlock(&new_block, insns, prog_size, curr_idx);
        if (curr_idx < 0){
            fprintf(stderr, "fillBlock had error\n");
            //free_list(&block_list);
            return curr_idx;
        }
        // printf("Inserted\n");
        struct cfg_block *block_ptr = insert(block_list, new_block);
        if (block_ptr == NULL){
            fprintf(stderr, "insert into block_list had error\n");
            //free_list(&block_list);
            return -1;
        }
        cfg_blocks_list[new_block.start_idx] = block_ptr;
        ++curr_idx;
    }
    assert(curr_idx == prog_size);    
    return 0;
}


/*
    Split blocks to create fallthrough blocks
    Does not modify insns
    
    Returns 0 if success, and a negative number if error
*/
int createFallthrough(struct block_llist* block_list, struct cfg_block *cfg_blocks_list[], struct bpf_insn * insns, int prog_size){
    if(block_list == NULL || cfg_blocks_list == NULL || insns == NULL || prog_size <= 0 ) {
        fprintf(stderr, "createBranchBlocks invalid initial values\n");
        return -1;
    }
    

    for (size_t block_idx = 0; block_idx < prog_size; block_idx++){
        struct cfg_block *curr_block_ptr = cfg_blocks_list[block_idx];
        if(curr_block_ptr == NULL || curr_block_ptr->type == EXIT || curr_block_ptr->type == FALLTHROUGH ){
            // We are only interested in branch and jump 
            continue;
        }
        int dst_idx = curr_block_ptr->next_idx;
        if(cfg_blocks_list[dst_idx] != NULL){
            // No need to split exisiting block
            continue;
        }
        int split_block_idx = dst_idx - 1;
        while (cfg_blocks_list[split_block_idx] == NULL){
            --split_block_idx;
        }

        assert(split_block_idx >= 0);
        struct cfg_block *split_block_ptr = cfg_blocks_list[split_block_idx];
        assert(split_block_idx == split_block_ptr->start_idx);
        struct cfg_block new_block; 
        
        if(splitBlock(split_block_ptr, &new_block, dst_idx)){
            fprintf(stderr, "split_block had error\n");
            return -1;
        }

        // Insert the fallthrough block
        struct cfg_block *block_ptr = insert(block_list, new_block);
        if (block_ptr == NULL){
            fprintf(stderr, "insert into block_list had error\n");
            return -1;
        }
        
        // Update the cfg_blocks_list
        cfg_blocks_list[split_block_ptr->start_idx] = split_block_ptr;
        cfg_blocks_list[block_ptr->start_idx] = block_ptr;
    }
    return 0;
}


int synth_cfg(struct bpf_insn * insns, int prog_size, int *  swap_idxs, int swap_idx_num){

    static bool debug = true;

    if(insns == NULL || prog_size <= 0){
        fprintf(stderr, "synth_cfg invalid initial values\n");
        return -1;
    }

    // List containing all the blocks
    struct block_llist block_list;

    // cfg_blocks_list at any idx points to the block starting at that idx, and NULL otherwise
    struct cfg_block *cfg_blocks_list[3*prog_size]; 
    memset(cfg_blocks_list, 0, sizeof(struct cfg_block *) * prog_size * 2);
    
    //struct block_llist block_list;
    if(init_list(&block_list)){
        fprintf(stderr, "init_list failed\n");
        free_list(&block_list);
        return -1;
    }
    if(debug)
        printf("Creating Branch Blocks\n");
    // Creating all blocks that end with a JMP 
    int err = createBranchBlocks(&block_list, cfg_blocks_list, insns, prog_size);

    if (err < 0){
        free_list(&block_list);
        return err;
    }


    if(debug){
        print_list(&block_list);
    }

    printf("Add jump\n");
    struct bpf_insn new_insns[2*prog_size];
    int new_prog_size = addJumps(&block_list, cfg_blocks_list, insns, prog_size, new_insns, swap_idxs, swap_idx_num);
    if(new_prog_size < prog_size){
        fprintf(stderr, "addJumps had error\n");
        free_list(&block_list);
        return -1;
    }
    
    if(debug){
        print_list(&block_list);
        printf("Swapping\n");
    }
    //assert(swapBranch(cfg_blocks_list, new_insns, new_prog_size, 6) == 0);
    int total_swap = 0;
    for (size_t i = 0; i < swap_idx_num; i++)
    {
        err = swapBranch(cfg_blocks_list, new_insns, new_prog_size, swap_idxs[i]);
        if (err < 0){
            free_list(&block_list);
            return err;
        }
        total_swap += err;
    }
    if(debug){
        print_list(&block_list);
    }
    

    if(total_swap == 0){
        // No change
        fprintf(stderr, "No changed to be made\n");
        free_list(&block_list);
        return 0;
    }

    if(debug){
        printf("Remove jump\n");
    }
    struct bpf_insn old_insns[new_prog_size];

    new_prog_size = removeJumps(cfg_blocks_list, new_insns, new_prog_size, old_insns);
    if(new_prog_size < prog_size){
        // true if new_prog_size is negative, or if removeJumps deleted too much
        fprintf(stderr, "addJumps had error\n");
        free_list(&block_list);
        return -1;
    }

    if(debug){
        print_list(&block_list);
    }
    memmove(insns, old_insns, new_prog_size * sizeof(struct bpf_insn));
    free_list(&block_list);

    return new_prog_size;
}

int get_branch_idx(char * char_insns, int prog_size, int* branch_idxs){
    static bool debug = true;
    if(char_insns == NULL || prog_size <= 0 || branch_idxs == NULL){
        fprintf(stderr, "get_branch_idx invalid initial values\n");
        return -1;
    }
    struct bpf_insn * insns = (struct bpf_insn *) char_insns;
    // List containing all the blocks
    struct block_llist block_list;

    // cfg_blocks_list at any idx points to the block starting at that idx, and NULL otherwise
    struct cfg_block *cfg_blocks_list[prog_size]; 
    memset(cfg_blocks_list, 0, sizeof(struct cfg_block *) * prog_size);
    
    //struct block_llist block_list;
    if(init_list(&block_list)){
        fprintf(stderr, "init_list failed\n");
        free_list(&block_list);
        return -1;
    }
    if(debug)
        printf("Creating Branch Blocks\n");
    // Creating all blocks that end with a JMP 
    int err = createBranchBlocks(&block_list, cfg_blocks_list, insns, prog_size);

    if (err < 0){
        free_list(&block_list);
        return err;
    }

    int branch_idx = 0;
    int curr_idx = 0;
    for (; curr_idx < prog_size; curr_idx++)
    {
        struct cfg_block * curr_block_ptr = cfg_blocks_list[curr_idx];
        if (curr_block_ptr == NULL){
            free_list(&block_list);
            return -1;
        }
        if(curr_block_ptr->type == BRANCH){
            branch_idxs[branch_idx] = curr_block_ptr->end_idx;
            ++branch_idx;
        }
        curr_idx = curr_block_ptr->end_idx;
    }
    assert(curr_idx == prog_size);

    return branch_idx;
}