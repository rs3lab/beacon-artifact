#pragma once
#include "../include/linux/bpf.h"
#include "cfg_block.h"
#include "block_llist.hpp"
#include <assert.h>
/*
    Print the block list block by block
*/
void printCFGBlocklist(struct cfg_block *cfg_blocks_list[], int prog_size);

/*
    Print the program instruction by instruction
*/
void printProg(struct bpf_insn * insns, int prog_size);

/*
    Fills out the given block
    Needs the start idx of the block
    Returns the end_idx, or a negative value if there's an error
*/
int fillBlock(struct cfg_block* block, struct bpf_insn * insns, int prog_size, int start_idx);

/*
    Create new block by cutting the block in two
    The old block will be the tail, while the new block is head

    Returns 0 on success, or a negative value if there's an error
*/
int splitBlock(struct cfg_block* block, struct cfg_block* new_block, int dst_idx);

/*
    Transforms all FALLTHROUGH blocks into JUMP blocks. Also adds all branch jumps
    new_insns must be ~ 2 * old_prog_size for this to never segfault (worst case scenario)
    Will translate the swapindxs 

    Returns the new program size, or a negative number if error
*/
int addJumps(struct block_llist* block_list, struct cfg_block *cfg_blocks_list[], struct bpf_insn * insns, int old_prog_size, struct bpf_insn * new_insns,  int* swap_idxs, int swap_idx_num);

/*
    Transforms all frivioulous JUMP into FALLTHROUGH blocks
    new_insns must be old_prog_size for this to never segfault (worst case scenario)

    Returns the new program size, or a negative number if error
*/
int removeJumps(struct cfg_block *cfg_blocks_list[], struct bpf_insn * insns, int old_prog_size, struct bpf_insn * new_insns);

/*
    Swaps fallthough block and branch block, if possible

    Branch idx is the last instruction of the branch basic block

    Returns 0 if success, and a negative number if 'error
*/
int swapBranch(struct cfg_block *cfg_blocks_list[],struct bpf_insn * insns, int prog_size, int branch_idx);

/*
    Create all block that end with a jump
    Does not modify instructions

    Returns 0 if success, and a negative number if error
*/
int createBranchBlocks(struct block_llist* block_list, struct cfg_block *cfg_blocks_list[], struct bpf_insn * insns, int prog_size);

/*
    Modifies insns to create an identical program with the branch at swap_idxs swapped
    insns is a program 
    caller must make sure that insns is big enough to host the new code

    Returns new_program size, 0 if program unchanged, and a negative value if an error was encountered

*/
int synth_cfg(struct bpf_insn * insns, int prog_size, int* swap_idxs, int swap_idx_num);

