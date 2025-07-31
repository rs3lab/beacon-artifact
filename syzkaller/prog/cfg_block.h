#pragma once

enum block_type {
    UNDEF=-1,
    EXIT,
    BRANCH,
    JUMP,
    FALLTHROUGH,
    BLOCK_TYPE_SIZE
};

struct cfg_block {
    // start_idx of block, inclusive. cfg_blocks[start_idx] == this cfg_block
    int start_idx;
    // end_idx of block, inclusive
    int end_idx;
    
    // if true, insns[end_idx] will be an exit
    enum block_type type;

    /*
    If is_exit, must be -1
    If is_branch, will be the idx of the non-fallthrough path
    If is_jump, will be the jump destination
    If is fallthough, will be the end_idx + 1 
    */
    int next_idx;
};
