#pragma once
#include "cfg_block.h"

struct block_llist_elem {
    struct cfg_block block;
    struct block_llist_elem* next;
};

struct block_llist{
    struct block_llist_elem* head;
    struct block_llist_elem* tail;
};

// Initializes the llist, returns 0 if no error
int init_list(struct block_llist* list);

struct cfg_block *insert(struct block_llist* list, struct cfg_block block);

// Free's and deletes the llist MUST BE CALLED
void free_list(struct block_llist* list);

void print_list(struct block_llist* list);

