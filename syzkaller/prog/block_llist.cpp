#include "block_llist.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int init_list(struct block_llist* list){
    if (list == NULL){
        return -1;
    }
    list->head = NULL;
    list->tail = NULL;
    return 0;
}

struct cfg_block *insert(struct block_llist* list, struct cfg_block block){
    if (list == NULL){
        return NULL;
    }
    struct block_llist_elem* new_elem = (struct block_llist_elem*) malloc(sizeof(struct block_llist_elem));
    if (new_elem == NULL){
        return NULL;
    }
    new_elem->block = block;
    new_elem->next = NULL;
    if(list->head == NULL){
        // First element
        list->head = new_elem;
        list->tail = new_elem;
    } else {
        list->tail->next = new_elem;
        list->tail = new_elem;
    }
    return &(new_elem->block);
}

void free_list(struct block_llist* list){
    if (list == NULL){
        return;
    }
    struct block_llist_elem* curr = list->head;
    struct block_llist_elem* next;
    while(curr != NULL) {
        next = curr->next;
        free(curr);
        curr = next;
    }
}

void print_list(struct block_llist* list){
    if (list == NULL){
        return;
    }
    struct block_llist_elem* curr = list->head;
    struct block_llist_elem* next;
    while(curr != NULL) {
        next = curr->next;
        int type = curr->block.type; 
        printf("Block from %d to %d, of type %s with next idx %d\n", curr->block.start_idx, curr->block.end_idx, 
            (type == -1)? "UNSPEC":(type == 0) ? "EXIT" :(type == 1) ? "BRANCH" :(type == 2) ? "JUMP" : (type == 3) ? "FALLTHROUGH" : "UNKNOWN", 
            curr->block.next_idx);
        //free(curr);
        curr = next;
    }
}