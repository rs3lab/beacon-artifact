#ifdef __cplusplus
extern "C" {
#endif
// int MutateBPFProg(char *insns1, char* func_info1);
int EquivCFGMutate(char *progAttr, int condInsnIdx);
/*
    Fills branch_idxs with all the branch idx
    caller must make sure that branch_idxs is big enough to host them
    Does not modify instructions

    Returns a negative value if an error was encountered, otherwise the number of idxs

*/
int get_branch_idx(char * insns, int prog_size, int* branch_idxs);
#ifdef __cplusplus
}
#endif
