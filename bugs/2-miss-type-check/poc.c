SEC("raw_tp")
int iter_check_arg_type(const void *ctx)
{
        struct bpf_iter_num it;
        int *v;

        int *map_val = NULL;
        int key = 0;

        map_val = bpf_map_lookup_elem(&arr_map, &key);
        if (!map_val)
                return 0;

        bpf_iter_num_new(&it, 0, 3);
        while ((v = bpf_iter_num_next((struct bpf_iter_num*)map_val))) {}
        bpf_iter_num_destroy(&it);

        return 0;
}
