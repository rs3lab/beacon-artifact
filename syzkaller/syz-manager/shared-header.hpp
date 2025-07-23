#define MAX_INTERM_STATES 50
#define BPF_REG_SIZE 8
// The bpf.h on server2 lacks of this declaration.
#define BPF_MEMSX   0x80

struct reg_smt_state {
    int type;
    int32_t off;
    uint64_t value;
    uint64_t mask;
    int id;
    int mapfd;
};

struct spi_slots {
    uint8_t type[BPF_REG_SIZE];
    uint8_t value[BPF_REG_SIZE];
};

struct stk_spi {
    uint8_t is_spilled;
    union {
        struct reg_smt_state spilled_reg;
        struct spi_slots slots;
    };
};

struct interm_state {
    int insn_idx;
    int alloc_slots[8];

    int is_spin_locked; // active_lock.ptr == reg->map_ptr (struct bpf_map) or reg->btf (struct btf)
    int spin_lock_id; // active_lock.id

    int id_gen; // env->id_gen
    struct reg_smt_state reg_states[11];
    struct stk_spi stk_spis[8][64];

	uint64_t sample_time;
};


struct state_hdr {
    int total;
    int total_maps;
    struct interm_state *itm_states;
};


enum bpf_reg_type {
    NOT_INIT = 0,        /* nothing was written into register */
    SCALAR_VALUE,        /* reg doesn't contain a valid pointer */
    PTR_TO_CTX,      /* reg points to bpf_context */
    CONST_PTR_TO_MAP,    /* reg points to struct bpf_map */
    PTR_TO_MAP_VALUE,    /* reg points to map element value */
    PTR_TO_MAP_KEY,      /* reg points to a map element key */
    PTR_TO_STACK,        /* reg == frame_pointer + offset */
    PTR_TO_PACKET_META,  /* skb->data - meta_len */
    PTR_TO_PACKET,       /* reg points to skb->data */
    PTR_TO_PACKET_END,   /* skb->data + headlen */
    PTR_TO_FLOW_KEYS,    /* reg points to bpf_flow_keys */
    PTR_TO_SOCKET,       /* reg points to struct bpf_sock */
    PTR_TO_SOCK_COMMON,  /* reg points to sock_common */
    PTR_TO_TCP_SOCK,     /* reg points to struct tcp_sock */
    PTR_TO_TP_BUFFER,    /* reg points to a writable raw tp's buffer */
    PTR_TO_XDP_SOCK,
    PTR_TO_BTF_ID,
    /* PTR_TO_BTF_ID_OR_NULL points to a kernel struct that has not
     * been checked for null. Used primarily to inform the verifier
     * an explicit null check is required for this struct.
     */
    PTR_TO_MEM,      /* reg points to valid memory region */
	PTR_TO_ARENA,
    PTR_TO_BUF,      /* reg points to a read/write buffer */
    PTR_TO_FUNC,         /* reg points to a bpf program function */
    CONST_PTR_TO_DYNPTR,     /* reg points to a const struct bpf_dynptr */
    __BPF_REG_TYPE_MAX,
};

enum bpf_stack_slot_type {
    STACK_INVALID,    /* nothing was stored in this stack slot */
    STACK_SPILL,      /* register spilled into stack */
    STACK_MISC,   /* BPF program wrote some data into this slot */
    STACK_ZERO,   /* BPF program wrote constant zero */
    /* A dynptr is stored in this stack slot. The type of dynptr
     * is stored in bpf_stack_state->spilled_ptr.dynptr.type
     */
    STACK_DYNPTR,
    STACK_ITER,
};
