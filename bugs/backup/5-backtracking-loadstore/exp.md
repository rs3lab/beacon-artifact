# Find the kernel text mapping erea

```c
static int map_create(union bpf_attr *attr) {
    struct bpf_map *map;
    ...
    // ringbuf_map_alloc
    map = ops->map_alloc(attr);
}

static struct bpf_map *ringbuf_map_alloc(union bpf_attr *attr) {
    struct bpf_ringbuf_map *rb_map;
    // allocate 
    rb_map = bpf_map_area_alloc(sizeof(*rb_map), ...);
    rb_map->rb = bpf_ringbuf_alloc(attr->max_entries, ...);
}

struct bpf_ringbuf_map {
    struct bpf_map map {
      const struct bpf_map_ops *ops ____cacheline_aligned;
    }
    struct bpf_ringbuf *rb {
      ...
      char data[] __aligned(PAGE_SIZE);
    }
};
```

```c
static struct bpf_map *array_map_alloc(union bpf_attr *attr) {
    struct bpf_array *array;
    ...
    array_size = sizeof(*array);
    array_size += (u64) max_entries * sizeof(void *);
    array = bpf_map_area_alloc(array_size, ...);
    ...
}

struct bpf_array {
    struct bpf_map map;
    u32 elem_size;
    u32 index_mask;
    struct bpf_array_aux *aux;
    union {
        DECLARE_FLEX_ARRAY(char, value) __aligned(8);
        DECLARE_FLEX_ARRAY(void *, ptrs) __aligned(8);
        DECLARE_FLEX_ARRAY(void __percpu *, pptrs) __aligned(8);
    };
};
```

```c
struct pid_namespace {
    struct idr idr;
    ...
}

struct idr {
    struct radix_tree_root  idr_rt;
    unsigned int        idr_base;
    unsigned int        idr_next;
};

#define radix_tree_root		xarray

struct xarray {
    spinlock_t  xa_lock;
    /* private:
    The rest of the data structure is not to be used directly. */
    gfp_t       xa_flags;
    // #define radix_tree_node		xa_node
    void __rcu *    xa_head;
};

struct xa_node {
    unsigned char   shift;      /* Bits remaining in each slot */
    unsigned char   offset;     /* Slot offset in parent */
    unsigned char   count;      /* Total entry count */
    unsigned char   nr_values;  /* Value entry count */
    struct xa_node __rcu *parent;   /* NULL at top of tree */
    struct xarray   *array;     /* The array we belong to */
    union {
        struct list_head private_list;  /* For tree user */
        struct rcu_head rcu_head;   /* Used when freeing node */
    };
    void __rcu  *slots[XA_CHUNK_SIZE];
    union {
        unsigned long   tags[XA_MAX_MARKS][XA_MARK_LONGS];
        unsigned long   marks[XA_MAX_MARKS][XA_MARK_LONGS];
    };
};

struct pid {
	refcount_t count;
	unsigned int level;
	spinlock_t lock;
	/* lists of tasks that use this pid */
	struct hlist_head tasks[PIDTYPE_MAX];
	struct hlist_head inodes;
	/* wait queue for pidfd notifications */
	wait_queue_head_t wait_pidfd;
	struct rcu_head rcu;
	struct upid numbers[];
};
```


# References
- [pid, task_struct](https://carecraft.github.io/basictheory/2017/03/linux-pid-manage/)