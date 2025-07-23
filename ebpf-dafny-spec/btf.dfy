include "types.dfy"

predicate bpf_map_btf(off:int64, size:int64)
    {
        (off == 0 && size == 8)
        ||
        (off == 8 && size == 8)
        ||
        (off == 16 && size == 8)
        ||
        (off == 24 && size == 4)
        ||
        (off == 28 && size == 4)
        ||
        (off == 32 && size == 4)
        ||
        (off == 36 && size == 4)
        ||
        (off == 40 && size == 8)
        ||
        (off == 48 && size == 4)
        ||
        (off == 52 && size == 4)
        ||
        (off == 56 && size == 8)
        ||
        (off == 64 && size == 4)
        ||
        (off == 68 && size == 4)
        ||
        (off == 72 && size == 4)
        ||
        (off == 76 && size == 4)
        ||
        (off == 80 && size == 8)
        ||
        (off == 88 && size == 16)
        ||
        (off == 104 && size == 32)
        ||
        (off == 136 && size == 8)
        ||
        (off == 144 && size == 8)
        ||
        (off == 152 && size == 32)
        ||
        (off == 184 && size == 8)
        ||
        (off == 192 && size == 12)
        ||
        (off == 204 && size == 1)
        ||
        (off == 205 && size == 1)
        ||
        (off == 206 && size == 1)
        ||
        (off == 207 && size == 1)
        ||
        (off == 208 && size == 8)
        ||
        (off == 216 && size == 8)
    }