SEC("socket")
__log_level(2) __success __caps_unpriv(CAP_BPF)
__naked void spill_32bit_onto_64bit_slot(void)
{
       asm volatile("                                  \
       r0 = 0;                                         \
       *(u64*)(r10 - 8) = r0;                          \
       *(u32*)(r10 - 8) = r0;                          \
       exit;                                           \
"      :
       :
       : __clobber_all);
}
