#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("?tc")
int incorrect_range(struct __sk_buff *ctx)
{
	asm volatile (
		"r5 = 100;\
		r5 /= 3;\
		w5 >>= 7;\
		r5 &= -386969681;\
		r5 -= -884670597;\
		w0 = w5;\
		if w0 & 0x894b6a55 goto +2;\
		r2 = 1;\
		r2 = 1;\
		r0 = 0;"
	);
	// if w0 == 0x894b6a55 goto pc+2;
	return 0;
}
