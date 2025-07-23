// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "repro.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static char log_buf[1024 * 1024];

int main(int argc, char **argv)
{
	struct repro_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts, .kernel_log_level = 2, .kernel_log_buf = log_buf,
                            .kernel_log_size = sizeof(log_buf));

	/* Open BPF application */
	skel = repro_bpf__open_opts(&opts);
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	struct bpf_program *prog;
	prog = bpf_object__next_program(skel->obj, NULL);
    	if (!prog) {
        	err = -ENOENT;
	        return err;
    	}
	// bpf_program__set_type(prog, BPF_PROG_TYPE_SK_LOOKUP);
	// unsigned int flags = bpf_program__flags(prog) | BPF_F_TEST_STATE_FREQ;
    	// bpf_program__set_flags(prog, flags);
	// bpf_program__set_caps(prog, BPF_CAP);

	/* ensure BPF program only handles write() syscalls from our process */
	//skel->bss->my_pid = getpid();

	/* Load & verify BPF programs */
	err = repro_bpf__load(skel);
	printf("Log:\n%s\n", log_buf);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	int prog_fd = bpf_program__fd(skel->progs.leak_ptr);

	/* Attach tracepoint handler */
	/*
	err = repro_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");
	for (;;) {
		// trigger our BPF program
		fprintf(stderr, ".");
		sleep(1);
	}
	*/

	// Set up test input data to simulate a packet (e.g., a basic Ethernet frame)
	char packet[64] = {0};  // Create a mock packet (all zeroed)
	packet[12] = 0x08;      // Mock Ethernet frame, Ethertype set to 0x0800 (IPv4)
	packet[13] = 0x00;
	
	// Set up options for `bpf_prog_test_run_opts`
	LIBBPF_OPTS(bpf_test_run_opts, opts1,
		.sz = sizeof(opts1),
		.data_in = packet,
                .data_size_in = sizeof(packet),
		.data_out = packet,
		.data_size_out = sizeof(packet),
                .repeat = 1,
        );
	
	// Run the BPF program in test mode
	int ret = bpf_prog_test_run_opts(prog_fd, &opts1);
	if (ret) {
		fprintf(stderr, "bpf_prog_test_run_opts failed: %d\n", ret);
		repro_bpf__destroy(skel);
		return 1;
	}

	// Read map value
	unsigned int key = 0;
	unsigned long long value;
	int fd;
    	if((fd = bpf_object__find_map_fd_by_name(skel->obj, "array_map3")) >= 0) {
        	if ((bpf_map_lookup_elem(fd, &key, &value)) != 0) {
			fprintf(stderr, "Could not find key in the map;\n");
		} else {
			fprintf(stderr, "\nLeaked address: %llx\n", value);
		}
	}

cleanup:
	repro_bpf__destroy(skel);
	return -err;
}

