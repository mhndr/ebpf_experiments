#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "tcplife.skel.h"
#include "tcplife.h"
#include <glib.h>


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}


static int event_logger(void* ctx, void* data, size_t len) {
	struct ip_data_t *ip_data = (struct ip_data_t*) data;
	printf("comm = %s, conn span = %luus, %d %d %lu %lu" ,ip_data->task,ip_data->span_us,
			ip_data->lport, ip_data->dport ,ip_data->rx_b,ip_data->tx_b);
	if(ip_data->af == AF_INET){
		int i = ip_data->saddr_v4;
		//TODO: printing ip in reverse, fixit
		printf(" %i.%i.%i.%i " ,
          (i >> 24) & 0xFF,
          (i >> 16) & 0xFF,
          (i >> 8) & 0xFF,
          i & 0xFF);
		i = ip_data->daddr_v4;
		printf("%i.%i.%i.%i\n",
          (i >> 24) & 0xFF,
          (i >> 16) & 0xFF,
          (i >> 8) & 0xFF,
          i & 0xFF);

	}
	else {
		printf(" %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x ",
			(int)ip_data->saddr_v6[0], (int)ip_data->saddr_v6[1],
			 (int)ip_data->saddr_v6[2], (int)ip_data->saddr_v6[3],
			 (int)ip_data->saddr_v6[4], (int)ip_data->saddr_v6[5],
			 (int)ip_data->saddr_v6[6], (int)ip_data->saddr_v6[7],
			 (int)ip_data->saddr_v6[8], (int)ip_data->saddr_v6[9],
			 (int)ip_data->saddr_v6[10], (int)ip_data->saddr_v6[11],
			 (int)ip_data->saddr_v6[12], (int)ip_data->saddr_v6[13],
			 (int)ip_data->saddr_v6[14], (int)ip_data->saddr_v6[15]);
		printf(" %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x \n",
			(int)ip_data->daddr_v6[0], (int)ip_data->daddr_v6[1],
			 (int)ip_data->daddr_v6[2], (int)ip_data->daddr_v6[3],
			 (int)ip_data->daddr_v6[4], (int)ip_data->daddr_v6[5],
			 (int)ip_data->daddr_v6[6], (int)ip_data->daddr_v6[7],
			 (int)ip_data->daddr_v6[8], (int)ip_data->daddr_v6[9],
			 (int)ip_data->daddr_v6[10], (int)ip_data->daddr_v6[11],
			 (int)ip_data->daddr_v6[12], (int)ip_data->daddr_v6[13],
			 (int)ip_data->daddr_v6[14], (int)ip_data->daddr_v6[15]);
	}

	return 0;
}


int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct tcplife *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	//libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = tcplife__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = tcplife__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	//printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	//       "to see output of the BPF programs.\n");

	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), event_logger , NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	while (!stop) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	tcplife__destroy(skel);
	return -err;
}
