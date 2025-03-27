#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "socket.skel.h"
#include "socket.h"
#include <glib.h>

GHashTable* accept_map = NULL;
GHashTable* connect_map = NULL;



void print_accept_map( gpointer key, gpointer value, gpointer userData ) {
   	char* realKey =  (char*)key;
   	int* realValue = (int*)value;

	printf( "\n@accept[%s: %d]", realKey, realValue );
   	return;
}

void print_connect_map( gpointer key, gpointer value, gpointer userData ) {
   	char* realKey =  (char*)key;
   	int* realValue = (int*)value;

   	printf( "\n@connect[%s: %d]", realKey, realValue );
   	return;
}


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
	struct sock_fam* sf = (struct sock_fam*) data;
/*	printf("socket family = %d and comm = %s\n" ,sf->sa_family,sf->comm);*/

	GHashTable *map = NULL;
	if(sf->type == accept)
		map = accept_map;
	else
		map = connect_map;

	gpointer value = g_hash_table_lookup(map,(gpointer)sf->comm);
	gpointer key = (gpointer)strdup(sf->comm);

/*
	switch(sf->sa_family) {
		case AF_INET:
			strncat((char*)key,"AF_INET",7);
		case AF_INET6:
			strncat((char*)key,"AF_INET6",8);
		case AF_UNIX:
			strncat((char*)key,"AF_UNIX",7);
		case AF_UNSPEC:
			strncat((char*)key,"AF_UNSPEC",9);
		default:
			strncat((char*)key,"AF_OTHER",8);
	}
*/
	if(value) {
		int new_value = GPOINTER_TO_INT(value)+1;
		g_hash_table_insert(map,key,GINT_TO_POINTER(new_value));
	}
	else {
		g_hash_table_insert(map,key,GINT_TO_POINTER(1));
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct socket *skel;
	int err;

	accept_map = g_hash_table_new(g_str_hash, g_str_equal);
	connect_map = g_hash_table_new(g_str_hash, g_str_equal);

	/* Set up libbpf errors and debug info callback */
	//libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = socket__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = socket__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	//printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	 //      "to see output of the BPF programs.\n");

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
	g_hash_table_foreach(accept_map, print_accept_map, NULL );
	g_hash_table_destroy(accept_map);
	g_hash_table_foreach(connect_map, print_connect_map, NULL );
	g_hash_table_destroy(connect_map);
	socket__destroy(skel);
	return -err;
}

