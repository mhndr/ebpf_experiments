#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "tcplife.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096*64);
} ringbuf SEC(".maps");

struct {
	 __uint(type, BPF_MAP_TYPE_HASH);
	 __uint(max_entries, MAX_ENTRIES);
	 __type(key, sizeof(struct sock *));
	 __type(value, __u64);
} birth SEC(".maps");

struct {
	 __uint(type, BPF_MAP_TYPE_HASH);
	 __uint(max_entries, MAX_ENTRIES);
	 __type(key, sizeof(struct sock));
	 __type(value, struct id_t);
	__uint(map_flags, BPF_F_NO_PREALLOC);

} whoami SEC(".maps");



SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{

	if (ctx->protocol != IPPROTO_TCP)
        return 0;

	pid_t pid = bpf_get_current_pid_tgid() >> 32;


	struct sock *sk = (struct sock *)ctx->skaddr;
        __u16 oldstate = ctx->oldstate;
 	__u16 newstate = ctx->newstate;
	__u16 lport = ctx->sport;
        __u16 dport = ctx->dport;

	bpf_printk("%llx %\n",sk,oldstate,newstate);

	if (newstate < TCP_FIN_WAIT1) {
		__u64 now = bpf_ktime_get_ns();
		bpf_map_update_elem(&birth, &sk, &now, BPF_ANY);
	}

	if (newstate == TCP_SYN_SENT || ctx->newstate == TCP_LAST_ACK) {
        struct id_t me = {.pid = pid};
		bpf_get_current_comm(&me.task, TASK_COMM_LEN);
                bpf_map_update_elem(&whoami,&sk, &me,BPF_ANY);
        }

	if (newstate != TCP_CLOSE)
              return 0;


	// calculate lifespan
 	__u64 delta_us, *tsp = bpf_map_lookup_elem(&birth,&sk);
	if (tsp == 0) {
             bpf_map_delete_elem(&whoami, &sk);
             return 0;               // missed create
        }
        delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
        bpf_map_delete_elem(&birth, &sk);

 	struct id_t *mep;
        mep = bpf_map_lookup_elem(&whoami, &sk);
        if (mep != 0)
            pid = mep->pid;

 	__u16 family = ctx->family;
        // get throughput stats. see tcp_get_info().
        __u64 rx_b = 0, tx_b = 0;
	struct tcp_sock *tp = (struct tcp_sock *)sk;
        bpf_probe_read_kernel(&rx_b, sizeof(rx_b), (void *)&tp->bytes_received);
        bpf_probe_read_kernel(&tx_b, sizeof(tx_b), (void *)&tp->bytes_acked);

	struct ip_data_t *d = bpf_ringbuf_reserve(&ringbuf,sizeof(struct ip_data_t),0);
	if(!d) {
		bpf_printk("bpf_ringbuf_reserve failed \n");
		return 1;
	}
        d->span_us = delta_us;
        d->rx_b = rx_b;
        d->tx_b = tx_b;
        d->ts_us = bpf_ktime_get_ns() / 1000;
        d->pid = pid;
        d->af = ctx->family;
        d->lport = lport;
        d->dport = dport;
        if (ctx->family == AF_INET) {
            BPF_CORE_READ_INTO(&d->saddr_v4, sk, __sk_common.skc_rcv_saddr);
            BPF_CORE_READ_INTO(&d->daddr_v4, sk, __sk_common.skc_daddr);
        } else {
            BPF_CORE_READ_INTO(&d->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
            BPF_CORE_READ_INTO(&d->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
        }
        if (mep == 0) {
            bpf_get_current_comm(d->task, sizeof(d->task));
        } else {
            bpf_probe_read_kernel(&d->task, sizeof(d->task), (void *)mep->task);
        }

	bpf_ringbuf_submit(d,0);
        if (mep != 0)
            bpf_map_delete_elem(&whoami, &sk);



	return 0;
}
