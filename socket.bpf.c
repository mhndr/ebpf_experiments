#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "socket.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096*64);
} ringbuf SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, __u32);
 __type(value, struct accept_args_t);
} accept_args SEC(".maps");


/*
 * SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr,
 * 		int, addrlen)
 * */
SEC("tracepoint/syscalls/sys_enter_connect")
int sys_enter_connect(struct trace_event_raw_sys_enter* ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("BPF triggered sys_enter_connect from PID %d.\n", pid);

	struct connect_args_t args={};
	args.uservaddr = (struct sockaddr   *)ctx->args[1];

	struct sock_fam* sf = bpf_ringbuf_reserve(&ringbuf,sizeof(struct sock_fam),0);
    	if(!sf) {
    		bpf_printk("bpf_ringbuf_reserve failed \n");
        	return 1;
    	}

	sf->type = connect;
	bpf_get_current_comm(&(sf->comm),sizeof(sf->comm));
	bpf_probe_read_user(&(sf->sa_family),sizeof(sf->sa_family),&(args.uservaddr->sa_family));
	bpf_ringbuf_submit(sf,0);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int sys_exit_connect(struct trace_event_raw_sys_exit* ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("BPF triggered sys_exit_connect from PID %d.\n", pid);
	return 0;

}


/*
 * SYSCALL_DEFINE3(accept, int, fd, struct sockaddr __user *, upeer_sockaddr,
 *         int __user *, upeer_addrlen)
 **/
SEC("tracepoint/syscalls/sys_enter_accept4")
int sys_enter_accept(struct trace_event_raw_sys_enter* ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("BPF triggered sys_enter_accept4 from PID %d.\n", pid);
	struct accept_args_t args={};
	args.upeer_sockaddr = (struct sockaddr   *)ctx->args[1];

	//store the args to be referred to in exit
	bpf_map_update_elem(&accept_args, &pid, &args, BPF_ANY);

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int sys_exit_accept(struct trace_event_raw_sys_exit* ctx)
{
	struct accept_args_t *args;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("BPF triggered sys_exit_accept4 from PID %d.\n", pid);

	if(ctx->ret > 0) {
		args = bpf_map_lookup_elem(&accept_args, &pid);
		if(!args)
			return 0;

		struct sock_fam* sf = bpf_ringbuf_reserve(&ringbuf,sizeof(struct sock_fam),0);
		if(!sf) {
			bpf_printk("bpf_ringbuf_reserve failed \n");
			return 1;
		}

		sf->type = accept;
		bpf_get_current_comm(&(sf->comm),sizeof(sf->comm));
		bpf_probe_read_user(&(sf->sa_family),sizeof(sf->sa_family),
				&(args->upeer_sockaddr->sa_family));
		bpf_ringbuf_submit(sf,0);
	}
	return 0;
}
