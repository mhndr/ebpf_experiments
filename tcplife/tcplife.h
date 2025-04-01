
#define TASK_COMM_LEN 16
#define MAX_ENTRIES 10240


//from linux/socket.h
/* Supported address families. */
#define AF_UNSPEC	0
#define AF_UNIX		1	/* Unix domain sockets 		*/
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_INET6	10	/* IP version 6 */

struct id_t {
    __u32 pid;
    char task[TASK_COMM_LEN];
};

struct ip_data_t {
	union {
		__u32 saddr_v4;
		__u8 saddr_v6[16];
	};
	union {
		__u32 daddr_v4;
		__u8 daddr_v6[16];
	};
	char task[TASK_COMM_LEN];
	__u64 rx_b;
	__u64 tx_b;
	__u64 span_us;
	__u64 ts_us;
	__u32 pid;
	__u32 af;
	__u16 lport;
	__u16 dport;
};
