
#define TASK_COMM_LEN 16
#define MAX_ENTRIES 10240

#define accept 1
#define connect 2

//from linux/socket.h
/* Supported address families. */
#define AF_UNSPEC	0
#define AF_UNIX		1	/* Unix domain sockets 		*/
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_BRIDGE	7	/* Multiprotocol bridge 	*/
#define AF_INET6	10	/* IP version 6			*/
#define AF_SECURITY	14	/* Security callback pseudo AF */
#define AF_KEY		15      /* PF_KEY key management API */
#define AF_NETLINK	16
#define AF_PACKET	17	/* Packet family		*/
#define AF_VSOCK	40	/* vSockets			*/
#define AF_XDP		44	/* XDP sockets			*/
#define AF_MAX		46	/* For now.. */

struct connect_args_t {
	int fd;
	struct sockaddr * uservaddr;
	int addrlen;
};

struct accept_args_t {
	int fd;
	struct sockaddr  * upeer_sockaddr;
	int  * upeer_addrlen;
};

struct accept4_args_t {
	int fd;
	struct sockaddr  * upeer_sockaddr;
	int  * upeer_addrlen;
	int flags;
};


struct sock_fam {
	unsigned short type;
	char comm[TASK_COMM_LEN];
	unsigned short  sa_family;
};
