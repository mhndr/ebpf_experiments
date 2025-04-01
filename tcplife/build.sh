bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf  -D__TARGET_ARCH_x86 -o ./tcplife.bpf.o -c ./tcplife.bpf.c
bpftool  gen skeleton tcplife.bpf.o name tcplife > tcplife.skel.h
cc -lbpf -lelf -lz -ldl -o socket  `pkg-config --cflags glib-2.0` ./tcplife.c  `pkg-config --libs glib-2.0` ./libbpf.a
