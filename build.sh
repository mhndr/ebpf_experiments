bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf  -D__TARGET_ARCH_x86 -o ./socket.bpf.o -c ./socket.bpf.c
bpftool  gen skeleton socket.bpf.o name socket > socket.skel.h
cc -lbpf -o socket  `pkg-config --cflags glib-2.0` ./socket.c  `pkg-config --libs glib-2.0` ./libbpf.a
