BPF_HEADERS := /usr/src/kernel-headers/include
BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 \
  -I$(BPF_HEADERS) \
  -I$(BPF_HEADERS)/uapi \
  -I$(BPF_HEADERS)/generated/uapi

all:
	clang $(BPF_CFLAGS) -c xdp_blocker_kern.c -o xdp_blocker_kern.o

clean:
	rm -f *.o
