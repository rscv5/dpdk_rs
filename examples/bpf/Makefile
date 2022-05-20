# header path
DPDK:=/home/dpdk-stable-19.11.12
LIB_LINUX_INCLUDE:=$(DPDK)/x86_64-native-linux-gcc/include
LIB_LINUX_INCLUDE_GENERIC:=$(LIB_LINUX_INCLUDE)/generic 

.PHONY:all
all:t4.o
t%.o:t%.c
	clang -O2 -U __GNUC__ -I $(LIB_LINUX_INCLUDE_GENERIC)\
						-I $(LIB_LINUX_INCLUDE)\
						-target bpf \
						-c $<