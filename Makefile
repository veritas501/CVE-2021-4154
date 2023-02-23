.PHONY: all

all: exp
	~/exp_sample/ks push rootfs.cpio exp / && \
	bash boot.sh

exp: exp.c
	gcc exp.c -o exp -no-pie -lpthread -static -Werror -Wall -O0 -s