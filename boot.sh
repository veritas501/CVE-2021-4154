qemu-system-x86_64 \
-m 4G \
-kernel bzImage \
-initrd rootfs.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 kaslr quiet" \
-cpu qemu64,+smep,+smap \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic  -monitor /dev/null \
-gdb tcp::1234
