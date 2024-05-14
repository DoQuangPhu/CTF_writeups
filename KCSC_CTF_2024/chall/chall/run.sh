qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -snapshot \
    -kernel bzImage \
    -append 'console=ttyS0 loglevel=0 kpti=1 oops=panic panic=1 kaslr' \
    -monitor /dev/null \
    -no-reboot \
    -initrd ./initramfs.cpio.gz  \
    -cpu kvm64,+smep,+smap 
