if [ "$1" -eq 1 ]
then
    sudo qemu-system-x86_64 -m 10240 -smp 4 -chardev socket,id=SOCKSYZ,server=on,nowait,host=localhost,port=6666 -mon chardev=SOCKSYZ,mode=control -display none -serial stdio -device virtio-rng-pci -enable-kvm -cpu host,migratable=off -netdev bridge,id=hn9 -device virtio-net,netdev=hn9,mac=e6:c8:ff:09:76:99 -hda /home/tlyu/ebpf-fuzzing/image/bullseye.img -kernel /home/tlyu/dfs-fuzzing/kernels/bpf-next/arch/x86/boot/bzImage -append "root=/dev/sda console=ttyS0 net.ifnames=0 ip=192.168.0.10" -snapshot
else
    qemu-system-x86_64 \
	-m 2G \
	-smp 2 \
	-kernel /home/tlyu/dfs-fuzzing/kernels/bpf-next/arch/x86/boot/bzImage \
	-append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
	-drive file=/home/tlyu/ebpf-fuzzing/image/bullseye.img,format=raw \
	-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
	-net nic,model=e1000 \
	-enable-kvm \
	-nographic
fi
