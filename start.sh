#!/bin/bash

#Load chuong trinh XDP va ghim map
bpftool prog load /etc/crowdsec/bouncers/xdp_blocker/bpf/xdp_blocker_kern.o /sys/fs/bpf/xdp_blocker type xdp

#Gan chuong trinh XDP vao cong mang dang chay, o day la ens33
ip link set dev [Card mạng cần gán, vd : ens33] xdp pinned /sys/fs/bpf/xdp_blocker

#chay bouncer
python3 /etc/crowdsec/bouncers/xdp_blocker/xdp_bouncer.py

