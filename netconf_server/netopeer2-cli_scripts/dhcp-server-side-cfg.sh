#!/bin/sh
# must be executed under sudo
# expect dual-tagged packets with ovid=20 and ivid=100
if [ $# -ne 1 ]; then
   echo "Usage: sudo $0 base-interface-name"
   exit -1
fi
ip link add link $1 name vlan.20 type vlan id 20
ip link add link vlan.20 name vlan.20.100 type vlan id 100
ifconfig vlan.20 up
ifconfig vlan.20.100 192.168.10.1 netmask 255.255.255.0

