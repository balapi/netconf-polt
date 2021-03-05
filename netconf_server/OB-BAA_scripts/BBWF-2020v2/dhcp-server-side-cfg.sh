#!/bin/sh
# must be executed under sudo
# expect dual-tagged packets with ovid=600 and ivid=10
if [ $# -ne 1 ]; then
   echo "Usage: sudo $0 base-interface-name"
   exit -1
fi
ip link add link $1 name vlan.600 type vlan id 600
ip link add link vlan.600 name vlan.600.10 type vlan id 10
ifconfig vlan.600 up
ifconfig vlan.600.10 192.168.10.1 netmask 255.255.255.0

