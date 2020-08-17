#!/bin/bash

START_DIR=`dirname $0`
cd $START_DIR
export SYSREPO_REPOSITORY_PATH=`pwd`/sysrepo
export LIBYANG_EXTENSIONS_PLUGINS_DIR=`pwd`/lib/libyang/extensions
export LIBYANG_USER_TYPES_PLUGINS_DIR=`pwd`/lib/libyang/user_types
export LD_LIBRARY_PATH=`pwd`/lib:$LD_LIBRARY_PATH

# busibox version of 'ps' doesn't support '-ef' operand
if ls -l `which ps` | grep busybox > /dev/null; then
    PS="ps"
else
    PS="ps -ef"
fi

NETCONF_PARMS=""
if ! $PS | grep netopeer2\-server | grep -v grep > /dev/null; then
    echo "netopeer2-server is NOT running. Please start it first"
    exit -1
fi
if [ "$1" = "gdb" ]; then
    GDB="gdb --args"
    shift
fi
if [ "$1" = "valgrind" ]; then
    GDB="valgrind"
    shift
fi
$GDB ./bcmolt_netconf_server $*
