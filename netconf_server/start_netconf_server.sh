#!/bin/bash
#set -x
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
# Kill the old netopeer2-server instance unless it is running in the foreground (ie, was started separately)
if $PS | grep netopeer2\-server | grep -v grep | grep '\-d' > /dev/null; then
    echo "netopeer2-server is running in the foreground. Keeping the running instance"
else
    # Kill stale netopeer2-server instance if any
    killall netopeer2-server 2> /dev/null
    echo "Starting netopeer2-server in the background"
    `pwd`/bin/start_netopeer2_server.sh -v3
    sleep 2
fi

if [ "$1" = "gdb" ]; then
    INSTRUMENT="gdb --args"
    shift
fi
if [ "$1" = "valgrind" ]; then
    INSTRUMENT="valgrind"
    shift
fi
$INSTRUMENT ./bcmolt_netconf_server $*
if ! $PS | grep bcmolt_netconf_server | grep -v grep > /dev/null; then
    echo Killing netopeer2-server
    killall netopeer2-server 2> /dev/null
fi
