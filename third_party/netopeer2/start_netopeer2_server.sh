#!/bin/bash
# Parameters:
# - tool parameters
# set -x

fs_bin_dir=`dirname $0`
tool_name=$fs_bin_dir/netopeer2-server
pushd $fs_bin_dir/../sysrepo
sysrepo_dir=`pwd`
popd
lib_dir=$fs_bin_dir/../lib

export LD_LIBRARY_PATH=$lib_dir:$LD_LIBRARY_PATH
export SYSREPO_REPOSITORY_PATH=$sysrepo_dir
export LIBYANG_EXTENSIONS_PLUGINS_DIR=$lib_dir/libyang/extensions
export LIBYANG_USER_TYPES_PLUGINS_DIR=$lib_dir/libyang/user_types
if [ "$1" = "gdb" ]; then
    GDB="gdb --args"
    shift
fi

# busibox version of 'ps' doesn't support '-ef' operand
if ls -l `which ps` | grep busybox > /dev/null; then
    PS="ps"
else
    PS="ps -ef"
fi

# cleanup
if $PS | grep netopeer2\-server | grep -v grep > /dev/null; then
    echo netopeer2-server is already running
    exit -1
fi
if [ "`whoami`" = "root" ]; then
    chown -R root:root $sysrepo_dir/*
fi
# Create sysrepo shared directory if doesn't exist
if test ! -d /dev/shm; then
    mkdir /dev/shm
fi
if ! $PS | grep netconf_server | grep -v grep > /dev/null; then
    echo Cleaning up stale state
    unset SHM_PREFIX
    if [ "$SYSREPO_SHM_PREFIX" != "" ]; then
       SHM_PREFIX=${SYSREPO_SHM_PREFIX}
    else
       SHM_PREFIX=sr
    fi
    rm -fr /dev/shm/${SHM_PREFIX}_* /dev/shm/${SHM_PREFIX}sub_* $sysrepo_dir/sr_evpipe* /tmp/netopeer2-server.pid
fi
$GDB $tool_name $*
