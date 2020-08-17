#!/bin/bash
#set -x

EXE=`which $0`
START_DIR=`dirname $EXE`
export LD_LIBRARY_PATH=$START_DIR/lib:$LD_LIBRARY_PATH
if [ "$1" = "gdb" ]; then
    GDB="gdb --args"
    shift
fi
if [ "$1" = "valgrind" ]; then
    GDB="valgrind"
    shift
fi
$GDB $START_DIR/tr451_polt_daemon $*
