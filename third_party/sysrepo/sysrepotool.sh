#!/bin/bash
# Parameters:
# - tool name
# - tool parameters
#set -x

fs_bin_dir=`dirname $0`
tool_name=$1
tool_dir=`dirname $1`
mkdir -p $fs_bin_dir/../sysrepo
pushd $fs_bin_dir/../sysrepo
sysrepo_dir=`pwd`
popd
lib_dir=$tool_dir/../lib

export LD_LIBRARY_PATH=$lib_dir:$LD_LIBRARY_PATH
export SYSREPO_REPOSITORY_PATH=$sysrepo_dir
export LIBYANG_EXTENSIONS_PLUGINS_DIR=$lib_dir/libyang/extensions
export LIBYANG_USER_TYPES_PLUGINS_DIR=$lib_dir/libyang/user_types
shift
$tool_name $*
