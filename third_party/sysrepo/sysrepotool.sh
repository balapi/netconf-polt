#!/bin/bash
# Parameters:
# - tool name
# - tool parameters
#set -x

get_abs_dirname() {
  # $1 : relative filename
  if [ -d "$1" ];then
    echo "$(cd "$1" && pwd)"
  else
    echo "$(cd "$(dirname "$1")" && pwd)"
  fi
}

fs_bin_dir=$(get_abs_dirname $0)
tool_name=$1
tool_dir=$(get_abs_dirname $tool_name)
mkdir -p $fs_bin_dir/../sysrepo
sysrepo_dir=$(get_abs_dirname $fs_bin_dir/../sysrepo)
lib_dir=$(get_abs_dirname $tool_dir/../lib)

export LD_LIBRARY_PATH=$lib_dir:$LD_LIBRARY_PATH
export SYSREPO_REPOSITORY_PATH=$sysrepo_dir
if [ -d "$lib_dir/libyang/extensions" ]; then
    export LIBYANG_EXTENSIONS_PLUGINS_DIR=$lib_dir/libyang/extensions
fi
if [ -d "$lib_dir/libyang/user_types" ]; then
    export LIBYANG_USER_TYPES_PLUGINS_DIR=$lib_dir/libyang/user_types
fi
shift
$tool_name $*
