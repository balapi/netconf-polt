# BAL API
# This version of CMakeLists.txt pull balapi from github and enables integration
# with an application that uses a BAL SDK build system and need to be integrated
# with BAL API

# BAL API version. Must match of of the versions released in github
bcm_make_normal_option(BAL_API_VERSION STRING "BAL API Version" "3.8.8.8")

set(_SUBDIR_LIST bal_api_subdir_list.txt)
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${_SUBDIR_LIST})
    set(_UNPACKED_DIR_NAME bal-sdk-${BAL_API_VERSION})
    set(_BAL_API_DOMAIN https://github.com/balapi/bal-sdk/archive)
    set(_BAL_API_ARCHIVE ${BAL_API_VERSION}.tar.gz)
    if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${_BAL_API_ARCHIVE})
        execute_process(
            COMMAND wget --no-check-certificate ${_BAL_API_DOMAIN}/${_BAL_API_ARCHIVE}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    endif()
    execute_process(
        COMMAND sh -c "rm -fr ${_UNPACKED_DIR_NAME} &&
            tar -xzf ${_BAL_API_ARCHIVE} &&
            grep bcm_add_subdirectory ${_UNPACKED_DIR_NAME}/CMakeLists.txt |
            sed -e 's@bcm_add_subdirectory(@bcm_add_subdirectory(${_UNPACKED_DIR_NAME}/@' > ${_SUBDIR_LIST}"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()

# Include all subdirectories in the bal_api package directly, bypassing its own CMakeLists.txt
include(${_SUBDIR_LIST})

# Create build/fs/include directory with copies of .h files
add_custom_target(github_install_include
        COMMAND mkdir -p ${BUILD_TOP}/fs/include/bal_api
        COMMAND find ${CMAKE_CURRENT_SOURCE_DIR} -path ${BUILD_TOP} -prune -o -name '*.h' -type f -exec cp -f \\{\\} ${BUILD_TOP}/fs/include/bal_api/ \\\;
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
