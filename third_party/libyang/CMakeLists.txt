# libyang - YANG support library
#
include(third_party)

if(NETCONF_TOOLS_FROM_DEVEL)
    set(_VERSION "devel")
else()
    set(_VERSION "1.0.215")
endif()

bcm_3rdparty_module_name(libyang "${_VERSION}")

if("${LIBYANG_VERSION}" STREQUAL "devel")
    bcm_3rdparty_download_wget("https://github.com/CESNET/libyang/archive" "devel.zip" "libyang-devel")
else()
    bcm_3rdparty_download_wget("https://github.com/CESNET/libyang/archive" "v${LIBYANG_VERSION}.tar.gz" libyang-${LIBYANG_VERSION})
endif()

bcm_3rdparty_add_dependencies(pcre)

bcm_3rdparty_add_build_options(-DENABLE_BUILD_TESTS=OFF -DENABLE_VALGRIND_TESTS=OFF -DPLUGINS_DIR=lib/libyang)
bcm_3rdparty_add_build_options(-DPLUGINS_DIR:PATH="${CMAKE_BINARY_DIR}/fs/lib/libyang")

bcm_3rdparty_build_cmake()

bcm_3rdparty_export()
