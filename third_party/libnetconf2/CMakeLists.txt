# libnetconf2 - NETCONF agent library
#
include(third_party)

bcm_make_debug_option(NETCONF_TOOLS_FROM_DEVEL BOOL "Take netopeer2, sysrepo, libyang and libnetconf2 from devel" n)
bcm_make_normal_option(NETOPEER2_VERSION_2X BOOL "Use libyang,sysrepo,libnetconf2,netopeer2 v2.x packages" y)
bcm_make_debug_option(NETOPEER2_DEBUG BOOL "Build netopeer2, sysrepo, libyang and libnetconf2 in debug mode" n)

if(NETCONF_TOOLS_FROM_DEVEL)
    set(_VERSION "devel")
    set(NETOPEER2_VERSION_2X y CACHE BOOL "Use libyang,sysrepo,libnetconf2,netopeer2 v2.x packages" FORCE)
elseif(NETOPEER2_VERSION_2X)
    set(_VERSION "2.1.25")
else()
    set(_VERSION "1.1.46")
endif()
bcm_3rdparty_module_name(libnetconf2 ${_VERSION})

if("${LIBNETCONF2_VERSION}" STREQUAL "devel")
    bcm_3rdparty_download_wget("https://github.com/CESNET/libnetconf2/archive" "devel.tar.gz" "libnetconf2-devel")
else()
    bcm_3rdparty_download_wget("https://github.com/CESNET/libnetconf2/archive" "v${LIBNETCONF2_VERSION}.tar.gz")
endif()

bcm_3rdparty_add_dependencies(libyang libssh openssl libgcrypt)
if(NOT NETOPEER2_DEBUG)
    bcm_3rdparty_add_build_options(-DCMAKE_BUILD_TYPE=Release)
endif()
bcm_3rdparty_add_build_options(-DENABLE_BUILD_TESTS=OFF -DENABLE_VALGRIND_TESTS=OFF)
bcm_3rdparty_add_build_options(-DENABLE_SSH=ON -DENABLE_TLS=ON)

bcm_3rdparty_build_cmake()

bcm_3rdparty_export()
