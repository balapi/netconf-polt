# libev - high performance event loop
#
include(third_party)

bcm_3rdparty_module_name(libev "4.31")

bcm_3rdparty_download_wget("http://dist.schmorp.de/libev/Attic" "libev-${LIBEV_VERSION}.tar.gz")

if("${BOARD}" STREQUAL "asfvolt16" OR "${BOARD}" STREQUAL "asgvolt64")
    set(LIBEV-DO_NOT_RECONF true)
endif()

bcm_3rdparty_build_automake()

bcm_3rdparty_export()
