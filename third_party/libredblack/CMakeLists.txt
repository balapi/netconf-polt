# libredblack - red-black tree sort
#
include(third_party)

bcm_3rdparty_module_name(libredblack "1.3")

bcm_3rdparty_download_wget("https://sourceforge.net/projects/libredblack/files/libredblack/1.3" "libredblack-${LIBREDBLACK_VERSION}.tar.gz")

bcm_3rdparty_add_build_options(--without-rbgen --without-python)

if(BCM_CONFIG_HOST MATCHES ".*aarch64.*")
    set(${_MOD_NAME_UPPER}_CONFIG_HOST arm-linux)
endif()
bcm_3rdparty_build_automake()

bcm_3rdparty_export()
