# pcre - Perl Regular Expression parser
# version 2.x
#
include(third_party)

bcm_3rdparty_module_name(pcre2 "10.39")

bcm_3rdparty_download_wget("https://github.com/PhilipHazel/pcre2/releases/download/pcre2-${PCRE2_VERSION}" "pcre2-${PCRE2_VERSION}.tar.gz")

bcm_3rdparty_add_dependencies(zlib)

bcm_3rdparty_add_build_options(-DBUILD_SHARED_LIBS=true -DPCRE_SUPPORT_UNICODE_PROPERTIES=true -DPCRE_SUPPORT_UTF=true)

bcm_3rdparty_build_cmake()

bcm_3rdparty_export()
