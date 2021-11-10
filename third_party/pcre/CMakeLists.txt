# pcre - Perl Regular Expression parser
#
include(third_party)

bcm_3rdparty_module_name(pcre "8.45")

bcm_3rdparty_download_wget("https://sourceforge.net/projects/pcre/files/pcre/${PCRE_VERSION}" "pcre-${PCRE_VERSION}.tar.gz")

bcm_3rdparty_add_dependencies(zlib)

bcm_3rdparty_add_build_options(-DBUILD_SHARED_LIBS=true -DPCRE_SUPPORT_UNICODE_PROPERTIES=true -DPCRE_SUPPORT_UTF=true)

bcm_3rdparty_build_cmake()

bcm_3rdparty_export()
