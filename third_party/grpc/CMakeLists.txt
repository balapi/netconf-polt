# grpc - Google RPC
#
include(third_party)

bcm_3rdparty_module_name(grpc "1.26.0")

bcm_3rdparty_add_dependencies(protobuf zlib openssl cares)

bcm_3rdparty_download_wget("https://github.com/grpc/grpc/archive" "v${GRPC_VERSION}.tar.gz")

bcm_3rdparty_add_build_options(-DgRPC_CARES_PROVIDER=package -DgRPC_PROTOBUF_PROVIDER=package)
bcm_3rdparty_add_build_options(-DgRPC_ZLIB_PROVIDER=package -DgRPC_SSL_PROVIDER=package)
bcm_3rdparty_add_build_options(-DZLIB_LIBRARIES=z)
bcm_3rdparty_add_build_options(-DgRPC_BUILD_TESTS=OFF)
bcm_3rdparty_add_build_options(-DgRPC_BUILD_GRPC_RUBY_PLUGIN=OFF -DgRPC_BUILD_GRPC_PHP_PLUGIN=OFF)
bcm_3rdparty_add_build_options(-DgRPC_BUILD_GRPC_NODE_PLUGIN=OFF -DgRPC_BUILD_GRPC_CSHARP_PLUGIN=OFF)
bcm_3rdparty_add_build_options(-DgRPC_BUILD_GRPC_OBJECTIVE_C_PLUGIN=OFF)
if(NOT BCM_CONFIG_HOST MATCHES "x86")
    bcm_3rdparty_add_build_options(-DgRPC_BUILD_CODEGEN=OFF)
    bcm_3rdparty_add_build_options(-DProtobuf_PROTOC_EXECUTABLE=${CMAKE_BINARY_DIR}/../host-sim/fs/bin/protoc)
else()
    set(_GRPC_REFLECTION -lgrpc++_reflection)
endif()
bcm_3rdparty_add_cflags(-std=c++11)
bcm_3rdparty_build_cmake()

bcm_3rdparty_export(rt -lgrpc++ -lgrpc -Wl,--no-as-needed ${_GRPC_REFLECTION} -Wl,--as-needed -laddress_sorting -lcares -lssl -lz -lgpr -lupb -lcrypto)
