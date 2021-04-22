# CMCC vOMCI : API definition
if(TR451_VOMCI_POLT)
bcm_module_name(tr451_sbi)
bcm_module_dependencies(PUBLIC grpc protobuf)
bcm_module_header_paths(PUBLIC .)

file(GLOB _ALL_PROTOS ${CMAKE_CURRENT_SOURCE_DIR}/*.proto)
unset(_ALL_PB_CC)
foreach(_PROTOFILE ${_ALL_PROTOS})
    string(REPLACE "${CMAKE_CURRENT_SOURCE_DIR}/" "" _PROTOFILE ${_PROTOFILE})
    string(REPLACE ".proto" ".pb.cc" _PROTOFILE ${_PROTOFILE})
    list(APPEND _ALL_PB_CC ${_PROTOFILE})
endforeach(_PROTOFILE)
bcm_module_cflags(PUBLIC -Wno-redundant-decls -Wno-switch-default
    -Wno-cast-qual -Wno-shadow -Wno-deprecated-declarations -Wno-unused-variable)
bcm_module_cflags(PUBLIC -std=c++11)
bcm_module_protoc_srcs(
    ${_ALL_PB_CC}
    tr451_vomci_sbi_service.grpc.pb.cc
    )

# Generate C++ files from .proto
bcm_protoc_generate()

# Build library
bcm_create_lib_target()
endif()
