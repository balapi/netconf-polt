# TR-451 pOLT vendor interface: Broadcom
if(TR451_VOMCI_POLT)
bcm_module_name(tr451_polt_vendor)
bcm_module_header_paths(PUBLIC . ..)
bcm_module_dependencies(PUBLIC os dev_log cli host_api)
bcm_module_dependencies(PRIVATE tr451_sbi grpc)
bcm_module_srcs(bcm_tr451_polt_vendor.cc bcm_tr451_polt_vendor_cli.cc)
bcm_create_lib_target()
endif()
