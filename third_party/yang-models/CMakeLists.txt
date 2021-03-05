# yang models
#
include(third_party)

set(YANG_MODEL_PACKAGE_VERSION "2.0")

# Netopeer2 consists from multiple components
# Umbrella module
bcm_3rdparty_module_name(yang-models ${YANG_MODEL_PACKAGE_VERSION})
bcm_3rdparty_add_dependencies(sysrepo)

set(_TR_385_VERSION issue2 CACHE STRING "TR-385 standard version")
if(BCM_CONFIG_HOST MATCHES "x86")
    set(_SYSREPOCTL ${CMAKE_BINARY_DIR}/fs/bin/sysrepoctl)
else()
    set(_SYSREPOCTL ${CMAKE_BINARY_DIR}/../host-sim/fs/bin/sysrepoctl)
endif()
set(_SYSREPOTOOL_WRAPPER ${CMAKE_BINARY_DIR}/fs/bin/sysrepotool.sh)
if(SYSREPO_SHM_PREFIX AND NOT "${SYSREPO_SHM_PREFIX}" STREQUAL "none")
    set(ENV{SYSREPO_SHM_PREFIX} ${SYSREPO_SHM_PREFIX})
endif()

bcm_make_normal_option(USE_OBBAA_YANG_MODELS bool "Use models from OB-BAA bundle" y)

unset(_DIRS)
if (USE_OBBAA_YANG_MODELS)
    if("${_TR_385_VERSION}" STREQUAL "issue2")
        set(_OBBAA_VERSION 4.1)
    else()
        set(_OBBAA_VERSION 4.0)
    endif()

    set(_OB_BAA_MODEL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/OB-BAA-standard-olt-adapter/${_OBBAA_VERSION}/yang)
    list(APPEND _DIRS ${_OB_BAA_MODEL_DIR})
    set(_IETF_IANA_DIR ${_OB_BAA_MODEL_DIR})
    set(_TR_385_DIR ${_OB_BAA_MODEL_DIR})
    set(_TR_385_COMMON_DIR ${_OB_BAA_MODEL_DIR})
    set(_TR_385_EQUIPMENT_DIR ${_OB_BAA_MODEL_DIR})
    set(_TR_385_NETWORKING_DIR ${_OB_BAA_MODEL_DIR})
    set(_TR_385_INTERFACE_DIR ${_OB_BAA_MODEL_DIR})
else()
    file(GLOB_RECURSE _DIRS_AND_FILES LIST_DIRECTORIES true ${CMAKE_CURRENT_SOURCE_DIR}/*)
    foreach(_DIR ${_DIRS_AND_FILES})
        if(IS_DIRECTORY ${_DIR} AND NOT "${_DIR}" MATCHES "${CMAKE_CURRENT_SOURCE_DIR}/OB-BAA-standard-olt-adapter.*")
            list(APPEND _DIRS ${_DIR})
        endif()
    endforeach(_DIR)
    set(_IETF_IANA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/IETF_IANA)
    set(_TR_385_DIR ${CMAKE_CURRENT_SOURCE_DIR}/BBF/TR-385/${_TR_385_VERSION}/standard)
    set(_TR_385_COMMON_DIR ${_TR_385_DIR}/common)
    set(_TR_385_EQUIPMENT_DIR ${_TR_385_DIR}/equipment)
    set(_TR_385_NETWORKING_DIR ${_TR_385_DIR}/networking)
    set(_TR_385_INTERFACE_DIR ${_TR_385_DIR}/interface)
endif()
if("${_TR_385_VERSION}" STREQUAL "issue2")
    set(TR385_ISSUE2 y CACHE BOOL "TR-385 Issue 2" FORCE)
endif()
set(_TR_451_DIR ${CMAKE_CURRENT_SOURCE_DIR}/TR-451)

# Import YANG models to sysrepo
if (USE_OBBAA_YANG_MODELS)
    set(_IMPORT_MODELS
        ${_IETF_IANA_DIR}/ietf-interfaces@2018-02-20.yang
        ${_IETF_IANA_DIR}/iana-if-type@2017-01-19.yang
        ${_IETF_IANA_DIR}/iana-hardware@2018-03-13.yang
        ${_IETF_IANA_DIR}/ietf-hardware.yang
        ${_IETF_IANA_DIR}/ietf-ipfix-psamp@2012-09-05.yang
        ${_IETF_IANA_DIR}/ietf-pseudowires@2018-10-22.yang
        ${_IETF_IANA_DIR}/ietf-alarms@2018-11-22.yang
        ${_IETF_IANA_DIR}/ietf-system.yang
        ${_IETF_IANA_DIR}/ieee802-dot1x.yang
        ${_IETF_IANA_DIR}/ietf-netconf-acm.yang
        ${_TR_385_EQUIPMENT_DIR}/bbf-hardware-types.yang
        ${_TR_385_EQUIPMENT_DIR}/bbf-hardware-extension.yang
        ${_TR_385_INTERFACE_DIR}/bbf-sub-interfaces.yang
        ${_TR_385_INTERFACE_DIR}/bbf-sub-interface-tagging.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-policing-types.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-classifiers.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-policies-sub-interfaces.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-shaping.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-traffic-mngt.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-enhanced-scheduling.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-policer-envelope-profiles.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-policies.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-filters.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-policing.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-types.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-rate-control.yang
        ${_TR_385_NETWORKING_DIR}/bbf-interface-port-reference.yang
        ${_TR_385_NETWORKING_DIR}/bbf-l2-forwarding.yang
        ${_TR_385_COMMON_DIR}/bbf-yang-types.yang
        ${_TR_385_COMMON_DIR}/bbf-dot1q-types.yang
        ${_TR_385_INTERFACE_DIR}/bbf-if-type.yang
        ${_TR_385_INTERFACE_DIR}/bbf-frame-classification.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xpon-types.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xpon-if-type.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xpon.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xponvani.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xponani.yang
        ${_TR_385_INTERFACE_DIR}/bbf-link-table.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xpongemtcont.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xpon-onu-types.yang
        ${_TR_385_INTERFACE_DIR}/bbf-interface-usage.yang
        ${_TR_385_INTERFACE_DIR}/bbf-ghn.yang
        ${_TR_385_INTERFACE_DIR}/bbf-ghs.yang
        ${_TR_385_INTERFACE_DIR}/bbf-vdsl.yang
        ${_TR_385_INTERFACE_DIR}/bbf-selt.yang
        ${_TR_385_INTERFACE_DIR}/bbf-l2-dhcpv4-relay.yang
        ${_TR_385_INTERFACE_DIR}/bbf-hardware-rpf-dpu.yang
        ${_TR_385_INTERFACE_DIR}/bbf-pppoe-intermediate-agent.yang
        ${_TR_385_INTERFACE_DIR}/bbf-fast.yang
        ${_TR_385_INTERFACE_DIR}/bbf-mgmd.yang
        ${_TR_385_INTERFACE_DIR}/bbf-melt.yang
        ${_TR_385_INTERFACE_DIR}/bbf-subscriber-profiles.yang
        ${_TR_385_INTERFACE_DIR}/bbf-ldra.yang
    )

    set(ietf-hardware-features entity-mib hardware-state hardware-sensor hardware-config)

else()
    set(_IMPORT_MODELS
        ${_IETF_IANA_DIR}/ietf-interfaces.yang
        ${_IETF_IANA_DIR}/iana-if-type.yang
        ${_IETF_IANA_DIR}/iana-hardware.yang
        ${_IETF_IANA_DIR}/ietf-hardware.yang
        ${_TR_385_EQUIPMENT_DIR}/bbf-hardware-types.yang
        ${_TR_385_EQUIPMENT_DIR}/bbf-hardware.yang
        ${_TR_385_EQUIPMENT_DIR}/bbf-hardware-transceivers.yang
        ${_TR_385_INTERFACE_DIR}/bbf-sub-interfaces.yang
        ${_TR_385_INTERFACE_DIR}/bbf-sub-interface-tagging.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-policing-types.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-classifiers.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-policies-sub-interfaces.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-enhanced-scheduling.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-policer-envelope-profiles.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-policies.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-filters.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-policing.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-types.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-shaping.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-rate-control.yang
        ${_TR_385_NETWORKING_DIR}/bbf-qos-traffic-mngt.yang
        ${_TR_385_NETWORKING_DIR}/bbf-l2-forwarding.yang
        ${_TR_385_COMMON_DIR}/bbf-yang-types.yang
        ${_TR_385_COMMON_DIR}/bbf-dot1q-types.yang
        ${_TR_385_INTERFACE_DIR}/bbf-if-type.yang
        ${_TR_385_INTERFACE_DIR}/bbf-frame-classification.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xpon-types.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xpon-if-type.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xpon.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xponvani.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xponani.yang
        ${_TR_385_INTERFACE_DIR}/bbf-link-table.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xpongemtcont.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xpon-onu-types.yang
        ${_TR_385_INTERFACE_DIR}/bbf-interface-usage.yang)

    set(ietf-hardware-features entity-mib hardware-state)
    set(bbf-hardware-features additional-hardware-configuration model-name-configuration interface-hardware-reference hardware-component-reset)

endif()

if(TR385_ISSUE2)
    list(APPEND _IMPORT_MODELS
        ${_TR_385_EQUIPMENT_DIR}/bbf-hardware-transceivers-xpon.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xpon-onu-state.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xpon-defects.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xpon-performance-management.yang
        ${_TR_385_INTERFACE_DIR}/bbf-xpon-power-management.yang)
else()
    list(APPEND _IMPORT_MODELS
        ${_TR_385_INTERFACE_DIR}/bbf-xpon-onu-states.yang)
endif()

set(ietf-interfaces-features arbitrary-names pre-provisioning if-mib)
set(ietf-hardware-features hardware-state)
set(bbf-xpongemtcont-features configurable-gemport-id configurable-alloc-id)
set(bbf-xponvani-features configurable-v-ani-onu-id configurable-v-ani-management-gem-port-id)
set(bbf-xponani-features configurable-ani-onu-id configurable-ani-management-gem-port-id)
set(bbf-xpon-features pon-pools)
set(bbf-sub-interfaces-features tag-rewrites)
set(bbf-sub-interface-tagging-features write-pbit-value-in-vlan-tag copy-vlan-id-from-tag-index)
set(bbf-l2-forwarding-features forwarding-databases shared-forwarding-databases mac-learning split-horizon-profiles)

# Import WT-451 models
list(APPEND _IMPORT_MODELS
    ${_TR_451_DIR}/standard/ietf-tcp-common.yang
    ${_TR_451_DIR}/standard/ietf-tcp-server.yang
    ${_TR_451_DIR}/standard/ietf-tcp-client.yang
    ${_TR_451_DIR}/common/bbf-grpc-client.yang
    ${_TR_451_DIR}/common/bbf-nf-client.yang
    ${_TR_451_DIR}/common/bbf-nf-endpoint-filter.yang
    ${_TR_451_DIR}/common/bbf-nf-server.yang
    ${_TR_451_DIR}/polt/bbf-polt-vomci.yang)
set(ietf-tcp-client-features local-binding-supported)
set(bbf-polt-vomci-features nf-client-supported nf-server-supported)
list(APPEND _DIRS ${_TR_451_DIR}/standard ${_TR_451_DIR}/common ${_TR_451_DIR}/types)

unset(_SEARCH_DIRS)
foreach(_DIR ${_DIRS})
    if(_SEARCH_DIRS)
        set(_SEARCH_DIRS "${_SEARCH_DIRS}:${_DIR}")
    else()
        set(_SEARCH_DIRS "--search-dirs ${_DIR}")
    endif()
endforeach(_DIR)

# Import models
unset(_FEATURES_OPT)
unset(_FEATURES_OPT_CMD)
unset(_FEATURES_OPT_CMD_ECHO)
unset(_IMPORT_INSTALLED)
unset(_IMPORT_INSTALLED_PREV)
foreach(_IMPORT ${_IMPORT_MODELS})
    get_filename_component(_IMPORT_NAME ${_IMPORT} NAME_WE)
    string(REGEX REPLACE "(.*)@(.*)" "\\1" _IMPORT_NAME_UNVERSIONED "${_IMPORT_NAME}")
    get_filename_component(_IMPORT_DIR ${_IMPORT} DIRECTORY)
    set(_IMPORT_INSTALLED_PREV ${_IMPORT_INSTALLED})
    set(_IMPORT_INSTALLED ${CMAKE_CURRENT_BINARY_DIR}/.${_IMPORT_NAME}.installed)
    set(_FEATURES ${_IMPORT_NAME_UNVERSIONED}-features)
    if(${_FEATURES})
        foreach(_FEATURE ${${_FEATURES}})
            list(APPEND _FEATURES_OPT --enable-feature ${_FEATURE})
        endforeach(_FEATURE)
    endif()
    if(_FEATURES_OPT)
        set(_FEATURES_OPT_CMD COMMAND ${_SYSREPOTOOL_WRAPPER} ${_SYSREPOCTL} --change ${_IMPORT_NAME_UNVERSIONED} ${_FEATURES_OPT})
        set(_FEATURES_OPT_CMD_ECHO COMMAND echo ${_SYSREPOTOOL_WRAPPER} ${_SYSREPOCTL} --change ${_IMPORT_NAME_UNVERSIONED} ${_FEATURES_OPT})
    endif()
    add_custom_command(OUTPUT ${_IMPORT_INSTALLED}
        COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND echo ${_SYSREPOTOOL_WRAPPER} ${_SYSREPOCTL} --install ${_IMPORT} ${_SEARCH_DIRS}
        COMMAND ${_SYSREPOTOOL_WRAPPER} ${_SYSREPOCTL} --install ${_IMPORT} ${_SEARCH_DIRS}
        ${_FEATURES_OPT_CMD_ECHO}
        ${_FEATURES_OPT_CMD}
        COMMAND echo ${_IMPORT} imported to sysrepo
        COMMAND touch ${_IMPORT_INSTALLED}
        DEPENDS sysrepo netopeer2-server ${_IMPORT_INSTALLED_PREV}
        WORKING_DIRECTORY ${_IMPORT_DIR})
    unset(_FEATURES_OPT)
    unset(_FEATURES_OPT_CMD)
    unset(_FEATURES_OPT_CMD_ECHO)
endforeach(_IMPORT)
add_custom_target(yang-models-push-scheduled-changes
    COMMAND ${_SYSREPOTOOL_WRAPPER} ${_SYSREPOCTL} -l > /dev/null
    DEPENDS ${_IMPORT_INSTALLED}
    WORKING_DIRECTORY ${_IMPORT_DIR})

bcm_3rdparty_add_dependencies(yang-models-push-scheduled-changes)
bcm_3rdparty_build_dummy()
bcm_3rdparty_export()
