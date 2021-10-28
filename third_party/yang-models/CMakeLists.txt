# yang models
#
include(third_party)

set(YANG_MODEL_PACKAGE_VERSION "2.0")

# Netopeer2 consists from multiple components
# Umbrella module
bcm_3rdparty_module_name(yang-models ${YANG_MODEL_PACKAGE_VERSION})
bcm_3rdparty_add_dependencies(sysrepo)

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
bcm_make_normal_option(OBBAA_DEVICE_ADAPTER_VERSION string "OB-BAA device adapter vesrion: 1.0 or 2.0" "1.0")

unset(_DIRS)
if (USE_OBBAA_YANG_MODELS)
    if(NOT ("${OBBAA_DEVICE_ADAPTER_VERSION}" STREQUAL "1.0") AND NOT ("${OBBAA_DEVICE_ADAPTER_VERSION}" STREQUAL "2.0"))
        message(FATAL_ERROR "OBBAA_DEVICE_ADAPTER_VERSION '${OBBAA_DEVICE_ADAPTER_VERSION}' is invalid. Must be 1.0 or 2.0")
    endif()
    if("${OBBAA_DEVICE_ADAPTER_VERSION}" STREQUAL "1.0")
        set(TR385_ISSUE2 n CACHE BOOL "TR-385 Issue 2" FORCE)
    else()
        set(TR385_ISSUE2 y CACHE BOOL "TR-385 Issue 2" FORCE)
    endif()

    set(_OB_BAA_MODEL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/OB-BAA-standard-olt-adapter/${OBBAA_DEVICE_ADAPTER_VERSION}/yang)
    list(APPEND _DIRS ${_OB_BAA_MODEL_DIR})
    set(_TR_385_EQUIPMENT_DIR ${_OB_BAA_MODEL_DIR})
    set(_TR_385_INTERFACE_DIR ${_OB_BAA_MODEL_DIR})
else()
    set(_TR_385_VERSION issue2 CACHE STRING "TR-385 standard version")
    file(GLOB_RECURSE _DIRS_AND_FILES LIST_DIRECTORIES true ${CMAKE_CURRENT_SOURCE_DIR}/*)
    foreach(_DIR ${_DIRS_AND_FILES})
        if(IS_DIRECTORY ${_DIR} AND NOT "${_DIR}" MATCHES "${CMAKE_CURRENT_SOURCE_DIR}/OB-BAA-standard-olt-adapter.*")
            list(APPEND _DIRS ${_DIR})
        endif()
    endforeach(_DIR)
    set(_TR_385_DIR ${CMAKE_CURRENT_SOURCE_DIR}/BBF/TR-385/${_TR_385_VERSION}/standard)
    set(_TR_385_COMMON_DIR ${_TR_385_DIR}/common)
    set(_TR_385_EQUIPMENT_DIR ${_TR_385_DIR}/equipment)
    set(_TR_385_NETWORKING_DIR ${_TR_385_DIR}/networking)
    set(_TR_385_INTERFACE_DIR ${_TR_385_DIR}/interface)
    if("${_TR_385_VERSION}" STREQUAL "issue2")
        set(TR385_ISSUE2 y CACHE BOOL "TR-385 Issue 2" FORCE)
    endif()
endif()
set(_IETF_IANA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/IETF_IANA)
set(_TR_451_DIR ${CMAKE_CURRENT_SOURCE_DIR}/TR-451)

# Import YANG models to sysrepo
if (USE_OBBAA_YANG_MODELS)
    if("${OBBAA_DEVICE_ADAPTER_VERSION}" STREQUAL "1.0")
        set(_IMPORT_MODELS
            ${_OB_BAA_MODEL_DIR}/ietf-interfaces@2018-02-20.yang
            ${_OB_BAA_MODEL_DIR}/iana-if-type@2017-01-19.yang
            ${_OB_BAA_MODEL_DIR}/iana-hardware@2018-03-13.yang
            ${_OB_BAA_MODEL_DIR}/ietf-hardware.yang
            ${_OB_BAA_MODEL_DIR}/ietf-ipfix-psamp@2012-09-05.yang
            ${_OB_BAA_MODEL_DIR}/ietf-pseudowires@2018-10-22.yang
            ${_OB_BAA_MODEL_DIR}/ietf-alarms@2019-09-11.yang
            ${_OB_BAA_MODEL_DIR}/ietf-system.yang
            ${_OB_BAA_MODEL_DIR}/ieee802-dot1x.yang
            ${_OB_BAA_MODEL_DIR}/bbf-hardware-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-hardware-extension.yang
            ${_OB_BAA_MODEL_DIR}/bbf-sub-interfaces.yang
            ${_OB_BAA_MODEL_DIR}/bbf-sub-interface-tagging.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-policing-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-classifiers.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-policies-sub-interfaces.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-shaping.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-traffic-mngt.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-enhanced-scheduling.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-policer-envelope-profiles.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-policies.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-filters.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-policing.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-rate-control.yang
            ${_OB_BAA_MODEL_DIR}/bbf-interface-port-reference.yang
            ${_OB_BAA_MODEL_DIR}/bbf-l2-forwarding.yang
            ${_OB_BAA_MODEL_DIR}/bbf-yang-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-dot1q-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-if-type.yang
            ${_OB_BAA_MODEL_DIR}/bbf-frame-classification.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xpon-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xpon-if-type.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xpon.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xponvani.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xponani.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xpon-onu-states.yang
            ${_OB_BAA_MODEL_DIR}/bbf-link-table.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xpongemtcont.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xpon-onu-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-interface-usage.yang
            ${_OB_BAA_MODEL_DIR}/bbf-ghn.yang
            ${_OB_BAA_MODEL_DIR}/bbf-ghs.yang
            ${_OB_BAA_MODEL_DIR}/bbf-vdsl.yang
            ${_OB_BAA_MODEL_DIR}/bbf-selt.yang
            ${_OB_BAA_MODEL_DIR}/bbf-l2-dhcpv4-relay.yang
            ${_OB_BAA_MODEL_DIR}/bbf-hardware-rpf-dpu.yang
            ${_OB_BAA_MODEL_DIR}/bbf-pppoe-intermediate-agent.yang
            ${_OB_BAA_MODEL_DIR}/bbf-fast.yang
            ${_OB_BAA_MODEL_DIR}/bbf-mgmd.yang
            ${_OB_BAA_MODEL_DIR}/bbf-melt.yang
            ${_OB_BAA_MODEL_DIR}/bbf-subscriber-profiles.yang
            ${_OB_BAA_MODEL_DIR}/bbf-ldra.yang
            ${_OB_BAA_MODEL_DIR}/bbf-obbaa-mfc-conf.yang
            ${_OB_BAA_MODEL_DIR}/bbf-vomci-entity.yang
            ${_OB_BAA_MODEL_DIR}/bbf-omci-message-retransmission.yang
            ${_OB_BAA_MODEL_DIR}/bbf-network-function-endpoint-filter.yang
            ${_OB_BAA_MODEL_DIR}/bbf-device-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-network-function-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-grpc-client.yang
            ${_OB_BAA_MODEL_DIR}/bbf-network-function-server.yang
            ${_OB_BAA_MODEL_DIR}/bbf-network-function-client.yang
            ${_OB_BAA_MODEL_DIR}/bbf-vomci-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-olt-vomci.yang
        )
        set(ietf-hardware-features entity-mib hardware-state hardware-sensor hardware-config)
        set(bbf-obbaa-mfc-conf-features control-relay nf-client-supported nf-server-supported)
        list(APPEND _DIRS ${_TR_451_DIR}/common ${_TR_451_DIR}/types ${_TR_451_DIR}/wt-383-common)
    else("${OBBAA_DEVICE_ADAPTER_VERSION}" STREQUAL "1.0")
        set(_IMPORT_MODELS
            ${_OB_BAA_MODEL_DIR}/ietf-pseudowires@2018-10-22.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-composite-filters.yang
            ${_OB_BAA_MODEL_DIR}/bbf-hardware-rpf-dpu-state.yang
            ${_OB_BAA_MODEL_DIR}/ieee802-dot1x.yang
            ${_OB_BAA_MODEL_DIR}/bbf-alarm-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xpon-power-management.yang
            ${_OB_BAA_MODEL_DIR}/bbf-l2-forwarding-shared-fdb.yang
            ${_OB_BAA_MODEL_DIR}/bbf-hardware-cpu.yang
            ${_OB_BAA_MODEL_DIR}/iana-hardware.yang
            ${_OB_BAA_MODEL_DIR}/ietf-yang-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-network-function-client.yang
            ${_OB_BAA_MODEL_DIR}/ietf-ethertypes.yang
            ${_OB_BAA_MODEL_DIR}/ietf-packet-fields.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-enhanced-scheduling.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-enhanced-scheduling-state.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-ancp-interfaces.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xpon-defects.yang
            ${_OB_BAA_MODEL_DIR}/bbf-ptm.yang
            ${_OB_BAA_MODEL_DIR}/bbf-pppoe-intermediate-agent.yang
            ${_OB_BAA_MODEL_DIR}/bbf-link-table.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-filters.yang
            ${_OB_BAA_MODEL_DIR}/bbf-if-type.yang
            ${_OB_BAA_MODEL_DIR}/bbf-hardware-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-l2-terminations.yang
            ${_OB_BAA_MODEL_DIR}/bbf-availability.yang
            ${_OB_BAA_MODEL_DIR}/bbf-inet-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-vomci-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xpon-if-type.yang
            ${_OB_BAA_MODEL_DIR}/bbf-hardware-rpf-dpu.yang
            ${_OB_BAA_MODEL_DIR}/ietf-ipfix-psamp.yang
            ${_OB_BAA_MODEL_DIR}/bbf-mgmd.yang
            ${_OB_BAA_MODEL_DIR}/bbf-ethernet-performance-management.yang
            ${_OB_BAA_MODEL_DIR}/bbf-ancp-fastdsl-access-extensions.yang
            ${_OB_BAA_MODEL_DIR}/ietf-hardware.yang
            ${_OB_BAA_MODEL_DIR}/ieee802-dot1x-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-gbond.yang
            ${_OB_BAA_MODEL_DIR}/bbf-hardware.yang
            ${_OB_BAA_MODEL_DIR}/bbf-interface-usage.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-traffic-mngt.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-traffic-mngt-state.yang
            ${_OB_BAA_MODEL_DIR}/bbf-device-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-l2-dhcpv4-relay.yang
            ${_OB_BAA_MODEL_DIR}/bbf-vdsl-alarm-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-interfaces-performance-management.yang
            ${_OB_BAA_MODEL_DIR}/bbf-hardware-transceivers.yang
            ${_OB_BAA_MODEL_DIR}/bbf-olt-vomci.yang
            ${_OB_BAA_MODEL_DIR}/bbf-ancp-fastdsl-threshold.yang
            ${_OB_BAA_MODEL_DIR}/bbf-vdsl.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xpon-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xpon-onu-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-subscriber-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-fast-alarm-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-sub-interface-tagging.yang
            ${_OB_BAA_MODEL_DIR}/ietf-hardware-state.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xponani.yang
            ${_OB_BAA_MODEL_DIR}/bbf-network-function-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-l2-dhcpv4-relay-forwarding.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-classifiers.yang
            ${_OB_BAA_MODEL_DIR}/bbf-ghs.yang
            ${_OB_BAA_MODEL_DIR}/bbf-ghn.yang
            ${_OB_BAA_MODEL_DIR}/bbf-frame-classification.yang
            ${_OB_BAA_MODEL_DIR}/bbf-frame-processing-profiles.yang
            ${_OB_BAA_MODEL_DIR}/bbf-interfaces-statistics-management.yang
            ${_OB_BAA_MODEL_DIR}/ietf-inet-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-hardware-rpf-dpu-alarm-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-l2-forwarding.yang
            ${_OB_BAA_MODEL_DIR}/iana-if-type.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xpongemtcont-qos.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-rate-control.yang
            ${_OB_BAA_MODEL_DIR}/bbf-sub-interfaces.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-policies-sub-interfaces.yang
            ${_OB_BAA_MODEL_DIR}/ietf-interfaces.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-shaping.yang
            ${_OB_BAA_MODEL_DIR}/bbf-hardware-transceivers-xpon.yang
            ${_OB_BAA_MODEL_DIR}/bbf-vomci-entity.yang
            ${_OB_BAA_MODEL_DIR}/ietf-system.yang
            ${_OB_BAA_MODEL_DIR}/bbf-network-function-server.yang
            ${_OB_BAA_MODEL_DIR}/ieee802-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xponani-power-management.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-policies-sub-interface-rewrite.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-policer-envelope-profiles.yang
            ${_OB_BAA_MODEL_DIR}/bbf-network-function-endpoint-filter.yang
            ${_OB_BAA_MODEL_DIR}/bbf-yang-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xpon.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-policies.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-policies-state.yang
            ${_OB_BAA_MODEL_DIR}/bbf-subscriber-profiles.yang
            ${_OB_BAA_MODEL_DIR}/bbf-melt.yang
            ${_OB_BAA_MODEL_DIR}/bbf-kafka-agent.yang
            ${_OB_BAA_MODEL_DIR}/bbf-fastdsl.yang
            ${_OB_BAA_MODEL_DIR}/bbf-hardware-storage-drives.yang
            ${_OB_BAA_MODEL_DIR}/ietf-alarms-x733.yang
            ${_OB_BAA_MODEL_DIR}/bbf-grpc-client.yang
            ${_OB_BAA_MODEL_DIR}/bbf-gbond-state.yang
            ${_OB_BAA_MODEL_DIR}/ietf-http-server.yang
            ${_OB_BAA_MODEL_DIR}/bbf-dot1q-types.yang
            ${_OB_BAA_MODEL_DIR}/ietf-yang-library.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xpon-onu-state.yang
            ${_OB_BAA_MODEL_DIR}/bbf-mgmd-mrd.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xponvani-power-management.yang
            ${_OB_BAA_MODEL_DIR}/bbf-ldra.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xpongemtcont-gemport-performance-management.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xpongemtcont.yang
            ${_OB_BAA_MODEL_DIR}/bbf-ancp.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-policing-types.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-policing.yang
            ${_OB_BAA_MODEL_DIR}/bbf-qos-policing-state.yang
            ${_OB_BAA_MODEL_DIR}/bbf-mgmd-types.yang
            ${_OB_BAA_MODEL_DIR}/ietf-routing-types@2017-12-04.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xpon-performance-management.yang
            ${_OB_BAA_MODEL_DIR}/ietf-http-client.yang
            ${_OB_BAA_MODEL_DIR}/bbf-xponvani.yang
            ${_OB_BAA_MODEL_DIR}/bbf-fast.yang
            ${_OB_BAA_MODEL_DIR}/bbf-selt.yang
            ${_OB_BAA_MODEL_DIR}/ietf-alarms.yang
            ${_OB_BAA_MODEL_DIR}/bbf-omci-message-retransmission.yang
            ${_OB_BAA_MODEL_DIR}/ieee802-ethernet-interface.yang
            ${_OB_BAA_MODEL_DIR}/bbf-obbaa-mfc-conf.yang
        )
        set(ietf-hardware-features entity-mib hardware-state hardware-sensor)
        set(bbf-hardware-features interface-hardware-management)
        set(bbf-xpon-power-management-features xpon-power-management)
    endif("${OBBAA_DEVICE_ADAPTER_VERSION}" STREQUAL "1.0")
    set(bbf-olt-vomci-features nf-client-supported nf-server-supported)
    set(bbf-network-function-client-features grpc-client-supported)
    set(bbf-obbaa-mfc-conf-features control-relay nf-client-supported nf-server-supported)
    list(APPEND _DIRS ${_IETF_IANA_DIR})
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
endif()

list(APPEND bbf-hardware-features additional-hardware-configuration model-name-configuration interface-hardware-reference hardware-component-reset)
set(ietf-interfaces-features arbitrary-names pre-provisioning if-mib)
set(bbf-xpongemtcont-features configurable-gemport-id configurable-alloc-id)
set(bbf-xponvani-features configurable-v-ani-onu-id configurable-v-ani-management-gem-port-id)
set(bbf-xponani-features configurable-ani-onu-id configurable-ani-management-gem-port-id)
set(bbf-xpon-features pon-pools)
set(bbf-sub-interfaces-features tag-rewrites)
set(bbf-sub-interface-tagging-features write-pbit-value-in-vlan-tag copy-vlan-id-from-tag-index)
set(bbf-l2-forwarding-features forwarding-databases shared-forwarding-databases mac-learning split-horizon-profiles)

# Import modules required for netopeer2 server
list(APPEND _IMPORT_MODELS
    ${_IETF_IANA_DIR}/iana-crypt-hash.yang
    ${_IETF_IANA_DIR}/ietf-crypto-types.yang
    ${_IETF_IANA_DIR}/ietf-x509-cert-to-name.yang
    ${_IETF_IANA_DIR}/ietf-datastores.yang
    ${_IETF_IANA_DIR}/ietf-keystore.yang
    ${_IETF_IANA_DIR}/ietf-truststore.yang
    ${_IETF_IANA_DIR}/ietf-tcp-common.yang
    ${_IETF_IANA_DIR}/ietf-tcp-client.yang
    ${_IETF_IANA_DIR}/ietf-tcp-server.yang
    ${_IETF_IANA_DIR}/ietf-tls-common.yang
    ${_IETF_IANA_DIR}/ietf-tls-server.yang
    ${_IETF_IANA_DIR}/ietf-tls-client.yang
    ${_IETF_IANA_DIR}/ietf-netconf-notifications.yang
    ${_IETF_IANA_DIR}/ietf-ssh-common.yang
    ${_IETF_IANA_DIR}/ietf-ssh-client.yang
    ${_IETF_IANA_DIR}/ietf-ssh-server.yang
    ${_IETF_IANA_DIR}/ietf-netconf.yang
    ${_IETF_IANA_DIR}/ietf-netconf-server.yang
    ${_IETF_IANA_DIR}/ietf-netconf-nmda.yang
    ${_IETF_IANA_DIR}/ietf-netconf-acm.yang
    ${_IETF_IANA_DIR}/ietf-netconf-monitoring.yang
    ${_IETF_IANA_DIR}/ietf-ip.yang
    ${_IETF_IANA_DIR}/ietf-subscribed-notifications.yang
    ${_IETF_IANA_DIR}/ietf-yang-push.yang
    ${_IETF_IANA_DIR}/ietf-network-instance.yang
    ${_IETF_IANA_DIR}/ietf-restconf.yang
    ${_IETF_IANA_DIR}/ietf-yang-patch.yang
    ${_IETF_IANA_DIR}/ietf-yang-schema-mount.yang
    ${_IETF_IANA_DIR}/notifications.yang
    ${_IETF_IANA_DIR}/nc-notifications.yang)
set(ietf-tcp-client-features local-binding-supported)
set(ietf-netconf-nmda-features origin with-defaults)
set(ietf-netconf-features candidate writable-running rollback-on-error validate startup url xpath)
set(ietf-keystore-features keystore-supported)
set(ietf-truststore-features truststore-supported public-keys certificates)
set(ietf-tcp-common-features keepalives-supported)
set(ietf-ssh-server-features ssh-server-transport-params-config client-auth-config-supported client-auth-publickey client-auth-password)
set(ietf-tls-server-features client-auth-config-supported psk-auth)
set(ietf-netconf-server-features ssh-listen tls-listen ssh-call-home tls-call-home)
set(ietf-subscribed-notifications-features encode-xml replay subtree xpath)
set(ietf-yang-push-features on-change)

# Import WT-451 models
if (NOT USE_OBBAA_YANG_MODELS)
    list(APPEND _IMPORT_MODELS
        ${_TR_451_DIR}/common/bbf-vomci-entity.yang
        ${_TR_451_DIR}/common/bbf-omci-message-retransmission.yang
        ${_TR_451_DIR}/common/bbf-network-function-endpoint-filter.yang
        ${_TR_451_DIR}/wt-383-common/bbf-device-types.yang
        ${_TR_451_DIR}/wt-383-common/bbf-network-function-types.yang
        ${_TR_451_DIR}/wt-383-common/bbf-grpc-client.yang
        ${_TR_451_DIR}/wt-383-common/bbf-network-function-server.yang
        ${_TR_451_DIR}/wt-383-common/bbf-network-function-client.yang
        ${_TR_451_DIR}/types/bbf-vomci-types.yang
        ${_TR_451_DIR}/olt/bbf-olt-vomci.yang)
    set(bbf-olt-vomci-features nf-client-supported nf-server-supported)
    set(bbf-network-function-client-features grpc-client-supported)
endif()

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
        set(_FEATURES_OPT_CMD COMMAND ${_SYSREPOTOOL_WRAPPER} ${_SYSREPOCTL} --change ${_IMPORT_NAME_UNVERSIONED} -a ${_FEATURES_OPT})
        set(_FEATURES_OPT_CMD_ECHO COMMAND echo ${_SYSREPOTOOL_WRAPPER} ${_SYSREPOCTL} --change ${_IMPORT_NAME_UNVERSIONED} -a ${_FEATURES_OPT})
    endif()
    add_custom_command(OUTPUT ${_IMPORT_INSTALLED}
        COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND echo ${_SYSREPOTOOL_WRAPPER} ${_SYSREPOCTL} --install ${_IMPORT} -a ${_SEARCH_DIRS}
        COMMAND ${_SYSREPOTOOL_WRAPPER} ${_SYSREPOCTL} --install ${_IMPORT} -a ${_SEARCH_DIRS}
        ${_FEATURES_OPT_CMD_ECHO}
        ${_FEATURES_OPT_CMD}
        COMMAND echo ${_IMPORT} imported to sysrepo
        COMMAND touch ${_IMPORT_INSTALLED}
        DEPENDS sysrepo ${_IMPORT_INSTALLED_PREV}
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
