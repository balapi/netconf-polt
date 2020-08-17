/*
<:copyright-BRCM:2016-2020:Apache:standard

 Copyright (c) 2016-2020 Broadcom. All Rights Reserved

 The term “Broadcom” refers to Broadcom Inc. and/or its subsidiaries

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

:>
 */

/** TR-451 pOLT vendor service interface
 * This header file declares functions and types provided in the common code that can be used
 * by vendor-specific plugin
 */

#ifndef BCM_TR451_FOR_VENDOR__H
#define BCM_TR451_FOR_VENDOR__H

#ifdef __cplusplus
extern "C"
{
#endif

#include <bcmos_system.h>
#include <bcmcli.h>
#include <bcm_dev_log.h>

#ifdef __cplusplus
}

#include <grpc/grpc.h>
#include <grpcpp/channel.h>

using grpc::Status;
using grpc::StatusCode;
using std::string;

/* Translate Broadcom system error code to grpc::StatusCode */
grpc::Status tr451_bcm_errno_grpc_status(bcmos_errno err, const char *fmt, ...);

#endif

extern dev_log_id bcm_polt_log_id;
/* Log message */
#define BCM_POLT_LOG(level, fmt, ...) BCM_LOG(level, bcm_polt_log_id, fmt, ##__VA_ARGS__)

#endif /* #ifndef BCM_TR451_FOR_VENDOR__H */
