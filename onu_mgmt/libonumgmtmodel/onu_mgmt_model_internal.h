/*
<:copyright-BRCM:2018-2020:Apache:standard

 Copyright (c) 2018-2020 Broadcom. All Rights Reserved

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

#ifndef ONU_MGMT_MODEL_INTERNAL_H_
#define ONU_MGMT_MODEL_INTERNAL_H_

#include <bcmos_system.h>

/* Internal macro: Check if a given bit is set in a structure presence mask */
#define _BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(_mask, _field_id) \
    ((_mask == 0) || ((_mask & (uint64_t)(1ULL << _field_id))) ? BCMOS_TRUE : BCMOS_FALSE)

/* Internal macro: Set a given bit in a structure presence mask */
#define _BCMONU_MGMT_FIELD_MASK_BIT_SET(_mask, _field_id) \
    do {                                             \
        _mask |= (uint64_t)(1ULL << _field_id);      \
    } while(0)

/* Internal macro: Check if a given bit is set in an array index mask */
/* Note: array indices >63 cannot be covered by the index mask and are assumed to always be set. */
#define _BCMONU_MGMT_ARRAY_MASK_BIT_IS_SET(_mask, _idx) \
    ((_idx > 63) || (_mask == 0) || ((_mask & (1ULL << _idx)) ? BCMOS_TRUE : BCMOS_FALSE))

/* Internal macro: Check if a given bit is set in a group property mask */
#define _BCMONU_MGMT_PROPERTY_MASK_BIT_IS_SET(_mask, _prop_id) \
    ((_mask & (1ULL << (uint64_t)_prop_id)) ? BCMOS_TRUE : BCMOS_FALSE)

#endif
