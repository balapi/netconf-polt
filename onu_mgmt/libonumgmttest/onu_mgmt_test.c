/*
 *  <:copyright-BRCM:2016-2020:Apache:standard
 *  
 *   Copyright (c) 2016-2020 Broadcom. All Rights Reserved
 *  
 *   The term “Broadcom” refers to Broadcom Inc. and/or its subsidiaries
 *  
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *  
 *       http://www.apache.org/licenses/LICENSE-2.0
 *  
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  
 *  :>
 *
 *****************************************************************************/

#include "onu_mgmt_test.h"

/** Test utility: 
  debug olt id used to map current olt selection to this debug olt id for any api call to onu mgmt */
bcmolt_oltid bcmonu_mgmt_test_olt_id = BCMONU_MGMT_OLT_INVALID;
bcmolt_oltid bcmonu_mgmt_test_default_olt_id = 0;

bcmos_errno bcmonu_mgmt_test_map_curr_olt_to(bcmolt_oltid olt_id)
{
    bcmonu_mgmt_test_olt_id = olt_id;
    return BCM_ERR_OK;
}

