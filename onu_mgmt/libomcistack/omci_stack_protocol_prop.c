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
/**
 * @file omci_stack_protocol_prop.c
 *
 * @brief This file will be manually written code. This has the properties of ME and Attributes defined as per 
 * OMCI specifications. These properties will be used for validating an ME api call.
 */

#include "omci_stack_protocol_prop.h"
#include "omci_stack_model_types.h"




/**
 * @brief String mapping of Omci msg type (action) to a readable string
 */
char *bcm_omci_msg_type_str[] =
{
    [BCM_OMCI_MSG_TYPE_CREATE]                   "CREATE",
    [BCM_OMCI_MSG_TYPE_DELETE]                   "DELETE",
    [BCM_OMCI_MSG_TYPE_SET]                      "SET",
    [BCM_OMCI_MSG_TYPE_GET]                      "GET",
    [BCM_OMCI_MSG_TYPE_GET_ALL_ALARMS]           "GET ALL ALARMS",
    [BCM_OMCI_MSG_TYPE_GET_ALL_ALARMS_NEXT]      "GET ALL ALARMS NEXT",
    [BCM_OMCI_MSG_TYPE_MIB_UPLOAD]               "MIB_UPLOAD",
    [BCM_OMCI_MSG_TYPE_MIB_UPLOAD_NEXT]          "MIB UPLOAD NEXT",
    [BCM_OMCI_MSG_TYPE_MIB_RESET]                "MIB RESET",
    [BCM_OMCI_MSG_TYPE_ALARM]                    "ALARM",
    [BCM_OMCI_MSG_TYPE_AVC]                      "AVC",
    [BCM_OMCI_MSG_TYPE_TEST]                     "TEST",
    [BCM_OMCI_MSG_TYPE_START_SW_DOWNLOAD]        "START SW DOWNLOAD",
    [BCM_OMCI_MSG_TYPE_DOWNLOAD_SECTION]         "DOWNLOAD SECTION",
    [BCM_OMCI_MSG_TYPE_END_SW_DOWNLOAD]          "END SW DOWNLOAD",
    [BCM_OMCI_MSG_TYPE_ACTIVATE_SW]              "ACTIVATE SW",
    [BCM_OMCI_MSG_TYPE_COMMIT_SW]                "COMMIT SW",
    [BCM_OMCI_MSG_TYPE_SYNC_TIME]                "SYNC TIME",
    [BCM_OMCI_MSG_TYPE_REBOOT]                   "REBOOT",
    [BCM_OMCI_MSG_TYPE_GET_NEXT]                 "GET NEXT",
    [BCM_OMCI_MSG_TYPE_TEST_RESULT]              "TEST RESULT",
    [BCM_OMCI_MSG_TYPE_GET_CURRENT_DATA]         "GET CURRENT DATA",
    [BCM_OMCI_MSG_TYPE_SET_TABLE]                "SET TABLE",
    [BCM_OMCI_MSG_TYPE__END]                     "INVALID"
};

/**
 * @brief Table to define associated properties i.e. AK & Increment Sync Counter,
 * for each OMCI Msg Type. This is also taken from Table 11.2.2-1 in G.988 and is 
 * an extension of the above enum.
 *
 * @details this table defines AK (acknowledge) & Increment MIB sync counter flags
 * for each  OMCI Message Type.
 *
 * @note This may be used by stack to wait/check for Ack from ONU , and also
 * to increment MIB sync counter.
 *
 * @note Some of these messages will be sent only from the ONU side e.g. ALARM, AVC etc. OMCI
 *       stack can use this table to validate if a message type is fine to be sent or received along
 *       with the constituent fields, and also take resultant action about send or not send ack , 
 *       wait or not wait for ack etc. 
 */
bcm_omci_msg_type_flags bcm_omci_msg_type_flags_arr[] =
{
    [BCM_OMCI_MSG_TYPE_CREATE]               {YES,  NO,     YES,    NO, NO},
    [BCM_OMCI_MSG_TYPE_DELETE]               {YES,  NO,     NO,     NO, NO},
    [BCM_OMCI_MSG_TYPE_SET]                  {YES,  YES,    YES,    NO, NO},  
            /* NOTE 1 MIB sync is incremented if a set action successfully updates 
               any of the attributes specified, even if some other attributes of the 
               same set action were to fail */
    [BCM_OMCI_MSG_TYPE_GET]                  {YES,  YES,    NO,     YES,YES},
    [BCM_OMCI_MSG_TYPE_GET_ALL_ALARMS]       {YES,  NO,     NO,     NO, NO},
    [BCM_OMCI_MSG_TYPE_GET_ALL_ALARMS_NEXT] ={YES,  NO,     NO,     NO, NO},
    [BCM_OMCI_MSG_TYPE_MIB_UPLOAD] =         {YES,  NO,     NO,     NO,NO},
    [BCM_OMCI_MSG_TYPE_MIB_UPLOAD_NEXT] =    {YES,  NO,     NO,     YES,YES},
    [BCM_OMCI_MSG_TYPE_MIB_RESET] =          {YES,  NO,     NO,     NO, NO},
    [BCM_OMCI_MSG_TYPE_ALARM] =              {NO,   NO,     NO,     NO, NO},
    [BCM_OMCI_MSG_TYPE_AVC] =                {NO,   NO,     NO,     YES,YES},
    [BCM_OMCI_MSG_TYPE_TEST] =               {YES,  NO,     NO,     NO, NO},
    [BCM_OMCI_MSG_TYPE_START_SW_DOWNLOAD] =  {YES,  NO,     NO,     NO, NO},
    [BCM_OMCI_MSG_TYPE_DOWNLOAD_SECTION] =   {YES,  NO,     NO,     NO, NO},   
    /* NOTE 2 The download section action is acknowledged only for the last section 
       within a window. See clause I.3 */
    [BCM_OMCI_MSG_TYPE_END_SW_DOWNLOAD] =    {YES,  NO,     NO,     NO, NO},
    [BCM_OMCI_MSG_TYPE_ACTIVATE_SW] =        {YES,  NO,     NO,     NO, NO},
    [BCM_OMCI_MSG_TYPE_COMMIT_SW] =          {YES,  NO,     NO,     NO, NO},
    [BCM_OMCI_MSG_TYPE_SYNC_TIME] =          {YES,  NO,     NO,     NO, NO},
    [BCM_OMCI_MSG_TYPE_REBOOT] =             {YES,  NO,     NO,     NO, NO},
    [BCM_OMCI_MSG_TYPE_GET_NEXT] =           {YES,  YES,    NO,     YES, YES},
    [BCM_OMCI_MSG_TYPE_TEST_RESULT] =        {NO,   NO,     NO,     NO, NO},
    [BCM_OMCI_MSG_TYPE_GET_CURRENT_DATA] =   {YES,  YES,    NO,     YES,YES},
    [BCM_OMCI_MSG_TYPE_SET_TABLE] =          {YES,  NO,     YES,    NO, NO},
    /* NOTE 3 Set table is defined only in the extended message set. */
    [BCM_OMCI_MSG_TYPE__END] =               {NO,   NO,     NO,     NO, NO}
};


/** @brief maps omci msg result field -> str */
bcm_omci_result2str_t bcm_omci_result2str[] =
{
    {BCM_OMCI_RESULT_CMD_PROC_SUCCESS,      "OMCI_RESULT_CMD_PROC_SUCCESS"},
    {BCM_OMCI_RESULT_CMD_PROC_ERROR,        "OMCI_RESULT_CMD_PROC_ERROR"},
    {BCM_OMCI_RESULT_CMD_NOT_SUPPORTED,     "OMCI_RESULT_CMD_NOT_SUPPORTED"},
    {BCM_OMCI_RESULT_PARAM_ERROR,           "OMCI_RESULT_PARAM_ERROR"},
    {BCM_OMCI_RESULT_UNKNOWN_ME,            "OMCI_RESULT_UNKNOWN_ME"},
    {BCM_OMCI_RESULT_UNKNOWN_INSTANCE,      "OMCI_RESULT_UNKNOWN_INSTANCE"},
    {BCM_OMCI_RESULT_DEVICE_BUSY,           "OMCI_RESULT_DEVICE_BUSY"},
    {BCM_OMCI_RESULT_INSTANCE_EXISTS,       "OMCI_RESULT_INSTANCE_EXISTS"},
    {BCM_OMCI_RESULT_RESERVED,              "OMCI_RESULT_RESERVED"},      /* not defined */
    {BCM_OMCI_RESULT_ATTR_FAILED_OR_UNKNOWN, "OMCI_RESULT_ATTR_FAILED_OR_UNKNOWN"},

    /* Internal result values reported by Transport layer */
    {BCM_OMCI_RESULT_IND_MORE,              "OMCI_RESULT_IND_MORE"},
    {BCM_OMCI_RESULT_IND_LAST,              "OMCI_RESULT_IND_LAST"},
    {BCM_OMCI_RESULT_TL_LINK_ERROR,         "OMCI_RESULT_TL_LINK_ERROR"},
    {BCM_OMCI_RESULT_TL_ERROR,              "OMCI_RESULT_TL_ERROR"},
    {-1}
};

