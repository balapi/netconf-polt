#ifndef _ONU_MGMT_MODEL_TAGS_H_
#define _ONU_MGMT_MODEL_TAGS_H_

#include "onu_mgmt_model_api_structs.h"

/** \addtogroup api_data_types
 * @{
 */

#include <bcmos_system.h>
 
/** All object/field tags included in the API object model. */
typedef enum
{
    BCMONU_MGMT_TAG__NONE = 0,
} bcmonu_mgmt_tag;

/* The following config modes are enabled for this build (based on tags). */

/** Get all tags that are currently active for a given flow based on system state. */
bcmonu_mgmt_tag bcmonu_mgmt_flow_get_active_tags(bcmonu_mgmt_oltid olt, const bcmonu_mgmt_flow_key *key);

/** Get all tags that are currently active for a given onu based on system state. */
bcmonu_mgmt_tag bcmonu_mgmt_onu_get_active_tags(bcmonu_mgmt_oltid olt, const bcmonu_mgmt_onu_key *key);




/** @} */

#endif /* _ONU_MGMT_MODEL_TAGS_H_ */
