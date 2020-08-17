#ifndef _ONU_MGMT_MODEL_SUPOORTING_TYPEDEFS_H_
#define _ONU_MGMT_MODEL_SUPPORTING_TYPEDEFS_H_

/** \addtogroup api_data_types
 * @{
 */

#include <bcmos_system.h>

/** bcmonu_mgmt_agg_port_id: Typed alias for a 16-bit unsigned integer. */
typedef uint16_t bcmonu_mgmt_agg_port_id;
#define BCMONU_MGMT_AGG_PORT_ID_UNASSIGNED ((bcmonu_mgmt_agg_port_id)65535U)

/** bcmonu_mgmt_svc_port_id: Typed alias for a 16-bit unsigned integer. */
typedef uint16_t bcmonu_mgmt_svc_port_id;
#define BCMONU_MGMT_SVC_PORT_ID_UNASSIGNED ((bcmonu_mgmt_svc_port_id)65535U)

/** bcmonu_mgmt_uni_port: Typed alias for a 16-bit unsigned integer. */
typedef uint16_t bcmonu_mgmt_uni_port;
#define BCMONU_MGMT_UNI_PORT_UNASSIGNED ((bcmonu_mgmt_uni_port)65535U)



/** @} */

#endif /* _ONU_MGMT_MODEL_SUPPORTING_TYPEDEFS_H_ */
