#ifndef _ONU_MGMT_MODEL_TYPES_H_
#define _ONU_MGMT_MODEL_TYPES_H_

#include <bcmos_system.h>
#include <bcmolt_buf.h>
#include <bcmolt_mgt_group.h>
#include <bcmolt_system_types_typedefs.h>
#include "onu_mgmt_model_ids.h"
#include "onu_mgmt_model_supporting_structs.h"
#include "onu_mgmt_model_helpers.h"

#define BCMOLT_MAX_ERR_TEXT_LENGTH      256

typedef void (*bcmonu_mgmt_complete_cb)(void *context, bcmos_errno ret);

typedef struct
{
    bcmonu_mgmt_obj_id obj_type;
    bcmolt_mgt_group group;
    uint16_t subgroup;
    bcmonu_mgmt_msg_type type;
    bcmonu_mgmt_msg_dir dir;
    bcmolt_oltid olt_id;       /**< OLT Id this cfg associates with */
    bcmos_errno err;           /**< Remote error code */
    char err_text[BCMOLT_MAX_ERR_TEXT_LENGTH];
    bcmonu_mgmt_complete_cb complete_cb;
    void *context;
} bcmonu_mgmt_msg;

/* Dummy */
typedef struct
{
    bcmonu_mgmt_msg hdr;
} bcmonu_mgmt_cfg;

/* ONU Mgmt Multi Cfg definitions */
/** Filter flags */
typedef enum
{
    BCMONU_MGMT_FILTER_FLAGS_NONE             = 0,
    BCMONU_MGMT_FILTER_FLAGS_INVERT_SELECTION = 0x00000001,   /** Return objects NOT selected by filter */
    BCMONU_MGMT_FILTER_FLAGS_DISABLE_FILTER   = 0x00000002,   /** Disable the filter entirely */
} bcmonu_mgmt_filter_flags;

/** Common header for multi-object API messages for ONU Mgmt */
typedef struct bcmonu_mgmt_multi_msg
{
    bcmonu_mgmt_msg hdr;                     /**< Common header */
    uint16_t max_responses;             /**< Max number of responses per call - set on creation and doesn't change */
    bcmonu_mgmt_filter_flags filter_flags;   /**< Filter flags */
} bcmonu_mgmt_multi_msg;

/** Multi-object configuration group message header for ONU Mgmt */
typedef struct bcmonu_mgmt_multi_cfg
{
    bcmonu_mgmt_multi_msg hdr;               /** Common header */
} bcmonu_mgmt_multi_cfg;

typedef bcmolt_buf bcmonu_mgmt_buf;

#endif /* _ONU_MGMT_MODEL_TYPES_H_ */
