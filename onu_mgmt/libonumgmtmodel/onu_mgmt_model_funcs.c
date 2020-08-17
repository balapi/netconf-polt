#include <bcmos_system.h>
#include "onu_mgmt_model_internal.h"
#include "onu_mgmt_model_funcs.h"

bcmos_bool bcmonu_mgmt_admin_state_pack(bcmonu_mgmt_admin_state obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_admin_state_unpack(bcmonu_mgmt_admin_state *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_admin_state)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_downstream_mode_values_pack(bcmonu_mgmt_downstream_mode_values obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_downstream_mode_values_unpack(bcmonu_mgmt_downstream_mode_values *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_downstream_mode_values)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_flow_action_type_id_pack(bcmonu_mgmt_flow_action_type_id obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_flow_action_type_id_unpack(bcmonu_mgmt_flow_action_type_id *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_flow_action_type_id)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_flow_dir_id_pack(bcmonu_mgmt_flow_dir_id obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_flow_dir_id_unpack(bcmonu_mgmt_flow_dir_id *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_flow_dir_id)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_flow_type_pack(bcmonu_mgmt_flow_type obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_flow_type_unpack(bcmonu_mgmt_flow_type *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_flow_type)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_igmp_us_action_type_id_pack(bcmonu_mgmt_igmp_us_action_type_id obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_igmp_us_action_type_id_unpack(bcmonu_mgmt_igmp_us_action_type_id *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_igmp_us_action_type_id)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_status_pack(bcmonu_mgmt_status obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u32(buf, (uint32_t)obj);
}

bcmos_bool bcmonu_mgmt_status_unpack(bcmonu_mgmt_status *obj, bcmolt_buf *buf)
{
    uint32_t num_val;
    if (!bcmolt_buf_read_u32(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_status)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_uni_type_pack(bcmonu_mgmt_uni_type obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_uni_type_unpack(bcmonu_mgmt_uni_type *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_uni_type)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_obj_id_pack(bcmonu_mgmt_obj_id obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u16(buf, (uint16_t)obj);
}

bcmos_bool bcmonu_mgmt_obj_id_unpack(bcmonu_mgmt_obj_id *obj, bcmolt_buf *buf)
{
    uint16_t num_val;
    if (!bcmolt_buf_read_u16(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_obj_id)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_api_group_id_pack(bcmonu_mgmt_api_group_id obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u16(buf, (uint16_t)obj);
}

bcmos_bool bcmonu_mgmt_api_group_id_unpack(bcmonu_mgmt_api_group_id *obj, bcmolt_buf *buf)
{
    uint16_t num_val;
    if (!bcmolt_buf_read_u16(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_api_group_id)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_agg_port_list_entry_id_pack(bcmonu_mgmt_agg_port_list_entry_id obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_agg_port_list_entry_id_unpack(bcmonu_mgmt_agg_port_list_entry_id *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_agg_port_list_entry_id)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_flow_action_id_pack(bcmonu_mgmt_flow_action_id obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_flow_action_id_unpack(bcmonu_mgmt_flow_action_id *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_flow_action_id)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_flow_match_id_pack(bcmonu_mgmt_flow_match_id obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_flow_match_id_unpack(bcmonu_mgmt_flow_match_id *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_flow_match_id)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_flow_onu_key_id_pack(bcmonu_mgmt_flow_onu_key_id obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_flow_onu_key_id_unpack(bcmonu_mgmt_flow_onu_key_id *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_flow_onu_key_id)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_igmp_us_action_id_pack(bcmonu_mgmt_igmp_us_action_id obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_igmp_us_action_id_unpack(bcmonu_mgmt_igmp_us_action_id *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_igmp_us_action_id)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_priority_queue_id_pack(bcmonu_mgmt_priority_queue_id obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_priority_queue_id_unpack(bcmonu_mgmt_priority_queue_id *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_priority_queue_id)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_uni_id_pack(bcmonu_mgmt_uni_id obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_uni_id_unpack(bcmonu_mgmt_uni_id *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_uni_id)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_flow_cfg_data_id_pack(bcmonu_mgmt_flow_cfg_data_id obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_flow_cfg_data_id_unpack(bcmonu_mgmt_flow_cfg_data_id *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_flow_cfg_data_id)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_flow_key_id_pack(bcmonu_mgmt_flow_key_id obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_flow_key_id_unpack(bcmonu_mgmt_flow_key_id *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_flow_key_id)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_onu_cfg_data_id_pack(bcmonu_mgmt_onu_cfg_data_id obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_onu_cfg_data_id_unpack(bcmonu_mgmt_onu_cfg_data_id *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_onu_cfg_data_id)num_val;
    return BCMOS_TRUE;
}

bcmos_bool bcmonu_mgmt_onu_key_id_pack(bcmonu_mgmt_onu_key_id obj, bcmolt_buf *buf)
{
    return bcmolt_buf_write_u8(buf, (uint8_t)obj);
}

bcmos_bool bcmonu_mgmt_onu_key_id_unpack(bcmonu_mgmt_onu_key_id *obj, bcmolt_buf *buf)
{
    uint8_t num_val;
    if (!bcmolt_buf_read_u8(buf, &num_val))
    {
        return BCMOS_FALSE;
    }
    *obj = (bcmonu_mgmt_onu_key_id)num_val;
    return BCMOS_TRUE;
}


void bcmonu_mgmt_agg_port_list_entry_set_default(bcmonu_mgmt_agg_port_list_entry *obj)
{
    obj->presence_mask = 0;
    obj->entity_id = 0U;
    obj->agg_port_id = (bcmonu_mgmt_agg_port_id)0U;
}

bcmos_bool bcmonu_mgmt_agg_port_list_entry_validate(const bcmonu_mgmt_agg_port_list_entry *obj, bcmos_errno *err, bcmolt_string *err_details)
{
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_AGG_PORT_LIST_ENTRY_ID_ENTITY_ID))
    {
        /* obj->entity_id can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_AGG_PORT_LIST_ENTRY_ID_AGG_PORT_ID))
    {
        /* obj->agg_port_id can't be invalid. */
    }
    return BCMOS_TRUE;
}

void bcmonu_mgmt_arr_agg_port_list_entry_64_set_default(bcmonu_mgmt_arr_agg_port_list_entry_64 *obj)
{
    obj->arr_index_mask = 0;
    memset(obj->arr, 0, sizeof(obj->arr));
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[0]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[1]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[2]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[3]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[4]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[5]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[6]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[7]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[8]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[9]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[10]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[11]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[12]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[13]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[14]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[15]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[16]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[17]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[18]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[19]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[20]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[21]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[22]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[23]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[24]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[25]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[26]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[27]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[28]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[29]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[30]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[31]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[32]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[33]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[34]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[35]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[36]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[37]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[38]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[39]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[40]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[41]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[42]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[43]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[44]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[45]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[46]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[47]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[48]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[49]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[50]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[51]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[52]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[53]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[54]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[55]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[56]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[57]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[58]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[59]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[60]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[61]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[62]);
    bcmonu_mgmt_agg_port_list_entry_set_default(&obj->arr[63]);
}

bcmos_bool bcmonu_mgmt_arr_agg_port_list_entry_64_validate(const bcmonu_mgmt_arr_agg_port_list_entry_64 *obj, bcmos_errno *err, bcmolt_string *err_details)
{
    for (uint32_t i = 0; i < 64; i++)
    {
        if (_BCMONU_MGMT_ARRAY_MASK_BIT_IS_SET(obj->arr_index_mask, i))
        {
            int prefix_len = bcmolt_string_append(err_details, "arr[%d].", i);
            if (!bcmonu_mgmt_agg_port_list_entry_validate(&obj->arr[i], err, err_details))
            {
                return BCMOS_FALSE;
            }
            bcmolt_string_rewind(err_details, prefix_len);
        }
    }
    return BCMOS_TRUE;
}

void bcmonu_mgmt_priority_queue_set_default(bcmonu_mgmt_priority_queue *obj)
{
    obj->presence_mask = 0;
    obj->entity_id = 0U;
    obj->port = 0U;
}

bcmos_bool bcmonu_mgmt_priority_queue_validate(const bcmonu_mgmt_priority_queue *obj, bcmos_errno *err, bcmolt_string *err_details)
{
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_PRIORITY_QUEUE_ID_ENTITY_ID))
    {
        /* obj->entity_id can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_PRIORITY_QUEUE_ID_PORT))
    {
        /* obj->port can't be invalid. */
    }
    return BCMOS_TRUE;
}

void bcmonu_mgmt_arr_priority_queue_128_set_default(bcmonu_mgmt_arr_priority_queue_128 *obj)
{
    obj->arr_index_mask = 0;
    memset(obj->arr, 0, sizeof(obj->arr));
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[0]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[1]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[2]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[3]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[4]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[5]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[6]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[7]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[8]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[9]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[10]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[11]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[12]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[13]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[14]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[15]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[16]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[17]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[18]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[19]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[20]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[21]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[22]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[23]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[24]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[25]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[26]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[27]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[28]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[29]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[30]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[31]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[32]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[33]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[34]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[35]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[36]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[37]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[38]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[39]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[40]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[41]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[42]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[43]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[44]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[45]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[46]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[47]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[48]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[49]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[50]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[51]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[52]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[53]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[54]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[55]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[56]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[57]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[58]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[59]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[60]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[61]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[62]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[63]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[64]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[65]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[66]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[67]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[68]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[69]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[70]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[71]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[72]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[73]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[74]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[75]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[76]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[77]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[78]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[79]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[80]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[81]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[82]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[83]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[84]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[85]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[86]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[87]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[88]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[89]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[90]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[91]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[92]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[93]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[94]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[95]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[96]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[97]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[98]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[99]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[100]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[101]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[102]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[103]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[104]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[105]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[106]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[107]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[108]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[109]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[110]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[111]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[112]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[113]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[114]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[115]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[116]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[117]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[118]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[119]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[120]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[121]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[122]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[123]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[124]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[125]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[126]);
    bcmonu_mgmt_priority_queue_set_default(&obj->arr[127]);
}

bcmos_bool bcmonu_mgmt_arr_priority_queue_128_validate(const bcmonu_mgmt_arr_priority_queue_128 *obj, bcmos_errno *err, bcmolt_string *err_details)
{
    for (uint32_t i = 0; i < 128; i++)
    {
        if (_BCMONU_MGMT_ARRAY_MASK_BIT_IS_SET(obj->arr_index_mask, i))
        {
            int prefix_len = bcmolt_string_append(err_details, "arr[%d].", i);
            if (!bcmonu_mgmt_priority_queue_validate(&obj->arr[i], err, err_details))
            {
                return BCMOS_FALSE;
            }
            bcmolt_string_rewind(err_details, prefix_len);
        }
    }
    return BCMOS_TRUE;
}

void bcmonu_mgmt_uni_set_default(bcmonu_mgmt_uni *obj)
{
    obj->presence_mask = 0;
    obj->entity_id = 0U;
    obj->type = BCMONU_MGMT_UNI_TYPE_INVALID;
}

bcmos_bool bcmonu_mgmt_uni_validate(const bcmonu_mgmt_uni *obj, bcmos_errno *err, bcmolt_string *err_details)
{
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_UNI_ID_ENTITY_ID))
    {
        /* obj->entity_id can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_UNI_ID_TYPE))
    {
        switch (obj->type)
        {
        case BCMONU_MGMT_UNI_TYPE_INVALID:
        case BCMONU_MGMT_UNI_TYPE_PPTP:
        case BCMONU_MGMT_UNI_TYPE_VEIP:
            break;
        default:
            *err = BCM_ERR_RANGE;
            bcmolt_string_append(err_details, "type: enum value %d is unexpected\n", (int)obj->type);
            return BCMOS_FALSE;
        }
    }
    return BCMOS_TRUE;
}

void bcmonu_mgmt_arr_uni_8_set_default(bcmonu_mgmt_arr_uni_8 *obj)
{
    obj->arr_index_mask = 0;
    memset(obj->arr, 0, sizeof(obj->arr));
    bcmonu_mgmt_uni_set_default(&obj->arr[0]);
    bcmonu_mgmt_uni_set_default(&obj->arr[1]);
    bcmonu_mgmt_uni_set_default(&obj->arr[2]);
    bcmonu_mgmt_uni_set_default(&obj->arr[3]);
    bcmonu_mgmt_uni_set_default(&obj->arr[4]);
    bcmonu_mgmt_uni_set_default(&obj->arr[5]);
    bcmonu_mgmt_uni_set_default(&obj->arr[6]);
    bcmonu_mgmt_uni_set_default(&obj->arr[7]);
}

bcmos_bool bcmonu_mgmt_arr_uni_8_validate(const bcmonu_mgmt_arr_uni_8 *obj, bcmos_errno *err, bcmolt_string *err_details)
{
    for (uint32_t i = 0; i < 8; i++)
    {
        if (_BCMONU_MGMT_ARRAY_MASK_BIT_IS_SET(obj->arr_index_mask, i))
        {
            int prefix_len = bcmolt_string_append(err_details, "arr[%d].", i);
            if (!bcmonu_mgmt_uni_validate(&obj->arr[i], err, err_details))
            {
                return BCMOS_FALSE;
            }
            bcmolt_string_rewind(err_details, prefix_len);
        }
    }
    return BCMOS_TRUE;
}

void bcmonu_mgmt_flow_action_set_default(bcmonu_mgmt_flow_action *obj)
{
    obj->presence_mask = 0;
    obj->type = (bcmonu_mgmt_flow_action_type_id)0;
    obj->o_pcp = 0;
    obj->o_vid = 0U;
    obj->i_pcp = 0;
    obj->i_vid = 0U;
}

bcmos_bool bcmonu_mgmt_flow_action_validate(const bcmonu_mgmt_flow_action *obj, bcmos_errno *err, bcmolt_string *err_details)
{
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_ACTION_ID_TYPE))
    {
        if ((obj->type & ~0xFF) != 0)
        {
            *err = BCM_ERR_RANGE;
            bcmolt_string_append(err_details, "type: 0x%X includes invalid bits\n", obj->type);
            return BCMOS_FALSE;
        }
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_ACTION_ID_O_PCP))
    {
        /* obj->o_pcp can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_ACTION_ID_O_VID))
    {
        /* obj->o_vid can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_ACTION_ID_I_PCP))
    {
        /* obj->i_pcp can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_ACTION_ID_I_VID))
    {
        /* obj->i_vid can't be invalid. */
    }
    return BCMOS_TRUE;
}

void bcmonu_mgmt_flow_match_set_default(bcmonu_mgmt_flow_match *obj)
{
    obj->presence_mask = 0;
    obj->ether_type = 0x0;
    obj->o_pcp = 0;
    obj->o_vid = 0U;
    obj->i_pcp = 0;
    obj->i_vid = 0U;
    obj->o_untagged = BCMOS_FALSE;
    obj->i_untagged = BCMOS_FALSE;
}

bcmos_bool bcmonu_mgmt_flow_match_validate(const bcmonu_mgmt_flow_match *obj, bcmos_errno *err, bcmolt_string *err_details)
{
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_MATCH_ID_ETHER_TYPE))
    {
        /* obj->ether_type can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_MATCH_ID_O_PCP))
    {
        /* obj->o_pcp can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_MATCH_ID_O_VID))
    {
        /* obj->o_vid can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_MATCH_ID_I_PCP))
    {
        /* obj->i_pcp can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_MATCH_ID_I_VID))
    {
        /* obj->i_vid can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_MATCH_ID_O_UNTAGGED))
    {
        /* obj->o_untagged can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_MATCH_ID_I_UNTAGGED))
    {
        /* obj->i_untagged can't be invalid. */
    }
    return BCMOS_TRUE;
}

void bcmonu_mgmt_flow_onu_key_set_default(bcmonu_mgmt_flow_onu_key *obj)
{
    obj->presence_mask = 0;
    obj->pon_ni = 0;
    obj->onu_id = 0U;
}

bcmos_bool bcmonu_mgmt_flow_onu_key_validate(const bcmonu_mgmt_flow_onu_key *obj, bcmos_errno *err, bcmolt_string *err_details)
{
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_ONU_KEY_ID_PON_NI))
    {
        /* obj->pon_ni can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_ONU_KEY_ID_ONU_ID))
    {
        /* obj->onu_id can't be invalid. */
    }
    return BCMOS_TRUE;
}

void bcmonu_mgmt_igmp_us_action_set_default(bcmonu_mgmt_igmp_us_action *obj)
{
    obj->presence_mask = 0;
    obj->type = (bcmonu_mgmt_igmp_us_action_type_id)0;
    obj->pcp = 0;
    obj->vid = 0U;
}

bcmos_bool bcmonu_mgmt_igmp_us_action_validate(const bcmonu_mgmt_igmp_us_action *obj, bcmos_errno *err, bcmolt_string *err_details)
{
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_IGMP_US_ACTION_ID_TYPE))
    {
        if ((obj->type & ~0xD) != 0)
        {
            *err = BCM_ERR_RANGE;
            bcmolt_string_append(err_details, "type: 0x%X includes invalid bits\n", obj->type);
            return BCMOS_FALSE;
        }
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_IGMP_US_ACTION_ID_PCP))
    {
        /* obj->pcp can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_IGMP_US_ACTION_ID_VID))
    {
        /* obj->vid can't be invalid. */
    }
    return BCMOS_TRUE;
}


void bcmonu_mgmt_flow_cfg_data_set_default(bcmonu_mgmt_flow_cfg_data *obj)
{
    obj->presence_mask = 0;
    obj->admin_state = BCMONU_MGMT_ADMIN_STATE_UP;
    obj->oper_status = (bcmonu_mgmt_status)0UL;
    bcmonu_mgmt_flow_onu_key_set_default(&obj->onu_key);
    obj->flow_type = BCMONU_MGMT_FLOW_TYPE_INVALID;
    obj->svc_port_id = (bcmonu_mgmt_svc_port_id)0U;
    obj->agg_port_id = (bcmonu_mgmt_agg_port_id)0U;
    obj->uni_port = (bcmonu_mgmt_uni_port)0U;
    bcmonu_mgmt_flow_match_set_default(&obj->match);
    bcmonu_mgmt_flow_action_set_default(&obj->action);
    bcmonu_mgmt_igmp_us_action_set_default(&obj->igmp_us_action);
}

bcmos_bool bcmonu_mgmt_flow_cfg_data_validate(const bcmonu_mgmt_flow_cfg_data *obj, bcmos_errno *err, bcmolt_string *err_details)
{
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_CFG_DATA_ID_ADMIN_STATE))
    {
        switch (obj->admin_state)
        {
        case BCMONU_MGMT_ADMIN_STATE_DOWN:
        case BCMONU_MGMT_ADMIN_STATE_UP:
            break;
        default:
            *err = BCM_ERR_RANGE;
            bcmolt_string_append(err_details, "admin_state: enum value %d is unexpected\n", (int)obj->admin_state);
            return BCMOS_FALSE;
        }
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_CFG_DATA_ID_OPER_STATUS))
    {
        *err = BCM_ERR_READ_ONLY;
        bcmolt_string_append(err_details, "oper_status: field is read-only and cannot be set\n");
        return BCMOS_FALSE;
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_CFG_DATA_ID_ONU_KEY))
    {
        int prefix_len = bcmolt_string_append(err_details, "onu_key.");
        if (!bcmonu_mgmt_flow_onu_key_validate(&obj->onu_key, err, err_details))
        {
            return BCMOS_FALSE;
        }
        bcmolt_string_rewind(err_details, prefix_len);
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_CFG_DATA_ID_FLOW_TYPE))
    {
        switch (obj->flow_type)
        {
        case BCMONU_MGMT_FLOW_TYPE_INVALID:
        case BCMONU_MGMT_FLOW_TYPE_UNICAST:
        case BCMONU_MGMT_FLOW_TYPE_MULTICAST:
        case BCMONU_MGMT_FLOW_TYPE_BROADCAST:
            break;
        default:
            *err = BCM_ERR_RANGE;
            bcmolt_string_append(err_details, "flow_type: enum value %d is unexpected\n", (int)obj->flow_type);
            return BCMOS_FALSE;
        }
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_CFG_DATA_ID_SVC_PORT_ID))
    {
        /* obj->svc_port_id can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_CFG_DATA_ID_AGG_PORT_ID))
    {
        /* obj->agg_port_id can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_CFG_DATA_ID_UNI_PORT))
    {
        /* obj->uni_port can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_CFG_DATA_ID_MATCH))
    {
        int prefix_len = bcmolt_string_append(err_details, "match.");
        if (!bcmonu_mgmt_flow_match_validate(&obj->match, err, err_details))
        {
            return BCMOS_FALSE;
        }
        bcmolt_string_rewind(err_details, prefix_len);
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_CFG_DATA_ID_ACTION))
    {
        int prefix_len = bcmolt_string_append(err_details, "action.");
        if (!bcmonu_mgmt_flow_action_validate(&obj->action, err, err_details))
        {
            return BCMOS_FALSE;
        }
        bcmolt_string_rewind(err_details, prefix_len);
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_FLOW_CFG_DATA_ID_IGMP_US_ACTION))
    {
        int prefix_len = bcmolt_string_append(err_details, "igmp_us_action.");
        if (!bcmonu_mgmt_igmp_us_action_validate(&obj->igmp_us_action, err, err_details))
        {
            return BCMOS_FALSE;
        }
        bcmolt_string_rewind(err_details, prefix_len);
    }
    return BCMOS_TRUE;
}

void bcmonu_mgmt_flow_key_set_default(bcmonu_mgmt_flow_key *obj)
{
    obj->id = 0UL;
    obj->dir = BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM;
}

bcmos_bool bcmonu_mgmt_flow_key_validate(const bcmonu_mgmt_flow_key *obj, bcmos_errno *err, bcmolt_string *err_details)
{
    /* obj->id can't be invalid. */
    switch (obj->dir)
    {
    case BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM:
    case BCMONU_MGMT_FLOW_DIR_ID_DOWNSTREAM:
        break;
    default:
        *err = BCM_ERR_RANGE;
        bcmolt_string_append(err_details, "dir: enum value %d is unexpected\n", (int)obj->dir);
        return BCMOS_FALSE;
    }
    return BCMOS_TRUE;
}

void bcmonu_mgmt_onu_cfg_data_set_default(bcmonu_mgmt_onu_cfg_data *obj)
{
    obj->presence_mask = 0;
    obj->admin_state = BCMONU_MGMT_ADMIN_STATE_UP;
    obj->oper_status = (bcmonu_mgmt_status)0UL;
    obj->input_tpid = 0x0;
    obj->output_tpid = 0x0;
    bcmonu_mgmt_arr_uni_8_set_default(&obj->unis);
    obj->num_of_unis = 0UL;
    bcmonu_mgmt_arr_agg_port_list_entry_64_set_default(&obj->agg_ports);
    obj->num_of_agg_ports = 0UL;
    bcmonu_mgmt_arr_priority_queue_128_set_default(&obj->us_priority_queues);
    obj->num_of_us_priority_queues = 0UL;
    bcmonu_mgmt_arr_priority_queue_128_set_default(&obj->ds_priority_queues);
    obj->num_of_ds_priority_queues = 0UL;
    obj->downstream_mode = BCMONU_MGMT_DOWNSTREAM_MODE_VALUES_INVERSE;
}

bcmos_bool bcmonu_mgmt_onu_cfg_data_validate(const bcmonu_mgmt_onu_cfg_data *obj, bcmos_errno *err, bcmolt_string *err_details)
{
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_ONU_CFG_DATA_ID_ADMIN_STATE))
    {
        switch (obj->admin_state)
        {
        case BCMONU_MGMT_ADMIN_STATE_DOWN:
        case BCMONU_MGMT_ADMIN_STATE_UP:
            break;
        default:
            *err = BCM_ERR_RANGE;
            bcmolt_string_append(err_details, "admin_state: enum value %d is unexpected\n", (int)obj->admin_state);
            return BCMOS_FALSE;
        }
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_ONU_CFG_DATA_ID_OPER_STATUS))
    {
        *err = BCM_ERR_READ_ONLY;
        bcmolt_string_append(err_details, "oper_status: field is read-only and cannot be set\n");
        return BCMOS_FALSE;
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_ONU_CFG_DATA_ID_INPUT_TPID))
    {
        /* obj->input_tpid can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_ONU_CFG_DATA_ID_OUTPUT_TPID))
    {
        /* obj->output_tpid can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_ONU_CFG_DATA_ID_UNIS))
    {
        int prefix_len = bcmolt_string_append(err_details, "unis.");
        if (!bcmonu_mgmt_arr_uni_8_validate(&obj->unis, err, err_details))
        {
            return BCMOS_FALSE;
        }
        bcmolt_string_rewind(err_details, prefix_len);
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_UNIS))
    {
        /* obj->num_of_unis can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_ONU_CFG_DATA_ID_AGG_PORTS))
    {
        int prefix_len = bcmolt_string_append(err_details, "agg_ports.");
        if (!bcmonu_mgmt_arr_agg_port_list_entry_64_validate(&obj->agg_ports, err, err_details))
        {
            return BCMOS_FALSE;
        }
        bcmolt_string_rewind(err_details, prefix_len);
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_AGG_PORTS))
    {
        /* obj->num_of_agg_ports can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_ONU_CFG_DATA_ID_US_PRIORITY_QUEUES))
    {
        int prefix_len = bcmolt_string_append(err_details, "us_priority_queues.");
        if (!bcmonu_mgmt_arr_priority_queue_128_validate(&obj->us_priority_queues, err, err_details))
        {
            return BCMOS_FALSE;
        }
        bcmolt_string_rewind(err_details, prefix_len);
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_US_PRIORITY_QUEUES))
    {
        /* obj->num_of_us_priority_queues can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_ONU_CFG_DATA_ID_DS_PRIORITY_QUEUES))
    {
        int prefix_len = bcmolt_string_append(err_details, "ds_priority_queues.");
        if (!bcmonu_mgmt_arr_priority_queue_128_validate(&obj->ds_priority_queues, err, err_details))
        {
            return BCMOS_FALSE;
        }
        bcmolt_string_rewind(err_details, prefix_len);
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_DS_PRIORITY_QUEUES))
    {
        /* obj->num_of_ds_priority_queues can't be invalid. */
    }
    if (_BCMONU_MGMT_FIELD_MASK_BIT_IS_SET(obj->presence_mask, BCMONU_MGMT_ONU_CFG_DATA_ID_DOWNSTREAM_MODE))
    {
        switch (obj->downstream_mode)
        {
        case BCMONU_MGMT_DOWNSTREAM_MODE_VALUES_INVERSE:
        case BCMONU_MGMT_DOWNSTREAM_MODE_VALUES_MATCH_VID_INVERSE_VID_FORWARD_NO_MATCH:
        case BCMONU_MGMT_DOWNSTREAM_MODE_VALUES_MATCH_VID_INVERSE_VID_DISCARD_NO_MATCH:
            break;
        default:
            *err = BCM_ERR_RANGE;
            bcmolt_string_append(err_details, "downstream_mode: enum value %d is unexpected\n", (int)obj->downstream_mode);
            return BCMOS_FALSE;
        }
    }
    return BCMOS_TRUE;
}

void bcmonu_mgmt_onu_key_set_default(bcmonu_mgmt_onu_key *obj)
{
    obj->pon_ni = 0;
    obj->onu_id = 0U;
}

bcmos_bool bcmonu_mgmt_onu_key_validate(const bcmonu_mgmt_onu_key *obj, bcmos_errno *err, bcmolt_string *err_details)
{
    /* obj->pon_ni can't be invalid. */
    /* obj->onu_id can't be invalid. */
    return BCMOS_TRUE;
}


