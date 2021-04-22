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

#include <bcm_tr451_polt_internal.h>
#include <fstream>

extern "C"
{
#include <bcmos_hash_table.h>
}

dev_log_id bcm_polt_log_id;

static bool subsystem_enabled[2];

//
// bcmos_errno to Status translation
//
grpc::Status tr451_bcm_errno_grpc_status(bcmos_errno err, const char *fmt, ...)
{
    const char *err_text;
    if (err == BCM_ERR_OK)
        return Status::OK;

    StatusCode code;
    switch(err)
    {
        case BCM_ERR_ALREADY:
            code = StatusCode::ALREADY_EXISTS;
            break;
        case BCM_ERR_NOENT:
            code = StatusCode::NOT_FOUND;
            break;
        case BCM_ERR_PARM:
            code = StatusCode::INVALID_ARGUMENT;
            break;
        case BCM_ERR_NORES:
            code = StatusCode::UNAVAILABLE;
            break;
        case BCM_ERR_IN_PROGRESS:
            code = StatusCode::ABORTED;
            break;
        case BCM_ERR_NOT_SUPPORTED:
            code = StatusCode::UNIMPLEMENTED;
            break;
        case BCM_ERR_RANGE:
            code = StatusCode::OUT_OF_RANGE;
            break;
        case BCM_ERR_INTERNAL:
            code = StatusCode::INTERNAL;
            break;
        case BCM_ERR_NOT_CONNECTED:
            code = StatusCode::FAILED_PRECONDITION;
            break;
        default:
            code = StatusCode::UNKNOWN;
            break;
    }
    char err_buff[256];
    if (fmt == nullptr || !strlen(fmt))
    {
        err_text = bcmos_strerror(err);
    }
    else
    {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err_buff, sizeof(err_buff)-1, fmt, ap);
        va_end(ap);
        err_buff[sizeof(err_buff)-1] = 0;
        err_text = err_buff;
    }
    return grpc::Status(code, string(err_text));
}

//
// Filter service declaration
//
class OnuFilterSet
{

public:
    class FilterEntry
    {
    public:
        FilterEntry(const tr451_polt_filter *flt, const char *endpoint_name) :
            name_(flt->name), endpoint_name_(endpoint_name)
        {
            filter = *flt;
        }

        bool isMatch(const tr451_polt_onu_serial_number *serial_number)
        {
            if (filter.type == TR451_FILTER_TYPE_ANY)
            {
                BCM_POLT_LOG(DEBUG, "isMatch ANY : %c%c%c%c%02X%02X%02X%02X\n",
                    serial_number->data[0], serial_number->data[1], serial_number->data[2], serial_number->data[3],
                    serial_number->data[4], serial_number->data[5], serial_number->data[6], serial_number->data[7]);
                return true;
            }
            if (filter.type == TR451_FILTER_TYPE_VENDOR_ID)
            {
                BCM_POLT_LOG(DEBUG, "isMatch VENDOR %c%c%c%c : %c%c%c%c%02X%02X%02X%02X\n",
                    filter.serial_number[0], filter.serial_number[1], filter.serial_number[2], filter.serial_number[3],
                    serial_number->data[0], serial_number->data[1], serial_number->data[2], serial_number->data[3],
                    serial_number->data[4], serial_number->data[5], serial_number->data[6], serial_number->data[7]);
                return (memcmp(&serial_number->data[0], &filter.serial_number[0], 4) == 0);
            }
            if (filter.type == TR451_FILTER_TYPE_SERIAL_NUMBER)
            {
                BCM_POLT_LOG(DEBUG, "isMatch SERIAL %c%c%c%c%02X%02X%02X%02X : %c%c%c%c%02X%02X%02X%02X\n",
                    filter.serial_number[0], filter.serial_number[1], filter.serial_number[2], filter.serial_number[3],
                    filter.serial_number[4], filter.serial_number[5], filter.serial_number[6], filter.serial_number[7],
                    serial_number->data[0], serial_number->data[1], serial_number->data[2], serial_number->data[3],
                    serial_number->data[4], serial_number->data[5], serial_number->data[6], serial_number->data[7]);
                return (memcmp(&serial_number->data[0], &filter.serial_number[0], sizeof(serial_number->data)) == 0);
            }
            return false;
        }
        const char *name() { return name_.c_str(); }
        const char *endpoint_name() { return endpoint_name_.length() ? endpoint_name_.c_str() : nullptr; }

        tr451_polt_filter filter;
        STAILQ_ENTRY(FilterEntry) next;
    private:
        string name_;
        string endpoint_name_;
    };

private:
    void FilterInsert_(FilterEntry *entry)
    {
        FilterEntry *prev = NULL;
        FilterEntry *tmp;
        tmp = STAILQ_FIRST(&filter_list_);
        while (tmp && tmp->filter.priority <= entry->filter.priority)
        {
            prev = tmp;
            tmp = STAILQ_NEXT(tmp, next);
        }
        if (prev != nullptr)
            STAILQ_INSERT_AFTER(&filter_list_, prev, entry, next);
        else
            STAILQ_INSERT_HEAD(&filter_list_, entry, next);
    }

    STAILQ_HEAD(, FilterEntry) filter_list_;

public:
    OnuFilterSet()
    {
        STAILQ_INIT(&filter_list_);
    }

    // Add filter entry
    void FilterSet(const tr451_polt_filter *filter, const char *endpoint_name);

    FilterEntry *FilterGet(const char *name)
    {
        FilterEntry *entry, *tmp;
        STAILQ_FOREACH_SAFE(entry, &filter_list_, next, tmp)
        {
            if (!strcmp(entry->name(), name))
                break;
        }
        return entry;
    }

    void FilterDelete(FilterEntry *entry);

    // Find vOMCI client/server by ONU serial number
    bool FindConnectedFilter(const tr451_polt_onu_serial_number *serial_number,
        FilterEntry **p_filter, VomciConnection **p_conn);

    bool UpdateOnuAssignmentsFilterAdded(FilterEntry *entry);

    bool UpdateOnuAssignmentsFilterRemoved(FilterEntry *entry);

    FilterEntry *GetNextByEndpoint(FilterEntry *entry, const char *endpoint)
    {
        entry = (entry != nullptr) ? STAILQ_NEXT(entry, next) : STAILQ_FIRST(&filter_list_);
        while (entry != nullptr && entry->endpoint_name() != nullptr && strcmp(endpoint, entry->endpoint_name()))
            entry = STAILQ_NEXT(entry, next);
        return entry;
    }
};

// Endpoint filters set
static OnuFilterSet filter_set;

// Add server filter
bcmos_errno bcm_tr451_polt_filter_set(const tr451_polt_filter *filter, const char *endpoint_name)
{
    // Look up filter. Update if exists, add if doesn't
    filter_set.FilterSet(filter, endpoint_name);
    return BCM_ERR_OK;
}

// Get filter
bcmos_errno bcm_tr451_polt_filter_get(const char *filter_name, tr451_polt_filter *filter)
{
    if (filter_name == nullptr)
        return BCM_ERR_PARM;
    OnuFilterSet::FilterEntry *entry = filter_set.FilterGet(filter_name);
    if (entry == nullptr)
        return BCM_ERR_NOENT;
    if (filter != nullptr)
        *filter = entry->filter;
    return BCM_ERR_OK;
}

// Delete filter
bcmos_errno bcm_tr451_polt_filter_delete(const char *filter_name)
{
    if (filter_name == nullptr)
        return BCM_ERR_PARM;
    OnuFilterSet::FilterEntry *entry = filter_set.FilterGet(filter_name);
    if (entry == nullptr)
        return BCM_ERR_NOENT;
    filter_set.FilterDelete(entry);
    return BCM_ERR_OK;
}

//
// Active ONU data base
//

static hash_table *onu_info_table;
typedef struct
{
#define TR451_POLT_MAX_CTERM_NAME_LENGTH    30
    char cterm_name[TR451_POLT_MAX_CTERM_NAME_LENGTH];
    uint16_t onu_id;
} onu_info_key;

static void onu_info_make_key(const char *cterm_name, uint16_t onu_id, onu_info_key *key)
{
    memset(&key->cterm_name[0], 0, sizeof(key->cterm_name));
    strncpy(&key->cterm_name[0], cterm_name, sizeof(key->cterm_name));
    key->onu_id = onu_id;
}

class OnuInfo
{
public:

    OnuInfo(const char *cterm_name,
        uint16_t onu_id,
        const tr451_polt_onu_serial_number *serial_number) :
            vomci(nullptr), filter(nullptr),
            cterm_name_(cterm_name), onu_id_(onu_id), _endpoint_name()
    {
        onu_info_key key;
        onu_info_make_key(cterm_name, onu_id, &key);
        OnuInfo *obj = this;
        hash_table_put(onu_info_table, (uint8_t *)&key, &obj);
        if (serial_number != nullptr)
            serial_number_ = *serial_number;
        else
            memset(&serial_number_, 0, sizeof(serial_number_));
        reset_counters();
        BCM_POLT_LOG(DEBUG, "Added onu %s.%u\n", cterm_name, onu_id);
    }

    ~OnuInfo()
    {
        onu_info_key key;
        onu_info_make_key(cterm_name_.c_str(), onu_id_, &key);
        hash_table_remove(onu_info_table, (uint8_t *)&key);
        BCM_POLT_LOG(DEBUG, "Deleted onu %s.%u\n", cterm_name_.c_str(), onu_id_);
    }

    void AssignEndpoint(VomciConnection *conn, OnuFilterSet::FilterEntry *filt)
    {
        filter = filt;
        if (conn != vomci)
        {
            BCM_POLT_LOG(INFO, "ONU %s:%u is assigned to remote endpoint %s using filter '%s'\n",
                cterm_name(), onu_id(), (conn != nullptr) ? conn->name() : "<none>",
                (filt != nullptr) ? filt->name() : "<none>");
        }
        vomci = conn;
    }

    const tr451_polt_onu_serial_number *serial_number() const { return &serial_number_; }
    const char *cterm_name() const { return cterm_name_.c_str(); }
    uint16_t onu_id() const { return onu_id_; }
    void endpoint_name_set(const char *endpoint_name) { _endpoint_name = endpoint_name; }
    const char *endpoint_name() { return (_endpoint_name.length() > 0) ? _endpoint_name.c_str() : nullptr; }
    void reset_counters() {
        in_messages = out_messages = message_errors = 0;
    }
    bool isConnected() {
        return vomci != nullptr && vomci->isConnected();
    }

    VomciConnection *vomci;
    OnuFilterSet::FilterEntry *filter;
    uint64_t in_messages;
    uint64_t out_messages;
    uint64_t message_errors;

private:
    string cterm_name_;
    uint16_t onu_id_;
    tr451_polt_onu_serial_number serial_number_;
    string _endpoint_name;
};

static OnuInfo *onu_info_get(const char *cterm_name, uint16_t onu_id)
{
    onu_info_key key;
    OnuInfo **pp_onu_info;

    if (cterm_name == nullptr || onu_id >= TR451_POLT_MAX_ONUS_PER_PON)
        return NULL;
    onu_info_make_key(cterm_name, onu_id, &key);
    pp_onu_info = (OnuInfo **)hash_table_get(onu_info_table, (uint8_t *)&key);
    if (pp_onu_info == nullptr)
        return nullptr;
    return *pp_onu_info;
}

static void onu_info_set(const char *cterm_name,
    uint16_t onu_id,
    const tr451_polt_onu_serial_number *serial_number,
    OnuFilterSet::FilterEntry *filter,
    VomciConnection *vomci)
{
    BUG_ON(cterm_name == nullptr || onu_id >= TR451_POLT_MAX_ONUS_PER_PON);
    OnuInfo *onu_info = onu_info_get(cterm_name, onu_id);
    if (onu_info == nullptr)
    {
        onu_info = new OnuInfo(cterm_name, onu_id, serial_number);
    }
    onu_info->AssignEndpoint(vomci, filter);
}

static OnuInfo *onu_info_get_next(ht_iterator *iter)
{
    if (!ht_iterator_next(iter))
        return nullptr;

    uint8_t *key;
    OnuInfo **pp_info;
    ht_iterator_deref(iter, &key, (void **)&pp_info);
    return (pp_info != nullptr) ? *pp_info : nullptr;
}

// Create an explicit association between v-ani and vomci-endpoint */
bcmos_errno xpon_v_ani_vomci_endpoint_set(const char *cterm_name, uint16_t onu_id, const char *endpoint_name)
{
    BUG_ON(cterm_name == nullptr || onu_id >= TR451_POLT_MAX_ONUS_PER_PON);
    OnuInfo *onu_info = onu_info_get(cterm_name, onu_id);
    if (onu_info == nullptr)
    {
        onu_info = new OnuInfo(cterm_name, onu_id, nullptr);
    }
    onu_info->endpoint_name_set(endpoint_name);
    return BCM_ERR_OK;
}

// Clear an explicit association between v-ani and vomci-endpoint */
bcmos_errno xpon_v_ani_vomci_endpoint_clear(const char *cterm_name, uint16_t onu_id)
{
    return xpon_v_ani_vomci_endpoint_set(cterm_name, onu_id, nullptr);
}

//
// Filter Service implementation
//

// Find channel assignment
static bool find_channel_assignment(const tr451_polt_onu_serial_number *serial_number,
    OnuFilterSet::FilterEntry **p_filter, VomciConnection **p_vomci)
{
    *p_filter = nullptr;
    *p_vomci = nullptr;
    bool assigned =  filter_set.FindConnectedFilter(serial_number, p_filter, p_vomci);
    return assigned;
}

void OnuFilterSet::FilterSet(const tr451_polt_filter *filter, const char *endpoint_name)
{
    FilterEntry *entry = FilterGet(filter->name);
    if (entry != nullptr)
    {
        FilterDelete(entry);
    }

    entry = new FilterEntry(filter, endpoint_name);
    FilterInsert_(entry);
    BCM_POLT_LOG(DEBUG, "Added filter %s --> %s\n", entry->name(), endpoint_name);
    // Update ONU assignments
    if (entry->endpoint_name() != nullptr)
        UpdateOnuAssignmentsFilterAdded(entry);
}

void OnuFilterSet::FilterDelete(FilterEntry *entry)
{
    BCM_POLT_LOG(DEBUG, "Deleted filter %s\n", entry->name());
    STAILQ_REMOVE_SAFE(&filter_list_, entry, FilterEntry, next);
    UpdateOnuAssignmentsFilterRemoved(entry);
    delete entry;
}

// Find vOMCI client/server by ONU serial number
bool OnuFilterSet::FindConnectedFilter(const tr451_polt_onu_serial_number *serial_number,
    FilterEntry **p_filter, VomciConnection **p_conn)
{
    FilterEntry *entry, *tmp;
    VomciConnection *conn = nullptr;

    STAILQ_FOREACH_SAFE(entry, &filter_list_, next, tmp)
    {
        BCM_POLT_LOG(DEBUG, "Checking filter %s: %s\n",
            entry->name(), entry->isMatch(serial_number) ? "match" : "mismatch");
        if (!entry->isMatch(serial_number))
            continue;
        conn = vomci_connection_get_by_name(entry->endpoint_name());
        if (conn != nullptr && conn->isConnected())
            break;
        conn = nullptr;
    }
    *p_conn = conn;
    *p_filter = entry;
    return (conn != nullptr);
}

bool OnuFilterSet::UpdateOnuAssignmentsFilterAdded(FilterEntry *entry)
{
    bool updated = false;
    if (entry->endpoint_name() == nullptr)
        return false;
    VomciConnection *conn = vomci_connection_get_by_name(entry->endpoint_name());
    if (conn == nullptr || !conn->isConnected())
        return false;

    // Added active filter. Update matching ONUs
    ht_iterator iter = ht_iterator_get(onu_info_table);
    OnuInfo *info = onu_info_get_next(&iter);
    while (info != nullptr)
    {
        // Skip ONUs for which endpoint name is set explictly in v-ani
        if (info->endpoint_name() != nullptr)
        {
            info = onu_info_get_next(&iter);
            continue;
        }

        if (entry->isMatch(info->serial_number()) &&
            (info->filter == nullptr || entry->filter.priority < info->filter->filter.priority))
        {
            info->AssignEndpoint(conn, entry);
            updated = true;
        }
        info = onu_info_get_next(&iter);
    }

    return updated;
}

bool OnuFilterSet::UpdateOnuAssignmentsFilterRemoved(FilterEntry *entry)
{
    bool updated = false;
    // Removed filter. Update matching ONUs
    ht_iterator iter = ht_iterator_get(onu_info_table);
    OnuInfo *info = onu_info_get_next(&iter);
    while (info != nullptr)
    {
        // Skip ONUs for which endpoint name is set explictly in v-ani
        if (info->endpoint_name() != nullptr)
        {
            info = onu_info_get_next(&iter);
            continue;
        }

        const VomciConnection *old_conn = info->vomci;
        if (info->filter == entry)
        {
            updated |= find_channel_assignment(info->serial_number(), &info->filter, &info->vomci);
        }
        if (old_conn != info->vomci)
        {
            info->AssignEndpoint(info->vomci, info->filter);
        }
        info = onu_info_get_next(&iter);
    }
    return updated;
}

//
// common Client/Server handling
//
static STAILQ_HEAD(, VomciConnection) connection_list;
static STAILQ_HEAD(, GrpcProcessor) client_server_list;

/* Find connection by name, whereas name is
   - endpoint name for client connection
   - remote endpoint name for server connection
*/
VomciConnection *vomci_connection_get_by_name(const char *name, const GrpcProcessor *owner)
{
    VomciConnection *conn, *tmp;

    BCM_POLT_LOG(DEBUG, "Looking for connection with remote-endpoint name '%s'. Owner: '%s'\n",
        name, owner ? owner->name() : "<null>");

    STAILQ_FOREACH_SAFE(conn, &connection_list, next, tmp)
    {
        const char *remote_endpoint_name = conn->remote_endpoint_name();
        BCM_POLT_LOG(DEBUG, "..checking connection '%s': remote-endpoint='%s' parent='%s'\n",
            conn->name(), remote_endpoint_name, conn->parent()->name());
        if ((owner == nullptr || conn->parent() == owner) && !strcmp(name, remote_endpoint_name))
            break;
    }
    BCM_POLT_LOG(DEBUG, "Found connection '%s'. Connected=%d\n",
        conn ? conn->name() : "<null>", conn ? conn->isConnected() : false);
    return conn;
}

VomciConnection *vomci_connection_get_by_peer(const char *peer, const GrpcProcessor *owner)
{
    VomciConnection *conn, *tmp;
    STAILQ_FOREACH_SAFE(conn, &connection_list, next, tmp)
    {
        if ((owner == nullptr || conn->parent() == owner) && !strcmp(peer, conn->peer()))
            break;
    }
    return conn;
}

VomciConnection *vomci_connection_get_next(VomciConnection *prev, const GrpcProcessor *owner)
{
    VomciConnection *conn = (prev != nullptr) ? STAILQ_NEXT(prev, next) : STAILQ_FIRST(&connection_list);
    while (conn != nullptr && (owner != nullptr && conn->parent() != owner))
        conn = STAILQ_NEXT(conn, next);
    return conn;
}


static int grpc_processor_task_handler(long data)
{
    GrpcProcessor *client_server = (GrpcProcessor *)data;

    BCM_POLT_LOG(INFO, "pOLT %s %s started\n",
        client_server->type_name(), client_server->name());

    // Start client/server. Never returns until the client/server is terminated
    client_server->Start();

    return 0;
}

GrpcProcessor *bcm_grpc_processor_get_by_name(const char *name, GrpcProcessor::processor_type type)
{
    GrpcProcessor *entry, *tmp;

    STAILQ_FOREACH_SAFE(entry, &client_server_list, next, tmp)
    {
        if (!strcmp(name, entry->name()) && entry->type() == type)
            break;
    }

    return entry;
}

static bcm_tr451_polt_grpc_server_connect_disconnect_cb vomci_server_conn_discon_cb;
static void *vomci_server_conn_discon_cb_data;

static bcm_tr451_polt_grpc_client_connect_disconnect_cb vomci_client_conn_discon_cb;
static void *vomci_client_conn_discon_cb_data;

bcmos_errno bcm_tr451_polt_grpc_server_connect_disconnect_cb_register(
   bcm_tr451_polt_grpc_server_connect_disconnect_cb cb, void *data)
{
    vomci_server_conn_discon_cb = cb;
    vomci_server_conn_discon_cb_data = data;
    return BCM_ERR_OK;
}

bcmos_errno bcm_tr451_polt_grpc_client_connect_disconnect_cb_register(
   bcm_tr451_polt_grpc_client_connect_disconnect_cb cb, void *data)
{
    vomci_client_conn_discon_cb = cb;
    vomci_client_conn_discon_cb_data = data;
    return BCM_ERR_OK;
}

void vomci_notify_connect_disconnect(VomciConnection *conn, bool is_connected)
{
    // Notify only for server endpoints
    if (conn->parent()->type() == GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_SERVER &&
        vomci_server_conn_discon_cb != nullptr)
    {
        vomci_server_conn_discon_cb(vomci_server_conn_discon_cb_data,
            conn->parent()->name(), conn->name(), is_connected);
    }
    if (conn->parent()->type() == GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_CLIENT &&
        vomci_client_conn_discon_cb != nullptr)
    {
        vomci_client_conn_discon_cb(vomci_client_conn_discon_cb_data,
            conn->parent()->name(), conn->endpoint(), is_connected);
    }
}


static OnuInfo *vomci_get_by_omci_packet(const OmciPacket &grpc_omci_packet)
{
    uint16_t onu_id;

    onu_id = (uint16_t)grpc_omci_packet.header().onu_id();
    if (onu_id >= TR451_POLT_MAX_ONUS_PER_PON)
    {
        BCM_POLT_LOG(ERROR, "onu_id %u is insane\n", onu_id);
        return nullptr;
    }

    // Identify OnuInfo record
    return onu_info_get(grpc_omci_packet.header().chnl_term_name().c_str(), onu_id);
}


/*
 * GrpcProcessor class - the base class of both BcmPoltServer and BcmPoltClient
 */

GrpcProcessor::GrpcProcessor(processor_type type, const char *ep_name) :
    type_(type), endpoint_name_(ep_name), started_(false)
{
    STAILQ_INSERT_TAIL(&client_server_list, this, next);
    stopping = false;
}

// Create client/server task and start client/server
bcmos_errno GrpcProcessor::CreateTaskAndStart()
{
    bcmos_task_parm tp = {};
    bcmos_errno err;

    stopping = false;
    // Create task that will handle this endpoint
    tp.name = "polt_client_server";
    tp.priority = TASK_PRIORITY_VOMCI_DOLT_CLIENT;
    tp.handler = grpc_processor_task_handler;
    tp.data = (long)this;
    err = bcmos_task_create(&this->task_, &tp);
    if (err != BCM_ERR_OK)
    {
        return err;
    }
    started_ = true;
    return BCM_ERR_OK;
}

void GrpcProcessor::Stop()
{
    if (!started_)
        return;
    bcmos_task_destroy(&this->task_);
    started_ = false;
}

GrpcProcessor::~GrpcProcessor()
{
    Stop();
    STAILQ_REMOVE_SAFE(&client_server_list, this, GrpcProcessor, next);
}


Status GrpcProcessor::OmciTxToOnu(const OmciPacket &grpc_omci_packet, const char *peer)
{
    bcmos_errno err;

    OnuInfo *onu = vomci_get_by_omci_packet(grpc_omci_packet);
    VomciConnection *conn = (onu != nullptr) ? onu->vomci : nullptr;
    if (conn==nullptr)
    {
        grpc::Status status = tr451_bcm_errno_grpc_status(BCM_ERR_NOENT,
            "%s: Can't send OMCI message to vOMCI. No connection. ONU %s:%u\n",
            name(), grpc_omci_packet.header().chnl_term_name().c_str(), grpc_omci_packet.header().onu_id());
        BCM_POLT_LOG(ERROR, "%s:\n", status.error_message().c_str());
        return status;
    }

    ++conn->stats.packets_vomci_to_onu_recv;
    ++onu->in_messages;
    err = tr451_vendor_omci_send_to_onu(grpc_omci_packet);
    if (err != BCM_ERR_OK)
    {
        grpc::Status status = tr451_bcm_errno_grpc_status(err,
            "Failed to send OMCI message to ONU %s:%u. Error '%s'",
            grpc_omci_packet.header().chnl_term_name().c_str(), grpc_omci_packet.header().onu_id(),
            bcmos_strerror(err));
        ++conn->stats.packets_vomci_to_onu_disc;
        ++onu->message_errors;
        BCM_POLT_LOG(ERROR, "%s:\n", status.error_message().c_str());
        return status;
    }
    BCM_POLT_LOG(DEBUG, "Sent OMCI message to ONU %s:%u. %lu bytes\n",
        grpc_omci_packet.header().chnl_term_name().c_str(), grpc_omci_packet.header().onu_id(),
        grpc_omci_packet.payload().length());

    ++conn->stats.packets_vomci_to_onu_sent;

    return Status::OK;
}

//
// VomciConnection
//
VomciConnection::VomciConnection(GrpcProcessor *parent,
            const string &endpoint,
            const string &local_name,
            const string &vomci_name,
            const string &vomci_address) :
    parent_(parent) , name_(vomci_name), peer_(vomci_address),
    endpoint_(endpoint), local_name_(local_name), connected_(false)
{
    memset(&stats, 0, sizeof(stats));
    bcmos_mutex_create(&conn_lock_, 0, "vomci");
    bcmos_mutex_create(&omci_ind_lock, 0, "omci_ind");
    bcmos_sem_create(&omci_ind_sem, 0, 0, "omci_ind");
    STAILQ_INIT(&omci_ind_list);
    STAILQ_INSERT_TAIL(&connection_list, this, next);
}

VomciConnection::~VomciConnection()
{
    STAILQ_REMOVE_SAFE(&connection_list, this, VomciConnection, next);
    if (connected_)
    {
        setConnected(false);
        bcmos_sem_post(&omci_ind_sem);
    }
    OmciPacketEntry *omci_packet;
    bcmos_mutex_lock(&omci_ind_lock);
    while ((omci_packet = STAILQ_FIRST(&omci_ind_list)))
    {
        STAILQ_REMOVE_HEAD(&omci_ind_list, next);
        delete omci_packet;
    }
    bcmos_mutex_unlock(&omci_ind_lock);
    bcmos_sem_destroy(&omci_ind_sem);
    bcmos_mutex_destroy(&omci_ind_lock);
    bcmos_mutex_destroy(&conn_lock_);
}

void VomciConnection::setConnected(bool connected)
{
    if (connected == connected_)
        return;
    bcmos_mutex_lock(&conn_lock_);
    connected_ = connected;
    bcmos_mutex_unlock(&conn_lock_);
    vomci_notify_connect_disconnect(this, connected);
    if (connected)
        UpdateOnuAssignmentsConnected();
    else
        UpdateOnuAssignmentsDisconnected();
}

// Enque packet received from ONU.
// Eventually it will be popped using PopPacketFromOnuFromTxQueue and transmitted to vOMCI peer
bool VomciConnection::OmciRxFromOnu(OmciPacketEntry *omci_packet)
{
    bool ret;
    bcmos_mutex_lock(&conn_lock_);
    if (connected_)
    {
        bcmos_mutex_lock(&omci_ind_lock);
        STAILQ_INSERT_TAIL(&omci_ind_list, omci_packet, next);
        // Kick thread that unwinds the queue if the queue was empty
        if (STAILQ_FIRST(&omci_ind_list) == omci_packet)
            bcmos_sem_post(&omci_ind_sem);
        bcmos_mutex_unlock(&omci_ind_lock);
        ++stats.packets_onu_to_vomci_recv;
        ret = true;
    }
    else
    {
        BCM_POLT_LOG(DEBUG, "vOMCI %s: Failed to send OMCI RX message from  %s:%u. Not connected\n",
            name_.c_str(), omci_packet->header().chnl_term_name().c_str(), omci_packet->header().onu_id());
        delete omci_packet;
        ++stats.packets_onu_to_vomci_disc;
        ret = false;
    }
    bcmos_mutex_unlock(&conn_lock_);
    return ret;
}

// Pop packet received from ONU from vomci connection's TX queue
OmciPacketEntry *VomciConnection::PopPacketFromOnuFromTxQueue(void)
{
    OmciPacketEntry *omci_packet;
    bcmos_mutex_lock(&omci_ind_lock);
    omci_packet = STAILQ_FIRST(&omci_ind_list);
    if (omci_packet != nullptr)
    {
        STAILQ_REMOVE_HEAD(&omci_ind_list, next);
    }
    bcmos_mutex_unlock(&omci_ind_lock);
    return omci_packet;
}

// Connected. It might affect ONU channel assignment
void VomciConnection::UpdateOnuAssignmentsConnected()
{
    const char *remote_endpoint_name = this->remote_endpoint_name();
    // Assign ONUs with vomci-endpoint explicitly assigned in v-ani
    ht_iterator iter = ht_iterator_get(onu_info_table);
    OnuInfo *info = onu_info_get_next(&iter);
    while (info != nullptr)
    {
        if (info->endpoint_name() != nullptr && remote_endpoint_name != nullptr &&
            !strcmp(info->endpoint_name(), remote_endpoint_name))
        {
            info->AssignEndpoint(this, nullptr);
        }
        info = onu_info_get_next(&iter);
    }

    // Assign by filter
    OnuFilterSet::FilterEntry *filter = nullptr;
    while ((filter = filter_set.GetNextByEndpoint(filter, remote_endpoint_name)) != nullptr)
        filter_set.UpdateOnuAssignmentsFilterAdded(filter);
}

// Disconnected. It might affect ONU channel assignment
void VomciConnection::UpdateOnuAssignmentsDisconnected()
{
    const char *remote_endpoint_name = this->remote_endpoint_name();
    // Assign ONUs with vomci-endpoint explicitly assigned in v-ani
    ht_iterator iter = ht_iterator_get(onu_info_table);
    OnuInfo *info = onu_info_get_next(&iter);
    while (info != nullptr)
    {
        if (info->endpoint_name() != nullptr && remote_endpoint_name != nullptr &&
            !strcmp(info->endpoint_name(), remote_endpoint_name))
        {
            info->AssignEndpoint(nullptr, nullptr);
        }
        info = onu_info_get_next(&iter);
    }

    // Assign by filter
    OnuFilterSet::FilterEntry *filter = nullptr;
    while ((filter = filter_set.GetNextByEndpoint(filter, remote_endpoint_name)) != nullptr)
        filter_set.UpdateOnuAssignmentsFilterRemoved(filter);
}

//
// External services
//

// Enable server subsystem
bcmos_errno bcm_grpc_processor_enable_disable(bool enable, GrpcProcessor::processor_type type)
{
    GrpcProcessor *entry, *tmp;

    BCM_POLT_LOG(INFO, "%s %s subsystem..\n",
        enable ? "Enabling" : "Disabling",
        (type == GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_SERVER) ? "server" : "client");

    STAILQ_FOREACH_SAFE(entry, &client_server_list, next, tmp)
    {
        if (entry->type() == type)
        {
            if (enable)
            {
                if (!entry->isStarted())
                    entry->CreateTaskAndStart();
            }
            else
            {
                entry->Stop();
            }
        }
    }

    subsystem_enabled[(int)type] = enable;

    return BCM_ERR_OK;;
}

bool bcm_grpc_processor_is_enabled(GrpcProcessor::processor_type type)
{
    return subsystem_enabled[(int)type];
}

//
// Debug functions
//

void bcm_tr451_stats_get(const char **endpoint_name, const char **peer_name, VomciConnectionStats *stats)
{
    const char *prev_name=*endpoint_name;
    VomciConnection *conn = nullptr;

    memset(stats, 0, sizeof(*stats));
    *endpoint_name = nullptr;
    *peer_name = nullptr;

    if (prev_name != nullptr)
    {
        conn = vomci_connection_get_by_name(prev_name, nullptr);
        if (conn == nullptr)
            return;
    }
    conn = vomci_connection_get_next(conn, nullptr);
    if (conn == nullptr)
        return;
    *stats = conn->stats;
    *endpoint_name = conn->endpoint();
    *peer_name = conn->name();
}

//
// ONU status change notification
//

static xpon_v_ani_state_change_report_cb tr451_onu_status_change_cb;

bcmos_errno bcm_tr451_onu_state_change_notify_cb_register(xpon_v_ani_state_change_report_cb cb)
{
    tr451_onu_status_change_cb = cb;
    return BCM_ERR_OK;
}


//
// Vendor event callbacks
//

// OMCI packet received from ONU callback.
// It is the responsibility of this callback to release packet when no longer needed
static void tr451_polt_omci_rx_cb(void *user_handle, OmciPacketEntry *packet)
{
    // Find vomci connection
    OnuInfo *onu = vomci_get_by_omci_packet(*packet);
    VomciConnection *conn = (onu != nullptr ) ? onu->vomci : nullptr;
    bool is_sent;
    if (conn == nullptr)
    {
        BCM_POLT_LOG(ERROR, "Can't forward OMCI packet from ONU %s:%u to vOMCI. No connection\n",
            packet->header().chnl_term_name().c_str(), packet->header().onu_id());
        ++onu->message_errors;
        delete packet;
        return;
    }
    packet->mutable_header()->set_olt_name(conn->local_name());

    // Push to vOMCI connection tranmsit queue
    is_sent = conn->OmciRxFromOnu(packet);
    if (is_sent)
        ++onu->out_messages;
    else
        ++onu->message_errors;
}

/**
* @brief  Callback function to be called upon ONU state change
*/
static void tr451_polt_onu_state_change_cb(void *user_handle, const tr451_polt_onu_info *vendor_onu_info)
{
    if (vendor_onu_info->cterm_name == nullptr)
    {
        BCM_POLT_LOG(ERROR, "cterm_name must be set. tr451_onu_state_change_cb event is ignored\n");
        return;
    }
    if (vendor_onu_info->onu_id >= TR451_POLT_MAX_ONUS_PER_PON)
    {
        BCM_POLT_LOG(ERROR, "onu_id %u is > %u. tr451_onu_state_change_cb event is ignored\n",
            vendor_onu_info->onu_id, TR451_POLT_MAX_ONUS_PER_PON);
        return;
    }
    OnuInfo *onu_info = onu_info_get(vendor_onu_info->cterm_name, vendor_onu_info->onu_id);

    // Removed ?
    if ((vendor_onu_info->presence_flags & XPON_ONU_PRESENCE_FLAG_ONU) == 0)
    {
        if (onu_info != nullptr)
            delete onu_info;
        return;
    }

    OnuFilterSet::FilterEntry *filter;
    VomciConnection *vomci;
    find_channel_assignment(&vendor_onu_info->serial_number, &filter, &vomci);

    // Register in onu_info
    onu_info_set(vendor_onu_info->cterm_name, vendor_onu_info->onu_id,
        &vendor_onu_info->serial_number, filter, vomci);
}

// Report ONU state change to NETCONF server.
// Usually it is only needed when adding ONU via CLI for debugging
static bcmos_errno tr451_polt_onu_state_change_notify_cb(void *user_handle, const tr451_polt_onu_info *onu_info)
{
    if (tr451_onu_status_change_cb == nullptr)
        return BCM_ERR_OK;
    bcmos_errno err;
    err = tr451_onu_status_change_cb(
        onu_info->cterm_name, onu_info->onu_id,
        onu_info->serial_number.data, onu_info->presence_flags);
    return err;
}


//
// Initialization
//

static bool polt_initialized;

bcmos_errno bcm_tr451_polt_init(const tr451_polt_init_parms *init_parms)
{
    bcmos_errno err;

    if (polt_initialized)
        return BCM_ERR_ALREADY;

    bcm_polt_log_id = bcm_dev_log_id_register("POLT", init_parms->log_level, DEV_LOG_ID_TYPE_BOTH);

    bcm_tr451_polt_cli_init();

    // Create ONU info hash
    onu_info_table = hash_table_create(
        TR451_POLT_MAX_PONS_PER_OLT * TR451_POLT_MAX_ONUS_PER_PON,
        sizeof(OnuInfo),
        sizeof(onu_info_key),
        (char *)"active_onu_table");
    if (onu_info_table == nullptr)
        return BCM_ERR_NOMEM;

    // Initialize vendor interface
    err = tr451_vendor_init();

    // Register for vendor events
    tr451_vendor_event_cfg vendor_event_cfg =  {};
    vendor_event_cfg.tr451_omci_rx_cb = tr451_polt_omci_rx_cb;
    vendor_event_cfg.tr451_onu_state_change_cb = tr451_polt_onu_state_change_cb;
    vendor_event_cfg.tr451_onu_state_change_notify_cb = tr451_polt_onu_state_change_notify_cb;

    tr451_vendor_event_register(&vendor_event_cfg);

    // Initialize client and server
    STAILQ_INIT(&connection_list);
    STAILQ_INIT(&client_server_list);
    err = err ? err : bcm_tr451_polt_grpc_server_init();
    err = err ? err : bcm_tr451_polt_grpc_client_init();

    polt_initialized = true;

    return err;
}

//
// client endpoints helper functions
//
tr451_client_endpoint *bcm_tr451_client_endpoint_alloc(const char *name)
{
    tr451_client_endpoint *ep;
    char *name_copy;
    if (name == nullptr)
        return nullptr;
    ep = (tr451_client_endpoint *)bcmos_calloc(sizeof(tr451_client_endpoint) + strlen(name) + 1);
    if (ep == nullptr)
        return nullptr;
    STAILQ_INIT(&ep->entry_list);
    ep->name = name_copy = (char *)(ep + 1);
    strcpy(name_copy, name);
    BCM_POLT_LOG(DEBUG, "Allocated client endpoint %s\n", name);
    return ep;
}

bcmos_errno bcm_tr451_client_endpoint_add_entry(tr451_client_endpoint *ep, const tr451_endpoint *entry)
{
    uint32_t alloc_len = sizeof(tr451_endpoint);
    tr451_endpoint *e;
    char *name_copy;

    if (ep == nullptr || entry == nullptr)
        return BCM_ERR_PARM;
    if (entry->name != nullptr)
        alloc_len += strlen(entry->name) + 1;
    if (entry->host_name != nullptr)
        alloc_len += strlen(entry->host_name) + 1;
    e = (tr451_endpoint *)bcmos_calloc(alloc_len);
    if (e == nullptr)
        return BCM_ERR_NOMEM;
    name_copy = (char *)(e + 1);
    if (entry->name != nullptr)
    {
        e->name = name_copy;
        strcpy(name_copy, entry->name);
        name_copy += strlen(entry->name) + 1;
    }
    if (entry->host_name != nullptr)
    {
        e->host_name = name_copy;
        strcpy(name_copy, entry->host_name);
    }
    e->port = entry->port;
    STAILQ_INSERT_TAIL(&ep->entry_list, e, next);
    BCM_POLT_LOG(DEBUG, "Edded entry to client endpoint %s: %s host-name=%s port=%u\n",
        ep->name, entry->name, entry->host_name, entry->port);
    return BCM_ERR_OK;
}

void bcm_tr451_client_endpoint_free(tr451_client_endpoint *ep)
{
    tr451_endpoint *e;
    if (ep == nullptr)
        return;
    BCM_POLT_LOG(DEBUG, "Released client endpoint %s\n", ep->name);
    while ((e = STAILQ_FIRST(&ep->entry_list)) != nullptr)
    {
        STAILQ_REMOVE_HEAD(&ep->entry_list, next);
        bcmos_free(e);
    }
    bcmos_free(ep);
}

bcmos_errno bcm_tr451_onu_status_get(const char *cterm_name, uint16_t onu_id,
   bbf_vomci_communication_status *status, const char **remote_endpoint,
   uint64_t *in_messages, uint64_t *out_messages, uint64_t *message_errors)
{
    OnuInfo *onu_info = onu_info_get(cterm_name, onu_id);
    if (onu_info == nullptr)
        return BCM_ERR_NOENT;
    const char *onu_endpoint = onu_info->endpoint_name();
    if (remote_endpoint != nullptr)
        *remote_endpoint = onu_endpoint;
    if (status != nullptr)
    {
        VomciConnection *conn = onu_info->vomci;
        if (conn != nullptr)
        {
            *status = conn->isConnected() ?
                BBF_VOMCI_COMMUNICATION_STATUS_CONNECTION_ACTIVE :
                BBF_VOMCI_COMMUNICATION_STATUS_CONNECTION_INACTIVE;
        }
        else if (onu_endpoint && *onu_endpoint)
        {
            *status = BBF_VOMCI_COMMUNICATION_STATUS_CONNECTION_INACTIVE;
        }
        else
        {
            *status = BBF_VOMCI_COMMUNICATION_STATUS_REMOTE_ENDPOINT_IS_NOT_ASSIGNED;
        }
    }
    if (in_messages)
        *in_messages = onu_info->in_messages;
    if (out_messages)
        *out_messages = onu_info->out_messages;
    if (message_errors)
        *message_errors = onu_info->message_errors;
    return BCM_ERR_OK;
}


/*
 * Authentication parameters
 */

#define MAX_FILE_NAME_LENGTH  256
static char priv_key_file_name[MAX_FILE_NAME_LENGTH];
static char my_cert_file_name[MAX_FILE_NAME_LENGTH];
static char peer_cert_file_name[MAX_FILE_NAME_LENGTH];

static bool file_exists(const char *filename)
{
    FILE *f;
    if ((f=fopen(filename, "r"))== nullptr)
    {
        BCM_POLT_LOG(ERROR, "Can't open file %s for reading\n", filename);
        return false;
    }
    fclose(f);
    return true;
}

/* Authentication */
bcmos_errno bcm_tr451_auth_set(const char *priv_key_file, const char *my_cert_file, const char *peer_cert_file)
{
    if (!priv_key_file || !priv_key_file[0] || !my_cert_file || !my_cert_file[0] || !peer_cert_file || !peer_cert_file[0])
        return BCM_ERR_PARM;
    if (!file_exists(priv_key_file) || !file_exists(my_cert_file) || !file_exists(peer_cert_file))
        return BCM_ERR_NOENT;
    strncpy(priv_key_file_name, priv_key_file, sizeof(priv_key_file_name) - 1);
    strncpy(my_cert_file_name, my_cert_file, sizeof(my_cert_file_name) - 1);
    strncpy(peer_cert_file_name, peer_cert_file, sizeof(peer_cert_file_name) - 1);
    return BCM_ERR_OK;
}

bcmos_errno bcm_tr451_auth_get(const char **p_priv_key_file, const char **p_my_cert_file, const char **p_peer_cert_file)
{
    if (!priv_key_file_name[0])
        return BCM_ERR_NOENT;
    *p_priv_key_file = priv_key_file_name;
    *p_my_cert_file = my_cert_file_name;
    *p_peer_cert_file = peer_cert_file_name;
    return BCM_ERR_OK;
}


static bool _read_file_into_string(const char *filename, string &data)
{
    std::ifstream iff(filename);
    data.assign((std::istreambuf_iterator<char>(iff)), (std::istreambuf_iterator<char>()) );
    return true;
}

bool bcm_tr451_auth_data(string &priv_key, string &my_cert, string &peer_cert)
{
    bool res;
    if (!priv_key_file_name[0])
        return false;
    res = _read_file_into_string(priv_key_file_name, priv_key);
    res &= _read_file_into_string(my_cert_file_name, my_cert);
    res &= _read_file_into_string(peer_cert_file_name, peer_cert);
    return res;
}
