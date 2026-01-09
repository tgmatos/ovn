/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef OVN_IC_H
#define OVN_IC_H 1

#include "ovsdb-idl.h"
#include "unixctl.h"
#include "lib/inc-proc-eng.h"

struct ic_input {
    /* Northbound table references */
    const struct nbrec_logical_switch_table *nbrec_logical_switch_table;
    const struct nbrec_logical_router_table *nbrec_logical_router_table;

    /* Southbound table references */
    const struct sbrec_chassis_table *sbrec_chassis_table;
    const struct sbrec_sb_global_table *sbrec_sb_global_table;

    /* InterconnectNorthbound table references */
    const struct icnbrec_transit_switch_table *icnbrec_transit_switch_table;
    const struct icnbrec_ic_nb_global_table *icnbrec_ic_nb_global_table;
    const struct icnbrec_transit_router_table *icnbrec_transit_router_table;

    /* InterconnectSouthbound table references */
    const struct icsbrec_encap_table *icsbrec_encap_table;
    const struct icsbrec_gateway_table *icsbrec_gateway_table;
    const struct icsbrec_ic_sb_global_table *icsbrec_ic_sb_global_table;
    const struct icsbrec_datapath_binding_table
        *icsbrec_datapath_binding_table;
    const struct icsbrec_availability_zone_table
        *icsbrec_availability_zone_table;

    /* Indexes */
    const struct icsbrec_availability_zone *runned_az;
    struct ovsdb_idl_index *nbrec_ls_by_name;
    struct ovsdb_idl_index *nbrec_lr_by_name;
    struct ovsdb_idl_index *nbrec_lrp_by_name;
    struct ovsdb_idl_index *nbrec_port_by_name;
    struct ovsdb_idl_index *sbrec_chassis_by_name;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    struct ovsdb_idl_index *sbrec_service_monitor_by_remote_type;
    struct ovsdb_idl_index *sbrec_service_monitor_by_ic_learned;
    struct ovsdb_idl_index *sbrec_service_monitor_by_remote_type_logical_port;
    struct ovsdb_idl_index *icnbrec_transit_switch_by_name;
    struct ovsdb_idl_index *icsbrec_service_monitor_by_source_az;
    struct ovsdb_idl_index *icsbrec_service_monitor_by_target_az;
    struct ovsdb_idl_index *icsbrec_service_monitor_by_target_az_logical_port;
};

struct ic_data {
    /* Global state for 'en-enum-datapaths'. */
    struct hmap *dp_tnlids;
    struct shash *isb_ts_dps;
    struct shash *isb_tr_dps;
};
struct ic_state {
    bool had_lock;
    bool paused;
};

struct icsbrec_port_binding;

enum ic_datapath_type { IC_SWITCH, IC_ROUTER, IC_DATAPATH_MAX };
enum ic_port_binding_type { IC_SWITCH_PORT, IC_ROUTER_PORT, IC_PORT_MAX };

const struct nbrec_logical_router_port *
get_lrp_by_lrp_name(struct ovsdb_idl_index *nbrec_lrp_by_name,
                    const char *lrp_name);
const struct sbrec_port_binding * find_sb_pb_by_name(
    struct ovsdb_idl_index *sbrec_port_binding_by_name, const char *name);
const struct nbrec_logical_switch *
    find_ts_in_nb(struct ovsdb_idl_index *nbrec_ls_by_name, char *ts_name);
const struct nbrec_logical_switch_port *
    get_lsp_by_ts_port_name(struct ovsdb_idl_index *nbrec_port_by_name,
                            const char *ts_port_name);
const struct sbrec_port_binding *
    find_sb_pb_by_name(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                       const char *name);
enum ic_port_binding_type
    ic_pb_get_type(const struct icsbrec_port_binding *isb_pb);
const struct icsbrec_availability_zone *
    az_run(struct ovsdb_idl *ovnnb_idl, struct ovsdb_idl *ovnisb_idl,
           struct ovsdb_idl_txn *ovnisb_idl_txn);
void ovn_db_run(struct ic_input *input_data, struct ic_data *ic_data,
                struct engine_context *eng_ctx);

#endif /* OVN_IC_H */
