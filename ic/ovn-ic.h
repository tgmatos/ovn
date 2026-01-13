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

struct ic_state {
    bool had_lock;
    bool paused;
};

struct icsbrec_port_binding;

enum ic_datapath_type { IC_SWITCH, IC_ROUTER, IC_DATAPATH_MAX };
enum ic_port_binding_type { IC_SWITCH_PORT, IC_ROUTER_PORT, IC_PORT_MAX };

uint32_t
allocate_dp_key(struct hmap *dp_tnlids, bool vxlan_mode, const char *name);
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

#endif /* OVN_IC_H */
