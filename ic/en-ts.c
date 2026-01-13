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

#include <config.h>

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

/* OVS includes. */
#include "openvswitch/vlog.h"

/* OVN includes. */
#include "ovn-ic.h"
#include "en-ts.h"
#include "en-enum-datapaths.h"
#include "inc-proc-ic.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-ic-nb-idl.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-util.h"
#include "lib/stopwatch-names.h"
#include "coverage.h"
#include "stopwatch.h"
#include "stopwatch-names.h"

VLOG_DEFINE_THIS_MODULE(en_transit_switch);
COVERAGE_DEFINE(ts_run);

static void
ts_run(const struct engine_context *eng_ctx,
       struct ed_type_transit_switch *ts_data,
       struct ed_type_enum_datapaths *dp_node_data,
       const struct nbrec_logical_switch_table *nbrec_ls_table,
       const struct icnbrec_ic_nb_global_table *icnbrec_nb_global_table,
       const struct icnbrec_transit_switch_table *icnbrec_ts_table,
       const struct icsbrec_encap_table *icsbrec_encap_table,
       const struct icsbrec_datapath_binding_table *icsbrec_dp_table);
static void ts_init(struct ed_type_transit_switch *data);
static void ts_destroy(struct ed_type_transit_switch *data);

enum engine_node_state
en_ts_run(struct engine_node *node, void *data)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ed_type_transit_switch *ts_data = data;

    struct ed_type_enum_datapaths *dp_node_data =
        engine_get_input_data("enum_datapaths", node);

    const struct nbrec_logical_switch_table *nbrec_ls_table =
        EN_OVSDB_GET(engine_get_input("NB_logical_switch", node));
    const struct icnbrec_ic_nb_global_table *icnbrec_nb_global_table =
        EN_OVSDB_GET(engine_get_input("ICNB_ic_nb_global", node));
    const struct icnbrec_transit_switch_table *icnbrec_ts_table =
        EN_OVSDB_GET(engine_get_input("ICNB_transit_switch", node));
    const struct icsbrec_encap_table *icsbrec_encap_table =
        EN_OVSDB_GET(engine_get_input("ICSB_encap", node));
    const struct icsbrec_datapath_binding_table *icsbrec_dp_table =
        EN_OVSDB_GET(engine_get_input("ICSB_datapath_binding", node));

    COVERAGE_INC(ts_run);
    stopwatch_start(OVN_IC_TRANSIT_SWITCH_RUN_STOPWATCH_NAME, time_usec());
    ts_run(eng_ctx, ts_data, dp_node_data, nbrec_ls_table,
           icnbrec_nb_global_table, icnbrec_ts_table, icsbrec_encap_table,
           icsbrec_dp_table);
    stopwatch_stop(OVN_IC_TRANSIT_SWITCH_RUN_STOPWATCH_NAME, time_usec());

    return EN_UPDATED;
}

void *
en_ts_init(struct engine_node *node OVS_UNUSED,
           struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_transit_switch *data = xzalloc(sizeof *data);
    ts_init(data);
    return data;
}

void
en_ts_cleanup(void *data)
{
    ts_destroy(data);
}

static void
ts_init(struct ed_type_transit_switch *data)
{
    shash_init(&data->isb_ts_dps);
    hmap_init(&data->dp_tnlids);
}

static void
ts_destroy(struct ed_type_transit_switch *data)
{
    shash_destroy(&data->isb_ts_dps);
    ovn_destroy_tnlids(&data->dp_tnlids);
}

static void
ts_run(const struct engine_context *eng_ctx,
       struct ed_type_transit_switch *ts_data OVS_UNUSED,
       struct ed_type_enum_datapaths *dp_node_data,
       const struct nbrec_logical_switch_table *nbrec_ls_table,
       const struct icnbrec_ic_nb_global_table *icnbrec_nb_global_table,
       const struct icnbrec_transit_switch_table *icnbrec_ts_table,
       const struct icsbrec_encap_table *icsbrec_encap_table,
       const struct icsbrec_datapath_binding_table *icsbrec_dp_table)
{
    const struct icnbrec_transit_switch *ts;
    bool dp_key_refresh = false;
    bool vxlan_mode = false;
    const struct icnbrec_ic_nb_global *ic_nb =
        icnbrec_ic_nb_global_table_first(icnbrec_nb_global_table);

    if (ic_nb && smap_get_bool(&ic_nb->options, "vxlan_mode", false)) {
        const struct icsbrec_encap *encap;
        ICSBREC_ENCAP_TABLE_FOR_EACH (encap, icsbrec_encap_table) {
            if (!strcmp(encap->type, "vxlan")) {
                vxlan_mode = true;
                break;
            }
        }
    }

    /* Sync INB TS to AZ NB */
    if (eng_ctx->ovnnb_idl_txn) {
        struct shash nb_tses = SHASH_INITIALIZER(&nb_tses);
        const struct nbrec_logical_switch *ls;

        /* Get current NB Logical_Switch with other_config:interconn-ts */
        NBREC_LOGICAL_SWITCH_TABLE_FOR_EACH (ls, nbrec_ls_table) {
            const char *ts_name = smap_get(&ls->other_config, "interconn-ts");
            if (ts_name) {
                shash_add(&nb_tses, ts_name, ls);
            }
        }

        /* Create/update NB Logical_Switch for each TS */
        ICNBREC_TRANSIT_SWITCH_TABLE_FOR_EACH (ts, icnbrec_ts_table) {
            ls = shash_find_and_delete(&nb_tses, ts->name);
            if (!ls) {
                ls = nbrec_logical_switch_insert(eng_ctx->ovnnb_idl_txn);
                nbrec_logical_switch_set_name(ls, ts->name);
                nbrec_logical_switch_update_other_config_setkey(ls,
                                                                "interconn-ts",
                                                                ts->name);
                nbrec_logical_switch_update_other_config_setkey(
                        ls, "ic-vxlan_mode", vxlan_mode ? "true" : "false");
            } else {
                bool _vxlan_mode = smap_get_bool(&ls->other_config,
                                                 "ic-vxlan_mode", false);
                if (_vxlan_mode != vxlan_mode) {
                    dp_key_refresh = true;
                    nbrec_logical_switch_update_other_config_setkey(
                            ls, "ic-vxlan_mode",
                            vxlan_mode ? "true" : "false");
                }
            }

            const struct icsbrec_datapath_binding *isb_dp;
            isb_dp = shash_find_data(&dp_node_data->isb_ts_dps, ts->name);
            if (!isb_dp) {
                const struct icsbrec_datapath_binding *raw;
                ICSBREC_DATAPATH_BINDING_TABLE_FOR_EACH (raw,
                                                         icsbrec_dp_table) {
                    if (raw->transit_switch && !strcmp(raw->transit_switch,
                                                       ts->name)) {
                        isb_dp = raw;
                        break;
                    }
                }
            } else {
                int64_t nb_tnl_key = smap_get_int(&ls->other_config,
                                                  "requested-tnl-key",
                                                  0);
                if (nb_tnl_key != isb_dp->tunnel_key) {
                    VLOG_DBG("Set other_config:requested-tnl-key %"PRId64
                             " for transit switch %s in NB.",
                             isb_dp->tunnel_key, ts->name);
                    char *tnl_key_str = xasprintf("%"PRId64,
                                                  isb_dp->tunnel_key);
                    nbrec_logical_switch_update_other_config_setkey(
                        ls, "requested-tnl-key", tnl_key_str);
                    free(tnl_key_str);
                }
            }
        }

        /* Delete extra NB Logical_Switch with other_config:interconn-ts */
        struct shash_node *node;
        SHASH_FOR_EACH (node, &nb_tses) {
            nbrec_logical_switch_delete(node->data);
        }
        shash_destroy(&nb_tses);
    }

    /* Sync TS between INB and ISB.  This is performed after syncing with AZ
     * SB, to avoid uncommitted ISB datapath tunnel key to be synced back to
     * AZ. */
    if (eng_ctx->ovnisb_idl_txn) {
        /* Create ISB Datapath_Binding */
        ICNBREC_TRANSIT_SWITCH_TABLE_FOR_EACH (ts, icnbrec_ts_table) {
            const struct icsbrec_datapath_binding *isb_dp =
                shash_find_and_delete(&dp_node_data->isb_ts_dps, ts->name);

            if (!isb_dp) {
                const struct icsbrec_datapath_binding *raw_isb;
                ICSBREC_DATAPATH_BINDING_TABLE_FOR_EACH (raw_isb,
                                                         icsbrec_dp_table) {
                    if (raw_isb->n_nb_ic_uuid > 0 &&
                        uuid_equals(&raw_isb->nb_ic_uuid[0],
                                    &ts->header_.uuid)) {
                        isb_dp = raw_isb;
                        if (isb_dp->transit_switch) {
                            shash_find_and_delete(&dp_node_data->isb_ts_dps,
                                                  isb_dp->transit_switch);
                        }
                        break;
                    }
                }
            }

            if (!isb_dp) {
                /* Allocate tunnel key */
                int64_t dp_key = allocate_dp_key(&dp_node_data->dp_tnlids,
                                                 vxlan_mode,
                                                 "transit switch datapath");
                if (!dp_key) {
                    continue;
                }

                isb_dp =
                    icsbrec_datapath_binding_insert(eng_ctx->ovnisb_idl_txn);
                icsbrec_datapath_binding_set_transit_switch(isb_dp, ts->name);
                icsbrec_datapath_binding_set_tunnel_key(isb_dp, dp_key);
                icsbrec_datapath_binding_set_nb_ic_uuid(isb_dp,
                                                        &ts->header_.uuid, 1);
                icsbrec_datapath_binding_set_type(isb_dp, "transit-switch");
            } else if (dp_key_refresh) {
                /* Refresh tunnel key since encap mode has changed. */
                int64_t dp_key = allocate_dp_key(&dp_node_data->dp_tnlids,
                                                 vxlan_mode,
                                                 "transit switch datapath");
                if (dp_key) {
                    icsbrec_datapath_binding_set_tunnel_key(isb_dp, dp_key);
                }
            }

            if (!isb_dp->type) {
                icsbrec_datapath_binding_set_type(isb_dp, "transit-switch");
            }

            if (!isb_dp->nb_ic_uuid) {
                icsbrec_datapath_binding_set_nb_ic_uuid(isb_dp,
                                                        &ts->header_.uuid, 1);
            }
        }

        struct shash_node *node, *next;
        SHASH_FOR_EACH_SAFE (node, next, &dp_node_data->isb_ts_dps) {
            struct icsbrec_datapath_binding *isb_dp_to_del = node->data;
            if (isb_dp_to_del->n_nb_ic_uuid > 0) {
                icsbrec_datapath_binding_delete(isb_dp_to_del);
            }
            shash_delete(&dp_node_data->isb_ts_dps, node);
        }
    }
}
