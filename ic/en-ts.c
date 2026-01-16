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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* OVS includes. */
#include "openvswitch/util.h"
#include "openvswitch/vlog.h"
#include "openvswitch/hmap.h"
#include "openvswitch/shash.h"

/* OVN includes. */
#include "lib/inc-proc-eng.h"
#include "lib/ovn-ic-nb-idl.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-nb-idl.h"
#include "en-ts.h"
#include "ovn-ic.h"
#include "ovn-util.h"
#include "smap.h"
#include "util.h"
#include "stopwatch.h"
#include "stopwatch-names.h"
#include "en-enum-datapaths.h"

VLOG_DEFINE_THIS_MODULE(en_ts);

static void ts_data_init(struct ed_type_ts_data *data);
static void ts_data_destroy(struct ed_type_ts_data *data);
static void build_ts_run(const struct icnbrec_transit_switch_table *ts_table,
                         const struct icsbrec_datapath_binding_table *icsb_dp_table,
                         const struct nbrec_logical_switch_table *ls_table,
                         const struct icnbrec_ic_nb_global_table *ic_nb_global,
                         const struct icsbrec_encap_table *encap_table,
                         struct hmap *dp_tnlids, struct shash *isb_ts_dps,
                         struct shash *nb_tses);
void en_ts_clear_tracked_data(void *data);
static void clear_shash(struct shash *sh);
static void en_ts_clear_tracked(struct ed_type_ts_data *data);
static void ts_clear(struct ed_type_ts_data *data);
static enum ic_datapath_type ic_dp_get_type(
            const struct icsbrec_datapath_binding *isb_dp);
static bool is_vxlan_mode(struct engine_node *node);

enum engine_node_state
en_ts_run(struct engine_node *node, void *data)
{
    struct ed_type_ts_data *ts_data = (struct ed_type_ts_data *) data;

    ts_data_destroy(ts_data);
    ts_data_init(ts_data);

    const struct icnbrec_transit_switch_table *ts_table =
        EN_OVSDB_GET(engine_get_input("ICNB_transit_switch", node));

    const struct icsbrec_datapath_binding_table *dp_table =
        EN_OVSDB_GET(engine_get_input("ICSB_datapath_binding", node));

    const struct nbrec_logical_switch_table *ls_table =
        EN_OVSDB_GET(engine_get_input("NB_logical_switch", node));

    const struct icnbrec_ic_nb_global_table *nb_global_table =
        EN_OVSDB_GET(engine_get_input("ICNB_ic_nb_global", node));

    const struct icsbrec_encap_table *encap_table =
        EN_OVSDB_GET(engine_get_input("ICSB_encap", node));

    stopwatch_start(OVN_IC_TRANSIT_SWITCH_RUN_STOPWATCH_NAME, time_usec());
    build_ts_run(ts_table, dp_table, ls_table, nb_global_table, encap_table,
                 &ts_data->dp_tnlids, &ts_data->isb_ts_dps, &ts_data->nb_tses);
    stopwatch_stop(OVN_IC_TRANSIT_SWITCH_RUN_STOPWATCH_NAME, time_usec());

    return EN_UPDATED;
}

void *
en_ts_init(struct engine_node *node OVS_UNUSED,
           struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_ts_data *data = xzalloc(sizeof *data);
    ts_data_init(data);
    return data;
}

void
en_ts_cleanup(void *data)
{
    struct ed_type_ts_data *ts_data = (struct ed_type_ts_data *) data;
    ts_data_destroy(ts_data);
}

void
en_ts_clear_tracked_data(void *data)
{
    struct ed_type_ts_data *ts_data = (struct ed_type_ts_data *) data;
    ts_clear(ts_data);
}

enum engine_input_handler_result
en_ts_handler(struct engine_node *node, void *data)
{
    stopwatch_start(OVN_IC_TRANSIT_SWITCH_STOPWATCH_NAME, time_usec());
    struct ed_type_ts_data *ts_data = (struct ed_type_ts_data *) data;
    ts_data->tracked = true;

    const struct engine_context *ctx = engine_get_context();
    bool vxlan_mode = is_vxlan_mode(node);

    const struct icnbrec_transit_switch_table *ts_table =
        EN_OVSDB_GET(engine_get_input("ICNB_transit_switch", node));

    const struct icsbrec_datapath_binding_table *dp_table =
        EN_OVSDB_GET(engine_get_input("ICSB_datapath_binding", node));

    const struct nbrec_logical_switch_table *ls_table =
        EN_OVSDB_GET(engine_get_input("NB_logical_switch", node));

    struct ed_type_enum_datapaths *enum_datapath =
        engine_get_input_data("enum_datapaths", node);

    struct enum_datapaths_tracked *datapath_tracked_data =
        &enum_datapath->tracked_data;

    const struct icnbrec_transit_switch *tracked_ts;
    ICNBREC_TRANSIT_SWITCH_TABLE_FOR_EACH_TRACKED (tracked_ts, ts_table) {
        /* "New" + "Deleted" is a no-op. */
        if (icnbrec_transit_switch_is_deleted(tracked_ts) &&
            icnbrec_transit_switch_is_new(tracked_ts)) {
            continue;
        }

        struct nbrec_logical_switch *ls =
            shash_find_and_delete(&datapath_tracked_data->crupdated_ls,
                                  tracked_ts->name);

        if (icnbrec_transit_switch_is_deleted(tracked_ts)) {
            const struct nbrec_logical_switch *deleted_ls;
            NBREC_LOGICAL_SWITCH_TABLE_FOR_EACH(deleted_ls, ls_table) {
                if (!strcmp(deleted_ls->name, tracked_ts->name)) {
                    nbrec_logical_switch_delete(deleted_ls);
                }
            }

            const struct icsbrec_datapath_binding *dp;
            ICSBREC_DATAPATH_BINDING_TABLE_FOR_EACH(dp, dp_table) {
                if (!strcmp(dp->transit_switch, tracked_ts->name)) {
                    ovn_free_tnlid(&enum_datapath->dp_tnlids, dp->tunnel_key);
                    icsbrec_datapath_binding_delete(dp);
                }
            }

            shash_add(&ts_data->tracked_ts_data.deleted_ts,
                      tracked_ts->name, tracked_ts);
            continue;
        }

        if (icnbrec_transit_switch_is_new(tracked_ts)) {
            if (ctx->ovninb_idl_txn && !ls) {
                ls = nbrec_logical_switch_insert(ctx->ovnnb_idl_txn);
                nbrec_logical_switch_set_name(ls, tracked_ts->name);
                nbrec_logical_switch_update_other_config_setkey(
                           ls, "interconn-ts", tracked_ts->name);
                nbrec_logical_switch_update_other_config_setkey(
                           ls, "ic-vxlan_mode", vxlan_mode ? "true" : "false");

                shash_add(&ts_data->tracked_ts_data.crupdated_ts,
                          tracked_ts->name, tracked_ts);
            }
        }

        if (icnbrec_transit_switch_is_updated(tracked_ts,
                                    ICNBREC_TRANSIT_SWITCH_COL_OTHER_CONFIG)) {
            bool _vxlan = smap_get_bool(&ls->other_config,
                                       "ic-vxlan_mode", false);
            if (ls && (_vxlan != vxlan_mode)) {
                nbrec_logical_switch_update_other_config_setkey(
                        ls, "ic-vxlan_mode",
                        vxlan_mode ? "true" : "false");
                shash_add(&ts_data->tracked_ts_data.crupdated_ts,
                          tracked_ts->name, tracked_ts);
            }
        }

        /* Sync TS between INB and ISB.  This is performed after syncing with AZ
         * SB, to avoid uncommitted ISB datapath tunnel key to be synced back to
         * AZ. */
        if (ctx->ovnisb_idl_txn) {
            const struct icsbrec_datapath_binding *isb_dp =
                shash_find_and_delete(&enum_datapath->isb_ts_dps,
                                               tracked_ts->name);
            if (!isb_dp) {
                /* New ISB Datapath Binding required */
                int64_t dp_key = allocate_dp_key(
                    &enum_datapath->dp_tnlids, vxlan_mode,
                    "transit switch datapath");
                if (dp_key) {
                    ovn_add_tnlid(&enum_datapath->dp_tnlids, dp_key);
                    isb_dp =
                        icsbrec_datapath_binding_insert(ctx->ovnisb_idl_txn);
                    icsbrec_datapath_binding_set_transit_switch(isb_dp,
                                                      tracked_ts->name);
                    icsbrec_datapath_binding_set_tunnel_key(isb_dp, dp_key);
                }
            } else {
                if (!isb_dp->tunnel_key) {
                    int64_t dp_key = allocate_dp_key(
                          &enum_datapath->dp_tnlids, vxlan_mode,
                                     "transit switch datapath");
                    if (dp_key) {
                        ovn_add_tnlid(&enum_datapath->dp_tnlids, dp_key);
                        icsbrec_datapath_binding_set_tunnel_key(isb_dp, dp_key);
                    }
                }
            }

            if (isb_dp) {
                if (!isb_dp->type) {
                    icsbrec_datapath_binding_set_type(isb_dp,
                                            "transit-switch");
                }
                if (!isb_dp->nb_ic_uuid) {
                    icsbrec_datapath_binding_set_nb_ic_uuid(isb_dp,
                                            &tracked_ts->header_.uuid, 1);
                }
            }
        }
    }
    stopwatch_stop(OVN_IC_TRANSIT_SWITCH_STOPWATCH_NAME, time_usec());
    return EN_HANDLED_UPDATED;
}

enum engine_input_handler_result
en_ts_ic_nb_global_handler(struct engine_node *node, void *data)
{
    struct ed_type_ts_data *ts_data = data;
    bool dp_key_refresh = false;
    struct shash isb_ts_dps;
    shash_init(&isb_ts_dps);

    const struct icnbrec_ic_nb_global_table *ic_nb_global_table =
        EN_OVSDB_GET(engine_get_input("ICNB_ic_nb_global", node));

    const struct nbrec_logical_switch_table *ls_table =
        EN_OVSDB_GET(engine_get_input("NB_logical_switch", node));

    const struct icsbrec_datapath_binding_table *dp_table =
        EN_OVSDB_GET(engine_get_input("ICSB_datapath_binding", node));

    const struct icsbrec_datapath_binding *datapath;
    ICSBREC_DATAPATH_BINDING_TABLE_FOR_EACH (datapath, dp_table) {
        enum ic_datapath_type dp_type = ic_dp_get_type(datapath);
        if (dp_type == IC_SWITCH) {
            shash_add(&isb_ts_dps, datapath->transit_switch, datapath);
        }
    }

    const struct icnbrec_ic_nb_global *icnb_global;
    ICNBREC_IC_NB_GLOBAL_TABLE_FOR_EACH_TRACKED (icnb_global,
        ic_nb_global_table) {

        if (icnbrec_ic_nb_global_is_updated(icnb_global,
                          ICNBREC_IC_NB_GLOBAL_COL_OPTIONS)) {
            bool vxlan_mode = smap_get_bool(&icnb_global->options,
                                            "vxlan_mode", false);

            const struct nbrec_logical_switch *ls;
            NBREC_LOGICAL_SWITCH_TABLE_FOR_EACH (ls, ls_table) {
                const char *interconn = smap_get(
                    &ls->other_config, "interconn-ts");
                bool vxlan_mode_ls = smap_get_bool(
                    &ls->other_config, "ic-vxlan_mode", false);

                if (!interconn) {
                    continue;
                }

                if (vxlan_mode_ls != vxlan_mode) {
                    nbrec_logical_switch_update_other_config_setkey(
                        ls, "ic-vxlan_mode", vxlan_mode ? "true" : "false");
                    dp_key_refresh = true;
                }

                struct icsbrec_datapath_binding *isb_dp =
                               shash_find_and_delete(&isb_ts_dps, ls->name);
                if (isb_dp && dp_key_refresh) {
                    int64_t nb_tnl_key = smap_get_int(
                        &ls->other_config,"requested-tnl-key", 0);
                    if (nb_tnl_key != isb_dp->tunnel_key) {
                        char *tnl_key_str = xasprintf("%"PRId64,
                                             isb_dp->tunnel_key);
                        nbrec_logical_switch_update_other_config_setkey(
                            ls, "requested-tnl-key", tnl_key_str);
                    }

                    ovn_free_tnlid(&ts_data->dp_tnlids, isb_dp->tunnel_key);

                    int64_t dp_key = allocate_dp_key(
                        &ts_data->dp_tnlids, vxlan_mode,
                        "transit switch datapath");
                    if (dp_key) {
                        char *tnl_key_str = xasprintf("%"PRId64, dp_key);
                        nbrec_logical_switch_update_other_config_setkey(
                            ls, "requested-tnl-key", tnl_key_str);
                        free(tnl_key_str);
                        icsbrec_datapath_binding_set_tunnel_key(isb_dp,
                                                                dp_key);
                    }
                }
            }
        }
        shash_destroy(&isb_ts_dps);
        return EN_HANDLED_UPDATED;
    }
    return EN_UNHANDLED;
}

static void
build_ts_run(const struct icnbrec_transit_switch_table *ts_table,
             const struct icsbrec_datapath_binding_table *icsb_dp_table,
             const struct nbrec_logical_switch_table *ls_table,
             const struct icnbrec_ic_nb_global_table *ic_nb_global,
             const struct icsbrec_encap_table *encap_table,
             struct hmap *dp_tnlids, struct shash *isb_ts_dps,
             struct shash *nb_tses)
{
    bool vxlan_mode = false;
    bool dp_key_refresh = false;

    const struct icnbrec_transit_switch *ts;
    const struct nbrec_logical_switch *ls;
    const struct icsbrec_datapath_binding *isb_dp;
    const struct engine_context *ctx = engine_get_context();

    const struct icnbrec_ic_nb_global *ic_nb =
        icnbrec_ic_nb_global_table_first(ic_nb_global);

    if (ic_nb && smap_get_bool(&ic_nb->options, "vxlan_mode", false)) {
        const struct icsbrec_encap *encap =
                icsbrec_encap_table_first(encap_table);
        if (!strcmp(encap->type, "vxlan")) {
            vxlan_mode = true;
        }
    }

    ICSBREC_DATAPATH_BINDING_TABLE_FOR_EACH (isb_dp, icsb_dp_table) {
        ovn_add_tnlid(dp_tnlids, isb_dp->tunnel_key);

        enum ic_datapath_type dp_type = ic_dp_get_type(isb_dp);
        if (dp_type == IC_SWITCH) {
            shash_add(isb_ts_dps, isb_dp->transit_switch, isb_dp);
        }
    }

    /* Sync INB TS to AZ NB */
    if (ctx->ovnnb_idl_txn) {
        /* Get current NB Logical_Switch with other_config:interconn-ts */
        NBREC_LOGICAL_SWITCH_TABLE_FOR_EACH (ls, ls_table) {
            const char *ts_name = smap_get(&ls->other_config, "interconn-ts");
            if (ts_name) {
                shash_add(nb_tses, ts_name, ls);
            }
        }

        /* Create/update NB Logical_Switch for each TS */
        ICNBREC_TRANSIT_SWITCH_TABLE_FOR_EACH (ts, ts_table) {
            ls = shash_find_and_delete(nb_tses, ts->name);
            if (!ls) {
                ls = nbrec_logical_switch_insert(ctx->ovnnb_idl_txn);
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

            isb_dp = shash_find_data(isb_ts_dps, ts->name);
            if (isb_dp) {
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
        SHASH_FOR_EACH (node, nb_tses) {
            nbrec_logical_switch_delete(node->data);
        }
    }

    /* Sync TS between INB and ISB.  This is performed after syncing with AZ
     * SB, to avoid uncommitted ISB datapath tunnel key to be synced back to
     * AZ. */
    if (ctx->ovnisb_idl_txn) {
        /* Create ISB Datapath_Binding */
        ICNBREC_TRANSIT_SWITCH_TABLE_FOR_EACH (ts, ts_table) {
            isb_dp = shash_find_and_delete(isb_ts_dps, ts->name);
            if (!isb_dp) {
                /* Allocate tunnel key */
                int64_t dp_key = allocate_dp_key(dp_tnlids, vxlan_mode,
                                                 "transit switch datapath");
                if (!dp_key) {
                    continue;
                }
                isb_dp = icsbrec_datapath_binding_insert(ctx->ovnisb_idl_txn);
                icsbrec_datapath_binding_set_transit_switch(isb_dp, ts->name);
                icsbrec_datapath_binding_set_tunnel_key(isb_dp, dp_key);
            } else if (dp_key_refresh) {
                /* Refresh tunnel key since encap mode has changed. */
                int64_t dp_key = allocate_dp_key(dp_tnlids, vxlan_mode,
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

        struct shash_node *node;
        SHASH_FOR_EACH (node, isb_ts_dps) {
            icsbrec_datapath_binding_delete(node->data);
        }
    }
}

static void
ts_data_init(struct ed_type_ts_data *data)
{
    hmap_init(&data->dp_tnlids);
    shash_init(&data->isb_ts_dps);
    shash_init(&data->nb_tses);
    shash_init(&data->tracked_ts_data.crupdated_ts);
    shash_init(&data->tracked_ts_data.deleted_ts);
    data->tracked = false;
}

static void
ts_data_destroy(struct ed_type_ts_data *data)
{
    ovn_destroy_tnlids(&data->dp_tnlids);
    shash_destroy(&data->isb_ts_dps);
    shash_destroy(&data->nb_tses);
}

static void
clear_shash(struct shash *sh)
{
    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, sh) {
        hmap_remove(&sh->map, &node->node);
        free(node->name);
        free(node);
    }
}

static void
en_ts_clear_tracked(struct ed_type_ts_data *data)
{
    struct tracked_ts_data *tr_data = &data->tracked_ts_data;
    clear_shash(&tr_data->crupdated_ts);
    clear_shash(&tr_data->deleted_ts);
    data->tracked = false;
}


static void
ts_clear(struct ed_type_ts_data *data)
{
    ovn_destroy_tnlids(&data->dp_tnlids);
    hmap_init(&data->dp_tnlids);

    shash_clear(&data->isb_ts_dps);
    shash_clear(&data->nb_tses);
    en_ts_clear_tracked(data);
}

static enum ic_datapath_type
ic_dp_get_type(const struct icsbrec_datapath_binding *isb_dp)
{
    if (isb_dp->type && !strcmp(isb_dp->type, "transit-router")) {
        return IC_ROUTER;
    }

    return IC_SWITCH;
}

static bool
is_vxlan_mode(struct engine_node *node) {
    bool vxlan_mode = false;

    const struct icsbrec_encap_table *encap_table =
        EN_OVSDB_GET(engine_get_input("ICSB_encap", node));

    const struct icnbrec_ic_nb_global_table *ic_nb_global_table =
        EN_OVSDB_GET(engine_get_input("ICNB_ic_nb_global", node));

    const struct icnbrec_ic_nb_global *icnb_global =
        icnbrec_ic_nb_global_table_first(ic_nb_global_table);

    if (icnb_global &&
        smap_get_bool(&icnb_global->options, "vxlan_mode", false)) {
        const struct icsbrec_encap *encap =
                icsbrec_encap_table_first(encap_table);
        if (!strcmp(encap->type, "vxlan")) {
            vxlan_mode = true;
        }
    }

    return vxlan_mode;
}
