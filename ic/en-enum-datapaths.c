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

#include <ctype.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* OVS includes. */
#include "openvswitch/vlog.h"
#include "openvswitch/shash.h"
#include "openvswitch/hmap.h"

/* OVN includes. */
#include "ovn-ic.h"
#include "en-enum-datapaths.h"
#include "inc-proc-ic.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-ic-nb-idl.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-util.h"
#include "lib/stopwatch-names.h"
#include "coverage.h"
#include "smap.h"
#include "stopwatch.h"
#include "stopwatch-names.h"

VLOG_DEFINE_THIS_MODULE(en_enum_datapaths);
COVERAGE_DEFINE(enum_datapaths_run);

static void
enum_datapath_run(const struct icsbrec_datapath_binding_table *dp_table,
                  struct ed_type_enum_datapaths *dp_data);
static enum ic_datapath_type
ic_dp_get_type(const struct icsbrec_datapath_binding *isb_dp);
static void enum_datapaths_init(struct ed_type_enum_datapaths *data);
static void enum_datapaths_destroy(struct ed_type_enum_datapaths *data);
static void clear_shash(struct shash *sh);
static void enum_datapaths_clear_tracked(struct ed_type_enum_datapaths *data);
static void enum_datapaths_clear(struct ed_type_enum_datapaths *data);

void *
en_enum_datapaths_init(struct engine_node *node OVS_UNUSED,
                       struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_enum_datapaths *data = xzalloc(sizeof *data);
    enum_datapaths_init(data);
    return data;
}

void
en_enum_datapaths_cleanup(void *data)
{
    enum_datapaths_destroy(data);
}

void
en_enum_datapaths_clear_tracked_data(void *data)
{
    enum_datapaths_clear_tracked(data);
}

enum engine_node_state
en_enum_datapaths_run(struct engine_node *node, void *data)
{
    struct ed_type_enum_datapaths *dp_data = data;

    enum_datapaths_clear(dp_data);

    const struct icsbrec_datapath_binding_table *dp_table =
        EN_OVSDB_GET(engine_get_input("ICSB_datapath_binding", node));

    COVERAGE_INC(enum_datapaths_run);
    stopwatch_start(OVN_IC_ENUM_DATAPATHS_RUN_STOPWATCH_NAME, time_msec());
    enum_datapath_run(dp_table, dp_data);
    stopwatch_stop(OVN_IC_ENUM_DATAPATHS_RUN_STOPWATCH_NAME, time_msec());

    return EN_UPDATED;
}

enum engine_input_handler_result
icsb_datapath_binding_handler(struct engine_node *node, void *data)
{
    struct ed_type_enum_datapaths *dp_data = data;
    struct enum_datapaths_tracked *tr_data = &dp_data->tracked_data;
    const struct icsbrec_datapath_binding_table *dp_table =
        EN_OVSDB_GET(engine_get_input("ICSB_datapath_binding", node));

    const struct icsbrec_datapath_binding *isb_dp;
    bool changed = false;

    ICSBREC_DATAPATH_BINDING_TABLE_FOR_EACH_TRACKED (isb_dp, dp_table) {
        changed = true;

        if (icsbrec_datapath_binding_is_deleted(isb_dp)) {
            ovn_free_tnlid(&dp_data->dp_tnlids, isb_dp->tunnel_key);
            if (ic_dp_get_type(isb_dp) == IC_ROUTER) {
                char *uuid_str = uuid_to_string(isb_dp->nb_ic_uuid);
                shash_find_and_delete(&dp_data->isb_tr_dps, uuid_str);
                free(uuid_str);
            } else {
                shash_find_and_delete(&dp_data->isb_ts_dps,
                                      isb_dp->transit_switch);
            }

            shash_add(&tr_data->deleted_datapaths,
                      isb_dp->transit_switch, isb_dp);
        } else {
            if (icsbrec_datapath_binding_is_new(isb_dp)) {
                const struct icsbrec_datapath_binding *old_dp = NULL;
                if (ic_dp_get_type(isb_dp) == IC_ROUTER) {
                    char *uuid_str = uuid_to_string(isb_dp->nb_ic_uuid);
                    old_dp = shash_find_data(&dp_data->isb_tr_dps, uuid_str);
                    free(uuid_str);
                } else {
                    old_dp = shash_find_data(&dp_data->isb_ts_dps,
                                             isb_dp->transit_switch);
                }

                if (old_dp) {
                    ovn_free_tnlid(&dp_data->dp_tnlids, old_dp->tunnel_key);
                }

                struct nbrec_logical_switch *ls =
                    shash_find_data(&tr_data->crupdated_ls,
                                   isb_dp->transit_switch);
                if (ls) {
                    int64_t nb_tnl_key = smap_get_int(&ls->other_config,
                                                "requested-tnl-key", 0);
                    if (nb_tnl_key != isb_dp->tunnel_key) {
                        VLOG_DBG("Set other_config:requested-tnl-key %"PRId64
                                 " for transit switch %s in NB.",
                                 isb_dp->tunnel_key, isb_dp->transit_switch);
                        char *tnl_key_str =
                            xasprintf("%"PRId64, isb_dp->tunnel_key);
                        nbrec_logical_switch_update_other_config_setkey(
                                  ls, "requested-tnl-key", tnl_key_str);
                        free(tnl_key_str);
                    }
                }
            }

            shash_add(&tr_data->crupdated_datapaths,
                      isb_dp->transit_switch, isb_dp);
            ovn_add_tnlid(&dp_data->dp_tnlids, isb_dp->tunnel_key);
            if (ic_dp_get_type(isb_dp) == IC_ROUTER) {
                char *uuid_str = uuid_to_string(isb_dp->nb_ic_uuid);
                shash_replace(&dp_data->isb_tr_dps, uuid_str, (void *)isb_dp);
                free(uuid_str);
            } else {
                shash_replace(&dp_data->isb_ts_dps, isb_dp->transit_switch,
                              (void *)isb_dp);
            }
        }
    }

    if (changed) {
        dp_data->tracked = true;
        return EN_HANDLED_UPDATED;
    }

    return EN_UNHANDLED;
}

enum engine_input_handler_result
nb_logical_switch_handler(struct engine_node *node, void *data)
{
    struct ed_type_enum_datapaths *dp_data = data;
    struct enum_datapaths_tracked *tr_data =
        &dp_data->tracked_data;
    const struct engine_context *ctx = engine_get_context();

    const struct nbrec_logical_switch_table *ls_table =
        EN_OVSDB_GET(engine_get_input("NB_logical_switch", node));

    const struct icnbrec_transit_switch_table *ts_table =
        EN_OVSDB_GET(engine_get_input("ICNB_transit_switch", node));

    const struct nbrec_logical_switch *ls;
    bool changed = false;

    NBREC_LOGICAL_SWITCH_TABLE_FOR_EACH_TRACKED (ls, ls_table) {
        const char *ts_name = smap_get(&ls->other_config, "interconn-ts");
        if (!ts_name) {
            continue;
        }

        changed = true;
        if (nbrec_logical_switch_is_deleted(ls)) {
            /* Self-healing: The local Logical Switch was deleted, but the
             * corresponding global Transit Switch still exists in ICNB.
             * To maintain consistency with the global state and ensure
             * connectivity, we immediately recreate the local Logical Switch.
             */
            bool ts_exists = false;
            const struct icnbrec_transit_switch *ts;
            ICNBREC_TRANSIT_SWITCH_TABLE_FOR_EACH (ts, ts_table) {
                if (!strcmp(ts->name, ts_name)) {
                    ts_exists = true;
                    break;
                }
            }

            if (ts_exists) {
                const struct nbrec_logical_switch *new_ls =
                    nbrec_logical_switch_insert(ctx->ovnnb_idl_txn);
                nbrec_logical_switch_set_name(new_ls, ts->name);
                nbrec_logical_switch_update_other_config_setkey(
                           new_ls, "interconn-ts", ts->name);
                bool vxlan_mode = smap_get_bool(&ls->other_config,
                                             "vxlan_mode", false);
                nbrec_logical_switch_update_other_config_setkey(
                                                new_ls, "ic-vxlan_mode",
                                                vxlan_mode ? "true" : "false");
                int64_t nb_tnl_key = smap_get_int(&ls->other_config,
                                              "requested-tnl-key", 0);
                char *tnl_key_str =
                    xasprintf("%"PRId64, nb_tnl_key);
                nbrec_logical_switch_update_other_config_setkey(
                    new_ls, "requested-tnl-key", tnl_key_str);
                free(tnl_key_str);
                return EN_HANDLED_UPDATED;
            }
            shash_add(&tr_data->deleted_ls, ls->name, ls);
        } else {
            shash_add(&tr_data->crupdated_ls, ls->name, ls);
        }
    }

    if (changed) {
        dp_data->tracked = true;
        return EN_HANDLED_UPDATED;
    }

    return EN_HANDLED_UNCHANGED;
}

static void
enum_datapath_run(const struct icsbrec_datapath_binding_table *dp_table,
                  struct ed_type_enum_datapaths *dp_data)
{
    const struct icsbrec_datapath_binding *isb_dp;
    ICSBREC_DATAPATH_BINDING_TABLE_FOR_EACH (isb_dp, dp_table) {
        /* 1. Adds Tunnel ID */
        ovn_add_tnlid(&dp_data->dp_tnlids, isb_dp->tunnel_key);

        /* 2. Classifies the Datapath */
        enum ic_datapath_type dp_type = ic_dp_get_type(isb_dp);
        if (dp_type == IC_ROUTER) {
            char *uuid_str = uuid_to_string(isb_dp->nb_ic_uuid);
            shash_add(&dp_data->isb_tr_dps, uuid_str, (void *)isb_dp);
            free(uuid_str);
        } else {
            shash_add(&dp_data->isb_ts_dps, isb_dp->transit_switch,
                      (void *)isb_dp);
        }
    }
}

static enum ic_datapath_type
ic_dp_get_type(const struct icsbrec_datapath_binding *isb_dp)
{
    if (isb_dp->type && !strcmp(isb_dp->type, "transit-router")) {
        return IC_ROUTER;
    }

    return IC_SWITCH;
}

static void
enum_datapath_init_tracked_data(struct enum_datapaths_tracked *tracked_data)
{
    shash_init(&tracked_data->crupdated_datapaths);
    shash_init(&tracked_data->deleted_datapaths);

    shash_init(&tracked_data->crupdated_ls);
    shash_init(&tracked_data->deleted_ls);
}

static void
enum_datapaths_init(struct ed_type_enum_datapaths *data)
{
    hmap_init(&data->dp_tnlids);
    shash_init(&data->isb_ts_dps);
    shash_init(&data->isb_tr_dps);
    enum_datapath_init_tracked_data(&data->tracked_data);
    data->tracked = false;
}

static void
enum_datapaths_destroy(struct ed_type_enum_datapaths *data)
{
    enum_datapaths_clear(data);
    ovn_destroy_tnlids(&data->dp_tnlids);

    shash_destroy(&data->isb_ts_dps);
    shash_destroy(&data->isb_tr_dps);

    struct enum_datapaths_tracked *tr_data = &data->tracked_data;
    shash_destroy(&tr_data->crupdated_datapaths);
    shash_destroy(&tr_data->deleted_datapaths);
    shash_destroy(&tr_data->crupdated_ls);
    shash_destroy(&tr_data->deleted_ls);
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
enum_datapaths_clear_tracked(struct ed_type_enum_datapaths *data)
{
    clear_shash(&data->tracked_data.crupdated_datapaths);
    clear_shash(&data->tracked_data.deleted_datapaths);

    clear_shash(&data->tracked_data.crupdated_ls);
    clear_shash(&data->tracked_data.deleted_ls);

    data->tracked = false;
}

static void
enum_datapaths_clear(struct ed_type_enum_datapaths *data)
{
    ovn_destroy_tnlids(&data->dp_tnlids);
    hmap_init(&data->dp_tnlids);

    shash_clear(&data->isb_ts_dps);
    shash_clear(&data->isb_tr_dps);

    enum_datapaths_clear_tracked(data);
}
