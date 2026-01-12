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
#include "en-tr.h"
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

VLOG_DEFINE_THIS_MODULE(en_transit_router);
COVERAGE_DEFINE(tr_run);

static void
tr_run(const struct engine_context *eng_ctx,
       struct ed_type_transit_router *tr_data,
       struct ed_type_enum_datapaths *dp_node_data,
       const struct nbrec_logical_router_table *nbrec_lr_table,
       const struct icnbrec_transit_router_table *icnbrec_tr_table);
static void tr_init(struct ed_type_transit_router *data);
static void tr_destroy(struct ed_type_transit_router *data);

enum engine_node_state
en_tr_run(struct engine_node *node, void *data)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ed_type_transit_router *tr_data = data;

    struct ed_type_enum_datapaths *dp_node_data =
        engine_get_input_data("enum_datapaths", node);

    const struct nbrec_logical_router_table *nbrec_lr_table =
        EN_OVSDB_GET(engine_get_input("NB_logical_router", node));
    const struct icnbrec_transit_router_table *icnbrec_tr_table =
        EN_OVSDB_GET(engine_get_input("ICNB_transit_router", node));

    COVERAGE_INC(tr_run);
    stopwatch_start(OVN_IC_TRANSIT_ROUTER_RUN_STOPWATCH_NAME, time_usec());
    tr_run(eng_ctx, tr_data, dp_node_data, nbrec_lr_table, icnbrec_tr_table);
    stopwatch_stop(OVN_IC_TRANSIT_ROUTER_RUN_STOPWATCH_NAME, time_usec());

    return EN_UPDATED;
}

void *
en_tr_init(struct engine_node *node OVS_UNUSED,
           struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_transit_router *data = xzalloc(sizeof *data);
    tr_init(data);
    return data;
}

void
en_tr_cleanup(void *data)
{
    tr_destroy(data);
}

static void
tr_init(struct ed_type_transit_router *data)
{
    shash_init(&data->isb_tr_dps);
    hmap_init(&data->dp_tnlids);
}

static void
tr_destroy(struct ed_type_transit_router *data)
{
    shash_destroy(&data->isb_tr_dps);
    ovn_destroy_tnlids(&data->dp_tnlids);
}

static void
tr_run(const struct engine_context *eng_ctx,
       struct ed_type_transit_router *tr_data OVS_UNUSED,
       struct ed_type_enum_datapaths *dp_node_data,
       const struct nbrec_logical_router_table *nbrec_lr_table,
       const struct icnbrec_transit_router_table *icnbrec_tr_table)
{
    const struct nbrec_logical_router *lr;
    if (eng_ctx->ovnnb_idl_txn) {
        struct shash nb_tres = SHASH_INITIALIZER(&nb_tres);
        NBREC_LOGICAL_ROUTER_TABLE_FOR_EACH (lr, nbrec_lr_table) {
            const char *tr_name = smap_get(&lr->options, "interconn-tr");
            if (tr_name) {
                shash_add(&nb_tres, tr_name, lr);
            }
        }

        const struct icnbrec_transit_router *tr;
        ICNBREC_TRANSIT_ROUTER_TABLE_FOR_EACH (tr, icnbrec_tr_table) {
            lr = shash_find_and_delete(&nb_tres, tr->name);
            if (!lr) {
                lr = nbrec_logical_router_insert(eng_ctx->ovnnb_idl_txn);
                nbrec_logical_router_set_name(lr, tr->name);
                nbrec_logical_router_update_options_setkey(
                    lr, "interconn-tr", tr->name);
            }
            char *uuid_str = uuid_to_string(&tr->header_.uuid);
            struct icsbrec_datapath_binding *isb_dp = shash_find_data(
                &dp_node_data->isb_tr_dps, uuid_str);
            free(uuid_str);

            if (isb_dp) {
                char *tnl_key_str = xasprintf("%"PRId64, isb_dp->tunnel_key);
                nbrec_logical_router_update_options_setkey(
                    lr, "requested-tnl-key", tnl_key_str);
                free(tnl_key_str);
            }
        }

        struct shash_node *node;
        SHASH_FOR_EACH (node, &nb_tres) {
            nbrec_logical_router_delete(node->data);
        }
        shash_destroy(&nb_tres);
    }

    /* Sync TR between INB and ISB.  This is performed after syncing with AZ
     * SB, to avoid uncommitted ISB datapath tunnel key to be synced back to
     * AZ. */
    if (eng_ctx->ovnisb_idl_txn) {
        /* Create ISB Datapath_Binding */
        const struct icnbrec_transit_router *tr;
        ICNBREC_TRANSIT_ROUTER_TABLE_FOR_EACH (tr, icnbrec_tr_table) {
            char *uuid_str = uuid_to_string(&tr->header_.uuid);
            struct icsbrec_datapath_binding *isb_dp =
                shash_find_and_delete(&dp_node_data->isb_tr_dps, uuid_str);
            free(uuid_str);

            if (!isb_dp) {
                int dp_key = allocate_dp_key(&dp_node_data->dp_tnlids, false,
                                             "transit router datapath");
                if (!dp_key) {
                    continue;
                }

                isb_dp = icsbrec_datapath_binding_insert(
                    eng_ctx->ovnisb_idl_txn);
                icsbrec_datapath_binding_set_tunnel_key(isb_dp, dp_key);
                icsbrec_datapath_binding_set_nb_ic_uuid(isb_dp,
                                                        &tr->header_.uuid, 1);
                icsbrec_datapath_binding_set_type(isb_dp, "transit-router");
            }
        }

        struct shash_node *node;
        SHASH_FOR_EACH (node, &dp_node_data->isb_tr_dps) {
            icsbrec_datapath_binding_delete(node->data);
        }
    }
}
