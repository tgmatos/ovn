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
#include "en-port-binding.h"
#include "inc-proc-ic.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-ic-nb-idl.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-util.h"
#include "lib/stopwatch-names.h"
#include "coverage.h"
#include "stopwatch.h"
#include "stopwatch-names.h"

VLOG_DEFINE_THIS_MODULE(en_port_binding);
COVERAGE_DEFINE(port_binding_run);

static void
port_binding_run(const struct engine_context *eng_ctx,
                 struct pb_input *pb_input,
                 struct ed_type_port_binding *pb_data,
                 const struct icnbrec_transit_switch_table *icnb_ts_table,
                 const struct icnbrec_transit_router_table *icnb_tr_table);
static void port_binding_init(struct ed_type_port_binding *data);
static void port_binding_destroy(struct ed_type_port_binding *data);
static void port_binding_clear(struct ed_type_port_binding *data);
static void port_binding_get_input_data(struct engine_node *node,
                                        struct pb_input *input_data);
static const struct nbrec_logical_router *
    find_tr_in_nb(struct pb_input *pb, char *tr_name);
static const struct sbrec_port_binding *
    find_peer_port(struct pb_input *pb,
                   const struct sbrec_port_binding *sb_pb);
static const struct sbrec_port_binding *
    find_crp_from_lrp(struct pb_input *pb,
                      const struct sbrec_port_binding *lrp_pb);
static const struct sbrec_port_binding *
    find_crp_for_sb_pb(struct pb_input *pb,
                       const struct sbrec_port_binding *sb_pb);
static const char *
    get_lp_address_for_sb_pb(struct pb_input *pb,
                             const struct sbrec_port_binding *sb_pb);
static const struct sbrec_chassis *
    find_sb_chassis(struct pb_input *pb, const char *name);
static void sync_lsp_tnl_key(const struct nbrec_logical_switch_port *lsp,
                             int64_t isb_tnl_key);
static inline void
    sync_lrp_tnl_key(const struct nbrec_logical_router_port *lrp,
                     int64_t isb_tnl_key);
static bool
    get_router_uuid_by_sb_pb(struct pb_input *pb,
                             const struct sbrec_port_binding *sb_pb,
                             struct uuid *router_uuid);
static void
    update_isb_pb_external_ids(struct pb_input *pb,
                               const struct sbrec_port_binding *sb_pb,
                               const struct icsbrec_port_binding *isb_pb);
static void
    sync_local_port(struct pb_input *pb,
                    const struct icsbrec_port_binding *isb_pb,
                    const struct sbrec_port_binding *sb_pb,
                    const struct nbrec_logical_switch_port *lsp);
static void
    sync_remote_port(struct pb_input *pb,
                     const struct icsbrec_port_binding *isb_pb,
                     const struct nbrec_logical_switch_port *lsp,
                     const struct sbrec_port_binding *sb_pb);
static void
    sync_router_port(const struct icsbrec_port_binding *isb_pb,
                     const struct icnbrec_transit_router_port *trp,
                     const struct nbrec_logical_router_port *lrp);
static void
    create_nb_lsp(const struct engine_context *ctx,
                  const struct icsbrec_port_binding *isb_pb,
                  const struct nbrec_logical_switch *ls);
static uint32_t allocate_port_key(struct hmap *pb_tnlids);
static const struct icsbrec_port_binding *
    create_isb_pb(const struct engine_context *ctx, const char *logical_port,
                  const struct icsbrec_availability_zone *az,
                  const char *ts_name, const struct uuid *nb_ic_uuid,
                  const char *type, struct hmap *pb_tnlids);
static bool trp_is_remote(struct pb_input *pb, const char *chassis_name);
static struct nbrec_logical_router_port *
    lrp_create(const struct engine_context *ctx,
               const struct nbrec_logical_router *lr,
               const struct icnbrec_transit_router_port *trp);
static void
    sync_ts_isb_pb(struct pb_input *pb, const struct sbrec_port_binding *sb_pb,
                   const struct icsbrec_port_binding *isb_pb);
static const struct sbrec_port_binding *
    find_lsp_in_sb(struct pb_input *pb,
                   const struct nbrec_logical_switch_port *lsp);

static void
port_binding_get_input_data(struct engine_node *node,
                            struct pb_input *input_data)
{
    /* Indexes */
    input_data->icsbrec_port_binding_by_az =
        engine_ovsdb_node_get_index(
            engine_get_input("ICSB_port_binding", node),
            "icsbrec_port_binding_by_az");
    input_data->icsbrec_port_binding_by_ts =
        engine_ovsdb_node_get_index(
            engine_get_input("ICSB_port_binding", node),
            "icsbrec_port_binding_by_ts");
    input_data->nbrec_ls_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("NB_logical_switch", node),
            "nbrec_ls_by_name");
    input_data->sbrec_port_binding_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_port_binding", node),
            "sbrec_port_binding_by_name");
    input_data->nbrec_port_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("NB_logical_switch", node),
            "nbrec_port_by_name");
    input_data->nbrec_lr_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("NB_logical_router", node),
            "nbrec_lr_by_name");
    input_data->sbrec_chassis_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_chassis", node),
            "sbrec_chassis_by_name");
}

enum engine_node_state
en_port_binding_run(struct engine_node *node, void *data)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ed_type_port_binding *pb_data = data;
    struct pb_input pb_input;

    port_binding_clear(pb_data);

    const struct icnbrec_transit_switch_table *icnb_ts_table =
        EN_OVSDB_GET(engine_get_input("ICNB_transit_switch", node));
    const struct icnbrec_transit_router_table *icnb_tr_table =
        EN_OVSDB_GET(engine_get_input("ICNB_transit_router", node));

    port_binding_get_input_data(node, &pb_input);
    pb_input.runned_az = eng_ctx->client_ctx;

    COVERAGE_INC(port_binding_run);
    stopwatch_start(OVN_IC_PORT_BINDING_RUN_STOPWATCH_NAME, time_usec());
    port_binding_run(eng_ctx, &pb_input, pb_data, icnb_ts_table,
                     icnb_tr_table);
    stopwatch_stop(OVN_IC_PORT_BINDING_RUN_STOPWATCH_NAME, time_usec());

    return EN_UPDATED;
}

void *
en_port_binding_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_port_binding *data = xzalloc(sizeof *data);
    port_binding_init(data);
    return data;
}

void
en_port_binding_cleanup(void *data)
{
    port_binding_destroy(data);
}

static void
port_binding_init(struct ed_type_port_binding *data)
{
    hmap_init(&data->pb_tnlids);
    shash_init(&data->switch_all_local_pbs);
    shash_init(&data->router_all_local_pbs);
}

static void
port_binding_destroy(struct ed_type_port_binding *data)
{
    port_binding_clear(data);
    ovn_destroy_tnlids(&data->pb_tnlids);

    shash_destroy(&data->switch_all_local_pbs);
    shash_destroy(&data->router_all_local_pbs);
}

static void
port_binding_clear(struct ed_type_port_binding *data)
{
    ovn_destroy_tnlids(&data->pb_tnlids);
    hmap_init(&data->pb_tnlids);

    shash_clear(&data->switch_all_local_pbs);
    shash_clear(&data->router_all_local_pbs);
}

static void
port_binding_run(const struct engine_context *eng_ctx,
                 struct pb_input *pb_input,
                 struct ed_type_port_binding *pb_data,
                 const struct icnbrec_transit_switch_table *icnb_ts_table,
                 const struct icnbrec_transit_router_table *icnb_tr_table)
{
    if (!eng_ctx->ovnisb_idl_txn || !eng_ctx->ovnnb_idl_txn
        || !eng_ctx->ovnsb_idl_txn) {
        return;
    }

    struct shash_node *node;
    const struct icsbrec_port_binding *isb_pb;
    const struct icsbrec_port_binding *isb_pb_key =
        icsbrec_port_binding_index_init_row(
            pb_input->icsbrec_port_binding_by_az);
    icsbrec_port_binding_index_set_availability_zone(isb_pb_key,
                                                     pb_input->runned_az);

    ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (isb_pb, isb_pb_key,
        pb_input->icsbrec_port_binding_by_az) {
        ic_pb_get_type(isb_pb) != IC_ROUTER_PORT
            ? shash_add(&pb_data->switch_all_local_pbs, isb_pb->logical_port,
                        isb_pb)
            : shash_add(&pb_data->router_all_local_pbs, isb_pb->logical_port,
                        isb_pb);

        ovn_add_tnlid(&pb_data->pb_tnlids, isb_pb->tunnel_key);
    }
    icsbrec_port_binding_index_destroy_row(isb_pb_key);

    const struct sbrec_port_binding *sb_pb;
    const struct icnbrec_transit_switch *ts;
    ICNBREC_TRANSIT_SWITCH_TABLE_FOR_EACH (ts, icnb_ts_table) {
        const struct nbrec_logical_switch *ls =
            find_ts_in_nb(pb_input->nbrec_ls_by_name,
                          ts->name);
        if (!ls) {
            VLOG_DBG("Transit switch %s not found in NB.", ts->name);
            continue;
        }
        struct shash local_pbs = SHASH_INITIALIZER(&local_pbs);
        struct shash remote_pbs = SHASH_INITIALIZER(&remote_pbs);

        isb_pb_key = icsbrec_port_binding_index_init_row(
            pb_input->icsbrec_port_binding_by_ts);
        icsbrec_port_binding_index_set_transit_switch(isb_pb_key, ts->name);

        ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (isb_pb, isb_pb_key,
            pb_input->icsbrec_port_binding_by_ts) {
            if (isb_pb->availability_zone == pb_input->runned_az) {
                shash_add(&local_pbs, isb_pb->logical_port, isb_pb);
                shash_find_and_delete(&pb_data->switch_all_local_pbs,
                                      isb_pb->logical_port);
            } else {
                shash_add(&remote_pbs, isb_pb->logical_port, isb_pb);
            }
        }
        icsbrec_port_binding_index_destroy_row(isb_pb_key);

        const struct nbrec_logical_switch_port *lsp;
        for (int i = 0; i < ls->n_ports; i++) {
            lsp = ls->ports[i];

            if (!strcmp(lsp->type, "router")
                || !strcmp(lsp->type, "switch")) {
                /* The port is local. */
                sb_pb = find_lsp_in_sb(pb_input, lsp);
                if (!sb_pb) {
                    continue;
                }
                isb_pb = shash_find_and_delete(&local_pbs, lsp->name);
                if (!isb_pb) {
                    isb_pb = create_isb_pb(
                        eng_ctx, sb_pb->logical_port, pb_input->runned_az,
                        ts->name, &ts->header_.uuid, "transit-switch-port",
                        &pb_data->pb_tnlids);
                    sync_ts_isb_pb(pb_input, sb_pb, isb_pb);
                } else {
                    sync_local_port(pb_input, isb_pb, sb_pb, lsp);
                }

                if (isb_pb->type) {
                    icsbrec_port_binding_set_type(isb_pb,
                                                  "transit-switch-port");
                }

                if (isb_pb->nb_ic_uuid) {
                    icsbrec_port_binding_set_nb_ic_uuid(isb_pb,
                                                        &ts->header_.uuid, 1);
                }
            } else if (!strcmp(lsp->type, "remote")) {
                /* The port is remote. */
                isb_pb = shash_find_and_delete(&remote_pbs, lsp->name);
                if (!isb_pb) {
                    nbrec_logical_switch_update_ports_delvalue(ls, lsp);
                } else {
                    sb_pb = find_lsp_in_sb(pb_input, lsp);
                    if (!sb_pb) {
                        continue;
                    }
                    sync_remote_port(pb_input, isb_pb, lsp, sb_pb);
                }
            } else {
                VLOG_DBG("Ignore lsp %s on ts %s with type %s.",
                         lsp->name, ts->name, lsp->type);
            }
        }

        /* Delete extra port-binding from ISB */
        SHASH_FOR_EACH (node, &local_pbs) {
            icsbrec_port_binding_delete(node->data);
        }

        /* Create lsp in NB for remote ports */
        SHASH_FOR_EACH (node, &remote_pbs) {
            create_nb_lsp(eng_ctx, node->data, ls);
        }

        shash_destroy(&local_pbs);
        shash_destroy(&remote_pbs);
    }

    SHASH_FOR_EACH (node, &pb_data->switch_all_local_pbs) {
        icsbrec_port_binding_delete(node->data);
    }

    const struct icnbrec_transit_router *tr;
    ICNBREC_TRANSIT_ROUTER_TABLE_FOR_EACH (tr, icnb_tr_table) {
        const struct nbrec_logical_router *lr = find_tr_in_nb(pb_input,
                                                              tr->name);
        if (!lr) {
            VLOG_DBG("Transit router %s not found in NB.", tr->name);
            continue;
        }

        struct shash nb_ports = SHASH_INITIALIZER(&nb_ports);
        struct shash local_pbs = SHASH_INITIALIZER(&local_pbs);
        struct shash remote_pbs = SHASH_INITIALIZER(&remote_pbs);

        for (size_t i = 0; i < lr->n_ports; i++) {
            const struct nbrec_logical_router_port *lrp = lr->ports[i];
            if (smap_get_def(&lrp->options, "interconn-tr", NULL)) {
                shash_add(&nb_ports, lrp->name, lrp);
            }
        }

        isb_pb_key = icsbrec_port_binding_index_init_row(
            pb_input->icsbrec_port_binding_by_ts);
        icsbrec_port_binding_index_set_transit_switch(isb_pb_key, tr->name);

        ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (isb_pb, isb_pb_key,
            pb_input->icsbrec_port_binding_by_ts) {
            if (isb_pb->availability_zone == pb_input->runned_az) {
                shash_add(&local_pbs, isb_pb->logical_port, isb_pb);
                shash_find_and_delete(&pb_data->router_all_local_pbs,
                                      isb_pb->logical_port);
            } else {
                shash_add(&remote_pbs, isb_pb->logical_port, isb_pb);
            }
        }
        icsbrec_port_binding_index_destroy_row(isb_pb_key);

        for (size_t i = 0; i < tr->n_ports; i++) {
            const struct icnbrec_transit_router_port *trp = tr->ports[i];

            if (trp_is_remote(pb_input, trp->chassis)) {
                isb_pb = shash_find_and_delete(&remote_pbs, trp->name);
            } else {
                isb_pb = shash_find_and_delete(&local_pbs, trp->name);
                if (!isb_pb) {
                    isb_pb = create_isb_pb(eng_ctx, trp->name,
                                           pb_input->runned_az, tr->name,
                                           &tr->header_.uuid,
                                           "transit-router-port",
                                           &pb_data->pb_tnlids);
                    icsbrec_port_binding_set_address(isb_pb, trp->mac);
                }
            }

            /* Don't allow remote ports to create NB LRP until ICSB entry is
             * created in the appropriate AZ. */
            if (isb_pb) {
                const struct nbrec_logical_router_port *lrp =
                    shash_find_and_delete(&nb_ports, trp->name);
                if (!lrp) {
                    lrp = lrp_create(eng_ctx, lr, trp);
                }

                sync_router_port(isb_pb, trp, lrp);
            }
        }

        SHASH_FOR_EACH (node, &nb_ports) {
            nbrec_logical_router_port_delete(node->data);
            nbrec_logical_router_update_ports_delvalue(lr, node->data);
        }

        shash_destroy(&nb_ports);
        shash_destroy(&local_pbs);
        shash_destroy(&remote_pbs);
    }

    SHASH_FOR_EACH (node, &pb_data->router_all_local_pbs) {
        icsbrec_port_binding_delete(node->data);
    }
}

static const struct nbrec_logical_router *
find_tr_in_nb(struct pb_input *pb, char *tr_name)
{
    const struct nbrec_logical_router *key =
        nbrec_logical_router_index_init_row(pb->nbrec_lr_by_name);
    nbrec_logical_router_index_set_name(key, tr_name);

    const struct nbrec_logical_router *lr;
    bool found = false;
    NBREC_LOGICAL_ROUTER_FOR_EACH_EQUAL (lr, key, pb->nbrec_lr_by_name) {
        if (smap_get(&lr->options, "interconn-tr")) {
            found = true;
            break;
        }
    }

    nbrec_logical_router_index_destroy_row(key);
    if (found) {
        return lr;
    }

    return NULL;
}

static const struct sbrec_port_binding *
find_peer_port(struct pb_input *pb,
               const struct sbrec_port_binding *sb_pb)
{
    const char *peer_name = smap_get(&sb_pb->options, "peer");
    if (!peer_name) {
        return NULL;
    }

    return find_sb_pb_by_name(pb->sbrec_port_binding_by_name, peer_name);
}

static const struct sbrec_port_binding *
find_crp_from_lrp(struct pb_input *pb,
                  const struct sbrec_port_binding *lrp_pb)
{
    char *crp_name = ovn_chassis_redirect_name(lrp_pb->logical_port);

    const struct sbrec_port_binding *sb_pb =
        find_sb_pb_by_name(pb->sbrec_port_binding_by_name, crp_name);

    free(crp_name);
    return sb_pb;
}

static const struct sbrec_port_binding *
find_crp_for_sb_pb(struct pb_input *pb,
                   const struct sbrec_port_binding *sb_pb)
{
    const struct sbrec_port_binding *peer = find_peer_port(pb, sb_pb);
    if (!peer) {
        return NULL;
    }

    return find_crp_from_lrp(pb, peer);
}

static const char *
get_lp_address_for_sb_pb(struct pb_input *pb,
                         const struct sbrec_port_binding *sb_pb)
{
    const struct nbrec_logical_switch_port *nb_lsp;

    nb_lsp = get_lsp_by_ts_port_name(pb->nbrec_port_by_name,
                                     sb_pb->logical_port);
    if (!strcmp(nb_lsp->type, "switch")) {
        /* Switches always have implicit "unknown" address, and IC-SB port
         * binding can only have one address specified. */
        return "unknown";
    }

    const struct sbrec_port_binding *peer = find_peer_port(pb, sb_pb);
    if (!peer) {
        return NULL;
    }

    return peer->n_mac ? *peer->mac : NULL;
}

static const struct sbrec_chassis *
find_sb_chassis(struct pb_input *pb, const char *name)
{
    const struct sbrec_chassis *key =
        sbrec_chassis_index_init_row(pb->sbrec_chassis_by_name);
    sbrec_chassis_index_set_name(key, name);

    const struct sbrec_chassis *chassis =
        sbrec_chassis_index_find(pb->sbrec_chassis_by_name, key);
    sbrec_chassis_index_destroy_row(key);

    return chassis;
}

static void
sync_lsp_tnl_key(const struct nbrec_logical_switch_port *lsp,
                 int64_t isb_tnl_key)
{
    int64_t tnl_key = smap_get_int(&lsp->options, "requested-tnl-key", 0);
    if (tnl_key != isb_tnl_key) {
        VLOG_DBG("Set options:requested-tnl-key %"PRId64
                 " for lsp %s in NB.", isb_tnl_key, lsp->name);
        char *tnl_key_str = xasprintf("%"PRId64, isb_tnl_key);
        nbrec_logical_switch_port_update_options_setkey(lsp,
                                                        "requested-tnl-key",
                                                        tnl_key_str);
        free(tnl_key_str);
    }
}

static inline void
sync_lrp_tnl_key(const struct nbrec_logical_router_port *lrp,
                 int64_t isb_tnl_key)
{
    int64_t tnl_key = smap_get_int(&lrp->options, "requested-tnl-key", 0);
    if (tnl_key != isb_tnl_key) {
        VLOG_DBG("Set options:requested-tnl-key %" PRId64 " for lrp %s in NB.",
                 isb_tnl_key, lrp->name);
        char *tnl_key_str = xasprintf("%"PRId64, isb_tnl_key);
        nbrec_logical_router_port_update_options_setkey(
            lrp, "requested-tnl-key", tnl_key_str);
        free(tnl_key_str);
    }
}

static bool
get_router_uuid_by_sb_pb(struct pb_input *pb,
                         const struct sbrec_port_binding *sb_pb,
                         struct uuid *router_uuid)
{
    const struct sbrec_port_binding *router_pb = find_peer_port(pb, sb_pb);
    if (!router_pb || !router_pb->datapath) {
        return NULL;
    }

    return datapath_get_nb_uuid(router_pb->datapath, router_uuid);
}

static void
update_isb_pb_external_ids(struct pb_input *pb,
                           const struct sbrec_port_binding *sb_pb,
                           const struct icsbrec_port_binding *isb_pb)
{
    struct uuid lr_uuid;
    if (!get_router_uuid_by_sb_pb(pb, sb_pb, &lr_uuid)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Can't get router uuid for transit switch port %s.",
                     isb_pb->logical_port);
        return;
    }

    struct uuid current_lr_uuid;
    if (smap_get_uuid(&isb_pb->external_ids, "router-id", &current_lr_uuid) &&
        uuid_equals(&lr_uuid, &current_lr_uuid)) {
        return;
    }

    char *uuid_s = xasprintf(UUID_FMT, UUID_ARGS(&lr_uuid));
    icsbrec_port_binding_update_external_ids_setkey(isb_pb, "router-id",
                                                    uuid_s);
    free(uuid_s);
}

/* For each local port:
 *   - Sync from NB to ISB.
 *   - Sync gateway from SB to ISB.
 *   - Sync tunnel key from ISB to NB.
 */
static void
sync_local_port(struct pb_input *pb,
                const struct icsbrec_port_binding *isb_pb,
                const struct sbrec_port_binding *sb_pb,
                const struct nbrec_logical_switch_port *lsp)
{
    /* Sync address from NB to ISB */
    const char *address = get_lp_address_for_sb_pb(pb, sb_pb);
    if (!address) {
        VLOG_DBG("Can't get router/switch port address for logical"
                 " switch port %s", sb_pb->logical_port);
        if (isb_pb->address[0]) {
            icsbrec_port_binding_set_address(isb_pb, "");
        }
    } else {
        if (strcmp(address, isb_pb->address)) {
            icsbrec_port_binding_set_address(isb_pb, address);
        }
    }

    /* Sync gateway from SB to ISB */
    const struct sbrec_port_binding *crp = find_crp_for_sb_pb(pb, sb_pb);
    if (crp && crp->chassis) {
        if (strcmp(crp->chassis->name, isb_pb->gateway)) {
            icsbrec_port_binding_set_gateway(isb_pb, crp->chassis->name);
        }
    } else if (!strcmp(lsp->type, "switch") && sb_pb->chassis) {
        if (strcmp(sb_pb->chassis->name, isb_pb->gateway)) {
            icsbrec_port_binding_set_gateway(isb_pb, sb_pb->chassis->name);
        }
    } else {
        if (isb_pb->gateway[0]) {
            icsbrec_port_binding_set_gateway(isb_pb, "");
        }
    }

    /* Sync external_ids:router-id to ISB */
    update_isb_pb_external_ids(pb, sb_pb, isb_pb);

    /* Sync back tunnel key from ISB to NB */
    sync_lsp_tnl_key(lsp, isb_pb->tunnel_key);
}

/* For each remote port:
 *   - Sync from ISB to NB
 *   - Sync gateway from ISB to SB
 */
static void
sync_remote_port(struct pb_input *pb,
                 const struct icsbrec_port_binding *isb_pb,
                 const struct nbrec_logical_switch_port *lsp,
                 const struct sbrec_port_binding *sb_pb)
{
    /* Sync address from ISB to NB */
    if (isb_pb->address[0]) {
        if (lsp->n_addresses != 1 ||
            strcmp(isb_pb->address, lsp->addresses[0])) {
            nbrec_logical_switch_port_set_addresses(
                lsp, (const char **)&isb_pb->address, 1);
        }
    } else {
        if (lsp->n_addresses != 0) {
            nbrec_logical_switch_port_set_addresses(lsp, NULL, 0);
        }
    }

    /* Sync tunnel key from ISB to NB */
    sync_lsp_tnl_key(lsp, isb_pb->tunnel_key);

    /* Skip port binding if it is already requested by the CMS. */
    if (smap_get(&lsp->options, "requested-chassis")) {
        return;
    }

    /* Sync gateway from ISB to SB */
    if (isb_pb->gateway[0]) {
        if (!sb_pb->chassis || strcmp(sb_pb->chassis->name, isb_pb->gateway)) {
            const struct sbrec_chassis *chassis =
                find_sb_chassis(pb, isb_pb->gateway);
            if (!chassis) {
                VLOG_DBG("Chassis %s is not found in SB, syncing from ISB "
                         "to SB skipped for logical port %s.",
                         isb_pb->gateway, lsp->name);
                return;
            }
            sbrec_port_binding_set_chassis(sb_pb, chassis);
        }
    } else {
        if (sb_pb->chassis) {
            sbrec_port_binding_set_chassis(sb_pb, NULL);
        }
    }
}

/* For each remote port:
 *   - Sync from ISB to NB
 */
static void
sync_router_port(const struct icsbrec_port_binding *isb_pb,
                 const struct icnbrec_transit_router_port *trp,
                 const struct nbrec_logical_router_port *lrp)
{
    /* Sync from ICNB to NB */
    if (trp->chassis[0]) {
        const char *chassis_name =
            smap_get_def(&lrp->options, "requested-chassis", "");
        if (strcmp(trp->chassis, chassis_name)) {
            nbrec_logical_router_port_update_options_setkey(
                lrp, "requested-chassis", trp->chassis);
        }
    } else {
        nbrec_logical_router_port_update_options_delkey(
            lrp, "requested-chassis");
    }

    if (strcmp(trp->mac, lrp->mac)) {
        nbrec_logical_router_port_set_mac(lrp, trp->mac);
    }

    bool sync_networks = false;
    if (trp->n_networks != lrp->n_networks) {
        sync_networks = true;
    } else {
        for (size_t i = 0; i < trp->n_networks; i++) {
            if (strcmp(trp->networks[i], lrp->networks[i])) {
                sync_networks |= true;
                break;
            }
        }
    }

    if (sync_networks) {
        nbrec_logical_router_port_set_networks(
            lrp, (const char **) trp->networks, trp->n_networks);
    }

    /* Sync tunnel key from ISB to NB */
    sync_lrp_tnl_key(lrp, isb_pb->tunnel_key);
}

static void
create_nb_lsp(const struct engine_context *ctx,
              const struct icsbrec_port_binding *isb_pb,
              const struct nbrec_logical_switch *ls)
{
    const struct nbrec_logical_switch_port *lsp =
        nbrec_logical_switch_port_insert(ctx->ovnnb_idl_txn);
    nbrec_logical_switch_port_set_name(lsp, isb_pb->logical_port);
    nbrec_logical_switch_port_set_type(lsp, "remote");

    bool up = true;
    nbrec_logical_switch_port_set_up(lsp, &up, 1);

    if (isb_pb->address[0]) {
        nbrec_logical_switch_port_set_addresses(
            lsp, (const char **)&isb_pb->address, 1);
    }
    sync_lsp_tnl_key(lsp, isb_pb->tunnel_key);
    nbrec_logical_switch_update_ports_addvalue(ls, lsp);
}

static uint32_t
allocate_port_key(struct hmap *pb_tnlids)
{
    static uint32_t hint;
    return ovn_allocate_tnlid(pb_tnlids, "transit port",
                              1, (1u << 15) - 1, &hint);
}

static const struct icsbrec_port_binding *
create_isb_pb(const struct engine_context *ctx, const char *logical_port,
              const struct icsbrec_availability_zone *az, const char *ts_name,
              const struct uuid *nb_ic_uuid, const char *type,
              struct hmap *pb_tnlids)
{
    uint32_t pb_tnl_key = allocate_port_key(pb_tnlids);
    if (!pb_tnl_key) {
        return NULL;
    }

    const struct icsbrec_port_binding *isb_pb =
        icsbrec_port_binding_insert(ctx->ovnisb_idl_txn);
    icsbrec_port_binding_set_availability_zone(isb_pb, az);
    icsbrec_port_binding_set_transit_switch(isb_pb, ts_name);
    icsbrec_port_binding_set_logical_port(isb_pb, logical_port);
    icsbrec_port_binding_set_tunnel_key(isb_pb, pb_tnl_key);
    icsbrec_port_binding_set_nb_ic_uuid(isb_pb, nb_ic_uuid, 1);
    icsbrec_port_binding_set_type(isb_pb, type);
    return isb_pb;
}

static bool
trp_is_remote(struct pb_input *pb, const char *chassis_name)
{
    if (chassis_name) {
        const struct sbrec_chassis *chassis =
            find_sb_chassis(pb, chassis_name);
        if (chassis) {
            return smap_get_bool(&chassis->other_config, "is-remote", false);
        } else {
            return true;
        }
    }

    return false;
}

static struct nbrec_logical_router_port *
lrp_create(const struct engine_context *ctx,
           const struct nbrec_logical_router *lr,
           const struct icnbrec_transit_router_port *trp)
{
    struct nbrec_logical_router_port *lrp =
        nbrec_logical_router_port_insert(ctx->ovnnb_idl_txn);
    nbrec_logical_router_port_set_name(lrp, trp->name);

    nbrec_logical_router_port_update_options_setkey(lrp, "interconn-tr",
                                                    trp->name);
    nbrec_logical_router_update_ports_addvalue(lr, lrp);
    return lrp;
}

static void
sync_ts_isb_pb(struct pb_input *pb, const struct sbrec_port_binding *sb_pb,
               const struct icsbrec_port_binding *isb_pb)
{
    const char *address = get_lp_address_for_sb_pb(pb, sb_pb);
    if (address) {
        icsbrec_port_binding_set_address(isb_pb, address);
    }

    const struct sbrec_port_binding *crp = find_crp_for_sb_pb(pb, sb_pb);
    if (crp && crp->chassis) {
        icsbrec_port_binding_set_gateway(isb_pb, crp->chassis->name);
    }

    update_isb_pb_external_ids(pb, sb_pb, isb_pb);

    /* Sync encap so that multiple encaps can be used for the same
     * gateway.  However, it is not needed for now, since we don't yet
     * support specifying encap type/ip for gateway chassis or ha-chassis
     * for logical router port in NB DB, and now encap should always be
     * empty.  The sync can be added if we add such support for gateway
     * chassis/ha-chassis in NB DB. */
}

static const struct sbrec_port_binding *
find_lsp_in_sb(struct pb_input *pb,
               const struct nbrec_logical_switch_port *lsp)
{
    return find_sb_pb_by_name(pb->sbrec_port_binding_by_name, lsp->name);
}
