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

#include "lib/inc-proc-eng.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-ic-nb-idl.h"
#include "lib/ovn-ic-sb-idl.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "inc-proc-ic.h"
#include "en-ic.h"
#include "en-gateway.h"
#include "en-enum-datapaths.h"
#include "en-ts.h"
#include "en-tr.h"
#include "en-port-binding.h"
#include "en-route.h"
#include "en-srv-mon.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(inc_proc_ic);

#define NB_NODES \
    NB_NODE(nb_global, "nb_global") \
    NB_NODE(logical_router_static_route, "logical_router_static_route") \
    NB_NODE(logical_router, "logical_router") \
    NB_NODE(logical_switch, "logical_switch") \
    NB_NODE(load_balancer, "load_balancer") \
    NB_NODE(load_balancer_group, "load_balancer_group")

    enum nb_engine_node {
#define NB_NODE(NAME, NAME_STR) NB_##NAME,
    NB_NODES
#undef NB_NODE
    };

/* Define engine node functions for nodes that represent NB tables
 *
 * en_nb_<TABLE_NAME>_run()
 * en_nb_<TABLE_NAME>_init()
 * en_nb_<TABLE_NAME>_cleanup()
 */
#define NB_NODE(NAME, NAME_STR) ENGINE_FUNC_NB(NAME);
    NB_NODES
#undef NB_NODE

#define SB_NODES \
    SB_NODE(sb_global, "sb_global") \
    SB_NODE(chassis, "chassis") \
    SB_NODE(port_binding, "port_binding") \
    SB_NODE(service_monitor, "service_monitor")

    enum sb_engine_node {
#define SB_NODE(NAME, NAME_STR) SB_##NAME,
    SB_NODES
#undef SB_NODE
};

/* Define engine node functions for nodes that represent SB tables
 *
 * en_sb_<TABLE_NAME>_run()
 * en_sb_<TABLE_NAME>_init()
 * en_sb_<TABLE_NAME>_cleanup()
 */
#define SB_NODE(NAME, NAME_STR) ENGINE_FUNC_SB(NAME);
    SB_NODES
#undef SB_NODE

#define ICNB_NODES \
    ICNB_NODE(ic_nb_global, "ic_nb_global") \
    ICNB_NODE(transit_switch, "transit_switch") \
    ICNB_NODE(transit_router, "transit_router") \
    ICNB_NODE(transit_router_port, "transit_router_port")

    enum icnb_engine_node {
#define ICNB_NODE(NAME, NAME_STR) ICNB_##NAME,
    ICNB_NODES
#undef ICNB_NODE
    };

/* Define engine node functions for nodes that represent ICNB tables
 *
 * en_icnb_<TABLE_NAME>_run()
 * en_icnb_<TABLE_NAME>_init()
 * en_icnb_<TABLE_NAME>_cleanup()
 */
#define ICNB_NODE(NAME, NAME_STR) ENGINE_FUNC_ICNB(NAME);
    ICNB_NODES
#undef ICNB_NODE

#define ICSB_NODES \
    ICSB_NODE(service_monitor, "service_monitor") \
    ICSB_NODE(route, "route") \
    ICSB_NODE(datapath_binding, "datapath_binding") \
    ICSB_NODE(encap, "encap") \
    ICSB_NODE(gateway, "gateway") \
    ICSB_NODE(port_binding, "port_binding")

    enum icsb_engine_node {
#define ICSB_NODE(NAME, NAME_STR) ICSB_##NAME,
    ICSB_NODES
#undef ICSB_NODE
    };

/* Define engine node functions for nodes that represent ICSB tables
 *
 * en_icsb_<TABLE_NAME>_run()
 * en_icsb_<TABLE_NAME>_init()
 * en_icsb_<TABLE_NAME>_cleanup()
 */
#define ICSB_NODE(NAME, NAME_STR) ENGINE_FUNC_ICSB(NAME);
    ICSB_NODES
#undef ICSB_NODE

/* Define engine nodes for NB, SB, ICNB and ICSB tables
 *
 * struct engine_node en_nb_<TABLE_NAME>
 * struct engine_node en_sb_<TABLE_NAME>
 * struct engine_node en_icnb_<TABLE_NAME>
 * struct engine_node en_icsb_<TABLE_NAME>
 *
 * Define nodes as static to avoid sparse errors.
 */
#define NB_NODE(NAME, NAME_STR) static ENGINE_NODE_NB(NAME);
    NB_NODES
#undef NB_NODE

#define SB_NODE(NAME, NAME_STR) static ENGINE_NODE_SB(NAME);
    SB_NODES
#undef SB_NODE

#define ICNB_NODE(NAME, NAME_STR) static ENGINE_NODE_ICNB(NAME);
    ICNB_NODES
#undef ICNB_NODE

#define ICSB_NODE(NAME, NAME_STR) static ENGINE_NODE_ICSB(NAME);
    ICSB_NODES
#undef ICSB_NODE

/* Define engine nodes for other nodes. They should be defined as static to
 * avoid sparse errors. */
static ENGINE_NODE(ic, SB_WRITE);
static ENGINE_NODE(gateway, SB_WRITE);
static ENGINE_NODE(enum_datapaths);
static ENGINE_NODE(tr);
static ENGINE_NODE(ts, SB_WRITE);
static ENGINE_NODE(port_binding, SB_WRITE);
static ENGINE_NODE(route);
static ENGINE_NODE(srv_mon, SB_WRITE);

void inc_proc_ic_init(struct ovsdb_idl_loop *nb,
                      struct ovsdb_idl_loop *sb,
                      struct ovsdb_idl_loop *icnb,
                      struct ovsdb_idl_loop *icsb)
{
    /* Define relationships between nodes where first argument is dependent
     * on the second argument */
    engine_add_input(&en_gateway, &en_icsb_gateway, NULL);
    engine_add_input(&en_gateway, &en_sb_chassis, NULL);

    engine_add_input(&en_enum_datapaths, &en_icnb_transit_switch, NULL);
    engine_add_input(&en_enum_datapaths, &en_icsb_datapath_binding, NULL);

    engine_add_input(&en_ts, &en_enum_datapaths, NULL);
    engine_add_input(&en_ts, &en_icsb_datapath_binding, NULL);
    engine_add_input(&en_ts, &en_nb_logical_switch, NULL);
    engine_add_input(&en_ts, &en_icnb_ic_nb_global, NULL);
    engine_add_input(&en_ts, &en_icnb_transit_switch, NULL);
    engine_add_input(&en_ts, &en_icsb_encap, NULL);

    engine_add_input(&en_tr, &en_enum_datapaths, NULL);
    engine_add_input(&en_tr, &en_icsb_datapath_binding, NULL);
    engine_add_input(&en_tr, &en_nb_logical_router, NULL);
    engine_add_input(&en_tr, &en_icnb_transit_router, NULL);
    engine_add_input(&en_tr, &en_icnb_transit_router_port, NULL);

    engine_add_input(&en_port_binding, &en_icnb_transit_switch, NULL);
    engine_add_input(&en_port_binding, &en_icnb_transit_router, NULL);
    engine_add_input(&en_port_binding, &en_icsb_port_binding, NULL);
    engine_add_input(&en_port_binding, &en_nb_logical_switch, NULL);
    engine_add_input(&en_port_binding, &en_sb_port_binding, NULL);
    engine_add_input(&en_port_binding, &en_nb_logical_router, NULL);
    engine_add_input(&en_port_binding, &en_sb_chassis, NULL);

    engine_add_input(&en_route, &en_nb_nb_global, NULL);
    engine_add_input(&en_route, &en_nb_logical_switch, NULL);
    engine_add_input(&en_route, &en_nb_logical_router, NULL);
    engine_add_input(&en_route, &en_icnb_transit_switch, NULL);
    engine_add_input(&en_route, &en_icsb_port_binding, NULL);
    engine_add_input(&en_route, &en_icsb_route, NULL);
    engine_add_input(&en_route, &en_nb_logical_router_static_route, NULL);

    engine_add_input(&en_srv_mon, &en_icsb_service_monitor, NULL);
    engine_add_input(&en_srv_mon, &en_sb_sb_global, NULL);
    engine_add_input(&en_srv_mon, &en_sb_service_monitor, NULL);
    engine_add_input(&en_srv_mon, &en_nb_load_balancer, NULL);
    engine_add_input(&en_srv_mon, &en_nb_load_balancer_group, NULL);
    engine_add_input(&en_srv_mon, &en_sb_port_binding, NULL);

    engine_add_input(&en_ic, &en_gateway, NULL);
    engine_add_input(&en_ic, &en_enum_datapaths, NULL);
    engine_add_input(&en_ic, &en_ts, NULL);
    engine_add_input(&en_ic, &en_tr, NULL);
    engine_add_input(&en_ic, &en_port_binding, NULL);
    engine_add_input(&en_ic, &en_route, NULL);
    engine_add_input(&en_ic, &en_srv_mon, NULL);

    struct engine_arg engine_arg = {
        .nb_idl = nb->idl,
        .sb_idl = sb->idl,
        .icnb_idl = icnb->idl,
        .icsb_idl = icsb->idl,
    };

    /* create IDL indexes*/
    struct ovsdb_idl_index *nbrec_ls_by_name
        = ovsdb_idl_index_create1(nb->idl, &nbrec_logical_switch_col_name);
    struct ovsdb_idl_index *nbrec_lr_by_name
        = ovsdb_idl_index_create1(nb->idl, &nbrec_logical_router_col_name);
    struct ovsdb_idl_index *nbrec_lrp_by_name
        = ovsdb_idl_index_create1(nb->idl,
                                  &nbrec_logical_router_port_col_name);
    struct ovsdb_idl_index *nbrec_port_by_name
        = ovsdb_idl_index_create1(nb->idl,
                                  &nbrec_logical_switch_port_col_name);
    struct ovsdb_idl_index *sbrec_chassis_by_name
        = ovsdb_idl_index_create1(sb->idl, &sbrec_chassis_col_name);
    struct ovsdb_idl_index *sbrec_port_binding_by_name
        = ovsdb_idl_index_create1(sb->idl,
                                  &sbrec_port_binding_col_logical_port);
    struct ovsdb_idl_index *sbrec_service_monitor_by_remote_type
        = ovsdb_idl_index_create1(sb->idl,
                                  &sbrec_service_monitor_col_remote);
    struct ovsdb_idl_index *sbrec_service_monitor_by_ic_learned
        = ovsdb_idl_index_create1(sb->idl,
                                  &sbrec_service_monitor_col_ic_learned);
    struct ovsdb_idl_index *sbrec_service_monitor_by_remote_type_logical_port
        = ovsdb_idl_index_create2(sb->idl,
                                  &sbrec_service_monitor_col_remote,
                                  &sbrec_service_monitor_col_logical_port);
    struct ovsdb_idl_index *icnbrec_transit_switch_by_name
        = ovsdb_idl_index_create1(icnb->idl,
                                  &icnbrec_transit_switch_col_name);
    struct ovsdb_idl_index *icsbrec_port_binding_by_az
        = ovsdb_idl_index_create1(icsb->idl,
                                  &icsbrec_port_binding_col_availability_zone);
    struct ovsdb_idl_index *icsbrec_port_binding_by_ts
        = ovsdb_idl_index_create1(icsb->idl,
                                  &icsbrec_port_binding_col_transit_switch);
    struct ovsdb_idl_index *icsbrec_port_binding_by_ts_az
        = ovsdb_idl_index_create2(icsb->idl,
                                  &icsbrec_port_binding_col_transit_switch,
                                  &icsbrec_port_binding_col_availability_zone);
    struct ovsdb_idl_index *icsbrec_route_by_az
        = ovsdb_idl_index_create1(icsb->idl,
                                  &icsbrec_route_col_availability_zone);
    struct ovsdb_idl_index *icsbrec_route_by_ts
        = ovsdb_idl_index_create1(icsb->idl,
                                  &icsbrec_route_col_transit_switch);
    struct ovsdb_idl_index *icsbrec_route_by_ts_az
        = ovsdb_idl_index_create2(icsb->idl,
                                  &icsbrec_route_col_transit_switch,
                                  &icsbrec_route_col_availability_zone);
    struct ovsdb_idl_index *icsbrec_service_monitor_by_source_az
        = ovsdb_idl_index_create1(icsb->idl,
            &icsbrec_service_monitor_col_source_availability_zone);
    struct ovsdb_idl_index *icsbrec_service_monitor_by_target_az
        = ovsdb_idl_index_create1(icsb->idl,
            &icsbrec_service_monitor_col_target_availability_zone);
    struct ovsdb_idl_index *icsbrec_service_monitor_by_target_az_logical_port
        = ovsdb_idl_index_create2(icsb->idl,
            &icsbrec_service_monitor_col_target_availability_zone,
            &icsbrec_service_monitor_col_logical_port);

    engine_init(&en_ic, &engine_arg);

    /* indexes */
    engine_ovsdb_node_add_index(&en_nb_logical_switch,
                                "nbrec_ls_by_name",
                                nbrec_ls_by_name);
    engine_ovsdb_node_add_index(&en_nb_logical_router,
                                "nbrec_lr_by_name",
                                nbrec_lr_by_name);
    engine_ovsdb_node_add_index(&en_nb_logical_router,
                                "nbrec_lrp_by_name",
                                nbrec_lrp_by_name);
    engine_ovsdb_node_add_index(&en_nb_logical_switch,
                                "nbrec_port_by_name",
                                nbrec_port_by_name);
    engine_ovsdb_node_add_index(&en_sb_chassis,
                                "sbrec_chassis_by_name",
                                sbrec_chassis_by_name);
    engine_ovsdb_node_add_index(&en_sb_port_binding,
                                "sbrec_port_binding_by_name",
                                sbrec_port_binding_by_name);
    engine_ovsdb_node_add_index(&en_sb_service_monitor,
                                "sbrec_service_monitor_by_remote_type",
                                sbrec_service_monitor_by_remote_type);
    engine_ovsdb_node_add_index(&en_sb_service_monitor,
                                "sbrec_service_monitor_by_ic_learned",
                                sbrec_service_monitor_by_ic_learned);
    engine_ovsdb_node_add_index(&en_sb_service_monitor,
        "sbrec_service_monitor_by_remote_type_logical_port",
        sbrec_service_monitor_by_remote_type_logical_port);
    engine_ovsdb_node_add_index(&en_icnb_transit_switch,
                                "icnbrec_transit_switch_by_name",
                                icnbrec_transit_switch_by_name);
    engine_ovsdb_node_add_index(&en_icsb_port_binding,
                                "icsbrec_port_binding_by_az",
                                icsbrec_port_binding_by_az);
    engine_ovsdb_node_add_index(&en_icsb_port_binding,
                                "icsbrec_port_binding_by_ts",
                                icsbrec_port_binding_by_ts);
    engine_ovsdb_node_add_index(&en_icsb_port_binding,
                                "icsbrec_port_binding_by_ts_az",
                                icsbrec_port_binding_by_ts_az);
    engine_ovsdb_node_add_index(&en_icsb_route,
                                "icsbrec_route_by_az",
                                icsbrec_route_by_az);
    engine_ovsdb_node_add_index(&en_icsb_route,
                                "icsbrec_route_by_ts",
                                icsbrec_route_by_ts);
    engine_ovsdb_node_add_index(&en_icsb_route,
                                "icsbrec_route_by_ts_az",
                                icsbrec_route_by_ts_az);
    engine_ovsdb_node_add_index(&en_icsb_service_monitor,
                                "icsbrec_service_monitor_by_source_az",
                                icsbrec_service_monitor_by_source_az);
    engine_ovsdb_node_add_index(&en_icsb_service_monitor,
                                "icsbrec_service_monitor_by_target_az",
                                icsbrec_service_monitor_by_target_az);
    engine_ovsdb_node_add_index(&en_icsb_service_monitor,
        "icsbrec_service_monitor_by_target_az_logical_port",
        icsbrec_service_monitor_by_target_az_logical_port);
}

/* Returns true if the incremental processing ended up updating nodes. */
bool
inc_proc_ic_run(struct ovsdb_idl_txn *ovnnb_txn,
                struct ovsdb_idl_txn *ovnsb_txn,
                struct ovsdb_idl_txn *ovninb_txn,
                struct ovsdb_idl_txn *ovnisb_txn,
                struct ic_engine_context *ctx,
                const struct icsbrec_availability_zone *runned_az)
{
    ovs_assert(ovnnb_txn && ovnsb_txn &&
               ovninb_txn && ovnisb_txn);

    int64_t start = time_msec();
    engine_init_run();

    struct engine_context eng_ctx = {
        .client_ctx = (void *) runned_az,
        .ovnnb_idl_txn = ovnnb_txn,
        .ovnsb_idl_txn = ovnsb_txn,
        .ovninb_idl_txn = ovninb_txn,
        .ovnisb_idl_txn = ovnisb_txn,
    };

    engine_set_context(&eng_ctx);
    engine_run(true);

    if (!engine_has_run()) {
        if (engine_need_run()) {
            VLOG_DBG("engine did not run, force recompute next time.");
            engine_set_force_recompute_immediate();
        } else {
            VLOG_DBG("engine did not run, and it was not needed");
        }
    } else if (engine_canceled()) {
        VLOG_DBG("engine was canceled, force recompute next time.");
        engine_set_force_recompute_immediate();
    } else {
        engine_clear_force_recompute();
    }

    int64_t now = time_msec();
    /* Postpone the next run by length of current run with maximum capped
     * by "northd-backoff-interval-ms" interval. */
    ctx->next_run_ms = now + MIN(now - start, ctx->backoff_ms);

    return engine_has_updated();
}

void
inc_proc_ic_cleanup(void)
{
    engine_cleanup();
    engine_set_context(NULL);
}

bool
inc_proc_ic_can_run(struct ic_engine_context *ctx)
{
    if (engine_get_force_recompute() || time_msec() >= ctx->next_run_ms ||
        ctx->nb_idl_duration_ms >= IDL_LOOP_MAX_DURATION_MS ||
        ctx->sb_idl_duration_ms >= IDL_LOOP_MAX_DURATION_MS ||
        ctx->inb_idl_duration_ms >= IDL_LOOP_MAX_DURATION_MS ||
        ctx->isb_idl_duration_ms >= IDL_LOOP_MAX_DURATION_MS) {
        return true;
    }

    poll_timer_wait_until(ctx->next_run_ms);
    return false;
}
