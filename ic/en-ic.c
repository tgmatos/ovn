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
#include "en-ic.h"
#include "en-enum-datapaths.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-util.h"
#include "lib/stopwatch-names.h"
#include "coverage.h"
#include "stopwatch.h"
#include "stopwatch-names.h"

VLOG_DEFINE_THIS_MODULE(en_ic);
COVERAGE_DEFINE(ic_run);

void ic_destroy(struct ic_data *data);
void ic_init(struct ic_data *data);

static void
ic_get_input_data(struct engine_node *node,
                  struct ic_input *input_data)
{
    /* Table references */
    input_data->nbrec_logical_switch_table =
        EN_OVSDB_GET(engine_get_input("NB_logical_switch", node));
    input_data->nbrec_logical_router_table =
        EN_OVSDB_GET(engine_get_input("NB_logical_router", node));
    input_data->sbrec_sb_global_table =
        EN_OVSDB_GET(engine_get_input("SB_sb_global", node));
    input_data->sbrec_chassis_table =
        EN_OVSDB_GET(engine_get_input("SB_chassis", node));
    input_data->icnbrec_ic_nb_global_table =
        EN_OVSDB_GET(engine_get_input("ICNB_ic_nb_global", node));
    input_data->icnbrec_transit_switch_table =
        EN_OVSDB_GET(engine_get_input("ICNB_transit_switch", node));
    input_data->icnbrec_transit_router_table =
        EN_OVSDB_GET(engine_get_input("ICNB_transit_router", node));
    input_data->icsbrec_ic_sb_global_table =
        EN_OVSDB_GET(engine_get_input("ICSB_ic_sb_global", node));
    input_data->icsbrec_availability_zone_table =
        EN_OVSDB_GET(engine_get_input("ICSB_availability_zone", node));
    input_data->icsbrec_encap_table =
        EN_OVSDB_GET(engine_get_input("ICSB_encap", node));
    input_data->icsbrec_datapath_binding_table =
        EN_OVSDB_GET(engine_get_input("ICSB_datapath_binding", node));

    /* Indexes */
    input_data->nbrec_ls_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("NB_logical_switch", node),
            "nbrec_ls_by_name");
    input_data->nbrec_lr_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("NB_logical_router", node),
            "nbrec_lr_by_name");
    input_data->nbrec_lrp_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("NB_logical_router", node),
            "nbrec_lrp_by_name");
    input_data->nbrec_port_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("NB_logical_switch", node),
            "nbrec_port_by_name");
    input_data->sbrec_chassis_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_chassis", node),
            "sbrec_chassis_by_name");
    input_data->sbrec_port_binding_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_port_binding", node),
            "sbrec_port_binding_by_name");
    input_data->sbrec_service_monitor_by_remote_type =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_service_monitor", node),
            "sbrec_service_monitor_by_remote_type");
    input_data->sbrec_service_monitor_by_ic_learned =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_service_monitor", node),
            "sbrec_service_monitor_by_ic_learned");
    input_data->sbrec_service_monitor_by_remote_type_logical_port =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_service_monitor", node),
            "sbrec_service_monitor_by_remote_type_logical_port");
    input_data->icnbrec_transit_switch_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("ICNB_transit_switch", node),
            "icnbrec_transit_switch_by_name");
    input_data->icsbrec_service_monitor_by_source_az =
        engine_ovsdb_node_get_index(
            engine_get_input("ICSB_service_monitor", node),
            "icsbrec_service_monitor_by_source_az");
    input_data->icsbrec_service_monitor_by_target_az =
        engine_ovsdb_node_get_index(
            engine_get_input("ICSB_service_monitor", node),
            "icsbrec_service_monitor_by_target_az");
    input_data->icsbrec_service_monitor_by_target_az_logical_port =
        engine_ovsdb_node_get_index(
            engine_get_input("ICSB_service_monitor", node),
            "icsbrec_service_monitor_by_target_az_logical_port");
}

enum engine_node_state
en_ic_run(struct engine_node *node, void *data)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ic_data *ic_data = data;
    struct ic_input input_data;

    struct ed_type_enum_datapaths *dp_node_data =
        engine_get_input_data("enum_datapaths", node);

    if (!dp_node_data) {
        return EN_UNCHANGED;
    }

    ic_data->dp_tnlids = &dp_node_data->dp_tnlids;
    ic_data->isb_ts_dps = &dp_node_data->isb_ts_dps;
    ic_data->isb_tr_dps = &dp_node_data->isb_tr_dps;

    ic_get_input_data(node, &input_data);
    input_data.runned_az = eng_ctx->client_ctx;

    COVERAGE_INC(ic_run);
    stopwatch_start(IC_OVN_DB_RUN_STOPWATCH_NAME, time_msec());
    ovn_db_run(&input_data, ic_data, (struct engine_context *) eng_ctx);
    stopwatch_stop(IC_OVN_DB_RUN_STOPWATCH_NAME, time_msec());
    return EN_UPDATED;
}

void *
en_ic_init(struct engine_node *node OVS_UNUSED,
           struct engine_arg *arg OVS_UNUSED)
{
    struct ic_data *data = xzalloc(sizeof *data);

    ic_init(data);

    return data;
}

void
en_ic_cleanup(void *data)
{
    ic_destroy(data);
}

void
ic_destroy(struct ic_data *data OVS_UNUSED)
{
}

void
ic_init(struct ic_data *data)
{
    data->dp_tnlids = NULL;
    data->isb_ts_dps = NULL;
    data->isb_tr_dps = NULL;
}
