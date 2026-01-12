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
#include "en-gateway.h"
#include "inc-proc-ic.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-util.h"
#include "lib/stopwatch-names.h"
#include "coverage.h"
#include "stopwatch.h"
#include "stopwatch-names.h"

VLOG_DEFINE_THIS_MODULE(gateway);
COVERAGE_DEFINE(gateway_run);

static void
gateway_run(const struct engine_context *eng_ctx,
            struct gateway_input *gateway_input,
            struct ed_type_gateway *gateway_data,
            const struct icsbrec_gateway_table *icsb_gateway_table,
            const struct sbrec_chassis_table *sb_chassis_table);
static void gateway_init(struct ed_type_gateway *data);
static void gateway_destroy(struct ed_type_gateway *data);
static void gateway_clear(struct ed_type_gateway *data);
static void
sync_sb_gw_to_isb(const struct engine_context *ctx,
                  const struct sbrec_chassis *chassis,
                  const struct icsbrec_gateway *gw);
static void
sync_isb_gw_to_sb(const struct engine_context *ctx,
                  const struct icsbrec_gateway *gw,
                  const struct sbrec_chassis *chassis);
static bool
is_gateway_data_changed(const struct icsbrec_gateway *gw,
                        const struct sbrec_chassis *chassis);

enum engine_node_state
en_gateway_run(struct engine_node *node, void *data)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ed_type_gateway *gateway_data = data;
    struct gateway_input gateway_input;

    gateway_clear(gateway_data);

    const struct icsbrec_gateway_table *icsb_gateway_table =
        EN_OVSDB_GET(engine_get_input("ICSB_gateway", node));
    const struct sbrec_chassis_table *sb_chassis_table =
        EN_OVSDB_GET(engine_get_input("SB_chassis", node));

    gateway_input.runned_az = eng_ctx->client_ctx;

    COVERAGE_INC(gateway_run);
    stopwatch_start(OVN_IC_GATEWAY_RUN_STOPWATCH_NAME, time_usec());
    gateway_run(eng_ctx, &gateway_input, gateway_data, icsb_gateway_table,
                sb_chassis_table);
    stopwatch_stop(OVN_IC_GATEWAY_RUN_STOPWATCH_NAME, time_usec());

    return EN_UPDATED;
}

void *
en_gateway_init(struct engine_node *node OVS_UNUSED,
                struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_gateway *data = xzalloc(sizeof *data);
    gateway_init(data);
    return data;
}

void
en_gateway_cleanup(void *data)
{
    gateway_destroy(data);
}

static void
gateway_init(struct ed_type_gateway *data)
{
    shash_init(&data->local_gws);
    shash_init(&data->remote_gws);
}

static void
gateway_destroy(struct ed_type_gateway *data)
{
    gateway_clear(data);

    shash_destroy(&data->local_gws);
    shash_destroy(&data->remote_gws);
}

static void
gateway_clear(struct ed_type_gateway *data)
{
    shash_clear(&data->local_gws);
    shash_clear(&data->remote_gws);
}

static void
gateway_run(const struct engine_context *eng_ctx,
            struct gateway_input *gw_input,
            struct ed_type_gateway *gw_data,
            const struct icsbrec_gateway_table *icsb_gateway_table,
            const struct sbrec_chassis_table *sb_chassis_table)
{
    if (!eng_ctx->ovnisb_idl_txn || !eng_ctx->ovnsb_idl_txn) {
        return;
    }

    const struct icsbrec_gateway *gw;
    ICSBREC_GATEWAY_TABLE_FOR_EACH (gw, icsb_gateway_table) {
        if (gw->availability_zone == gw_input->runned_az) {
            shash_add(&gw_data->local_gws, gw->name, gw);
        } else {
            shash_add(&gw_data->remote_gws, gw->name, gw);
        }
    }

    const struct sbrec_chassis *chassis;
    SBREC_CHASSIS_TABLE_FOR_EACH (chassis, sb_chassis_table) {
        if (smap_get_bool(&chassis->other_config, "is-interconn", false)) {
            gw = shash_find_and_delete(&gw_data->local_gws, chassis->name);
            if (!gw) {
                gw = icsbrec_gateway_insert(eng_ctx->ovnisb_idl_txn);
                icsbrec_gateway_set_availability_zone(gw, gw_input->runned_az);
                icsbrec_gateway_set_name(gw, chassis->name);
                sync_sb_gw_to_isb(eng_ctx, chassis, gw);
            } else if (is_gateway_data_changed(gw, chassis)) {
                sync_sb_gw_to_isb(eng_ctx, chassis, gw);
            }
        } else if (smap_get_bool(&chassis->other_config, "is-remote", false)) {
            gw = shash_find_and_delete(&gw_data->remote_gws, chassis->name);
            if (!gw) {
                sbrec_chassis_delete(chassis);
            } else if (is_gateway_data_changed(gw, chassis)) {
                sync_isb_gw_to_sb(eng_ctx, gw, chassis);
            }
        }
    }

    /* Delete extra gateways from ISB for the local AZ */
    struct shash_node *node;
    SHASH_FOR_EACH (node, &gw_data->local_gws) {
        icsbrec_gateway_delete(node->data);
    }

    /* Create SB chassis for remote gateways in ISB */
    SHASH_FOR_EACH (node, &gw_data->remote_gws) {
        gw = node->data;
        chassis = sbrec_chassis_insert(eng_ctx->ovnsb_idl_txn);
        sbrec_chassis_set_name(chassis, gw->name);
        sync_isb_gw_to_sb(eng_ctx, gw, chassis);
    }
}

/* Returns true if any information in gw and chassis is different. */
static bool
is_gateway_data_changed(const struct icsbrec_gateway *gw,
                        const struct sbrec_chassis *chassis)
{
    if (strcmp(gw->hostname, chassis->hostname)) {
        return true;
    }

    if (gw->n_encaps != chassis->n_encaps) {
        return true;
    }

    for (int g = 0; g < gw->n_encaps; g++) {

        bool found = false;
        const struct icsbrec_encap *gw_encap = gw->encaps[g];
        for (int s = 0; s < chassis->n_encaps; s++) {
            const struct sbrec_encap *chassis_encap = chassis->encaps[s];
            if (!strcmp(gw_encap->type, chassis_encap->type) &&
                !strcmp(gw_encap->ip, chassis_encap->ip)) {
                found = true;
                if (!smap_equal(&gw_encap->options, &chassis_encap->options)) {
                    return true;
                }
                break;
            }
        }
        if (!found) {
            return true;
        }
    }

    return false;
}

static void
sync_isb_gw_to_sb(const struct engine_context *ctx,
                  const struct icsbrec_gateway *gw,
                  const struct sbrec_chassis *chassis)
{
    sbrec_chassis_set_hostname(chassis, gw->hostname);
    sbrec_chassis_update_other_config_setkey(chassis, "is-remote", "true");

    /* Sync encaps used by this gateway. */
    ovs_assert(gw->n_encaps);
    struct sbrec_encap *sb_encap;
    struct sbrec_encap **sb_encaps =
        xmalloc(gw->n_encaps * sizeof *sb_encaps);
    for (int i = 0; i < gw->n_encaps; i++) {
        sb_encap = sbrec_encap_insert(ctx->ovnsb_idl_txn);
        sbrec_encap_set_chassis_name(sb_encap, gw->name);
        sbrec_encap_set_ip(sb_encap, gw->encaps[i]->ip);
        sbrec_encap_set_type(sb_encap, gw->encaps[i]->type);
        sbrec_encap_set_options(sb_encap, &gw->encaps[i]->options);
        sb_encaps[i] = sb_encap;
    }
    sbrec_chassis_set_encaps(chassis, sb_encaps, gw->n_encaps);
    free(sb_encaps);
}

static void
sync_sb_gw_to_isb(const struct engine_context *ctx,
                  const struct sbrec_chassis *chassis,
                  const struct icsbrec_gateway *gw)
{
    icsbrec_gateway_set_hostname(gw, chassis->hostname);

    /* Sync encaps used by this chassis. */
    ovs_assert(chassis->n_encaps);
    struct icsbrec_encap *isb_encap;
    struct icsbrec_encap **isb_encaps =
        xmalloc(chassis->n_encaps * sizeof *isb_encaps);
    for (int i = 0; i < chassis->n_encaps; i++) {
        isb_encap = icsbrec_encap_insert(ctx->ovnisb_idl_txn);
        icsbrec_encap_set_gateway_name(isb_encap,
                                      chassis->name);
        icsbrec_encap_set_ip(isb_encap, chassis->encaps[i]->ip);
        icsbrec_encap_set_type(isb_encap,
                              chassis->encaps[i]->type);
        icsbrec_encap_set_options(isb_encap,
                                 &chassis->encaps[i]->options);
        isb_encaps[i] = isb_encap;
    }
    icsbrec_gateway_set_encaps(gw, isb_encaps,
                              chassis->n_encaps);
    free(isb_encaps);
}
