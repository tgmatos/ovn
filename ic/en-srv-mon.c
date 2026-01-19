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
#include "en-srv-mon.h"
#include "inc-proc-ic.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-util.h"
#include "lib/stopwatch-names.h"
#include "coverage.h"
#include "stopwatch.h"
#include "stopwatch-names.h"

VLOG_DEFINE_THIS_MODULE(en_srv_mon);
COVERAGE_DEFINE(srv_monitor_run);

static void
srv_mon_run(const struct engine_context *eng_ctx,
            struct ed_type_sync_service_monitor *srv_mon_data,
            struct srv_mon_input *srv_mon_input,
            const struct sbrec_sb_global_table *sbrec_sb_global_table);

static void srv_mon_init(struct ed_type_sync_service_monitor *data);
static void srv_mon_destroy(struct ed_type_sync_service_monitor *data);
static void srv_mon_clear(struct ed_type_sync_service_monitor *data);

static void
create_service_monitor_info(struct hmap *svc_map,
                            const void *db_rec,
                            const struct uuid *uuid,
                            const char *src_az_name,
                            const char *target_az_name,
                            const char *chassis_name,
                            bool ic_rec);
static void
destroy_service_monitor_info(struct service_monitor_info *svc_mon);
static void
refresh_sb_record_cache(struct hmap *svc_mon_map,
                        const struct sbrec_service_monitor *lookup_rec);
static void
refresh_ic_record_cache(struct hmap *svc_mon_map,
                        const struct icsbrec_service_monitor *lookup_rec);
static void
remove_unused_ic_records(struct hmap *local_ic_svcs_map);
static void
remove_unused_sb_records(struct hmap *local_sb_svcs_map);
static void
create_pushed_svcs_mon(struct srv_mon_input *srv_mon_input,
                       struct hmap *pushed_svcs_map);
static void
create_synced_svcs_mon(struct srv_mon_input *srv_mon_input,
                       struct hmap *synced_svcs_map);
static void
create_local_ic_svcs_map(struct srv_mon_input *srv_mon_input,
                         struct hmap *owned_svc_map);
static void
create_local_sb_svcs_map(struct srv_mon_input *srv_mon_input,
                         struct hmap *owned_svc_map);
static const struct sbrec_service_monitor *
lookup_sb_svc_rec(struct srv_mon_input *srv_mon_input,
                  const struct service_monitor_info *svc_mon);
static const struct icsbrec_service_monitor *
lookup_icsb_svc_rec(struct srv_mon_input *srv_mon_input,
                    const struct service_monitor_info *svc_mon);
static void
create_service_monitor_data(struct srv_mon_input *srv_mon_input,
    const struct sbrec_sb_global_table *sbrec_sb_global_table,
    struct ed_type_sync_service_monitor *sync_data);
static void
destroy_service_monitor_data(struct ed_type_sync_service_monitor *sync_data);

static void
srv_mon_get_input_data(struct engine_node *node,
                       struct srv_mon_input *input_data)
{
    /* Indexes */
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
en_srv_mon_run(struct engine_node *node, void *data)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ed_type_sync_service_monitor *srv_mon_data = data;
    struct srv_mon_input srv_mon_input;

    srv_mon_clear(srv_mon_data);

    const struct sbrec_sb_global_table *sbrec_sb_global_table =
        EN_OVSDB_GET(engine_get_input("SB_sb_global", node));

    srv_mon_get_input_data(node, &srv_mon_input);
    srv_mon_input.runned_az = eng_ctx->client_ctx;

    COVERAGE_INC(srv_monitor_run);
    stopwatch_start(OVN_IC_SERVICE_MONITOR_RUN_STOPWATCH_NAME, time_usec());
    srv_mon_run(eng_ctx, srv_mon_data, &srv_mon_input, sbrec_sb_global_table);
    stopwatch_stop(OVN_IC_SERVICE_MONITOR_RUN_STOPWATCH_NAME, time_usec());

    return EN_UPDATED;
}

void *
en_srv_mon_init(struct engine_node *node OVS_UNUSED,
           struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_sync_service_monitor *data = xzalloc(sizeof *data);
    srv_mon_init(data);
    return data;
}

void
en_srv_mon_cleanup(void *data)
{
    srv_mon_destroy(data);
}

static void
srv_mon_init(struct ed_type_sync_service_monitor *data)
{
    hmap_init(&data->pushed_svcs_map);
    hmap_init(&data->synced_svcs_map);
    hmap_init(&data->local_ic_svcs_map);
    hmap_init(&data->local_sb_svcs_map);
    data->prpg_svc_monitor_mac = NULL;
    data->tracked = false;
}

static void
srv_mon_destroy(struct ed_type_sync_service_monitor *data)
{
    destroy_service_monitor_data(data);
}

static void
srv_mon_clear(struct ed_type_sync_service_monitor *data)
{
    destroy_service_monitor_data(data);
    srv_mon_init(data);
}

static void
srv_mon_run(const struct engine_context *eng_ctx,
            struct ed_type_sync_service_monitor *srv_mon_data,
            struct srv_mon_input *srv_mon_input,
            const struct sbrec_sb_global_table *sbrec_sb_global_table)
{
    if (!eng_ctx->ovnisb_idl_txn || !eng_ctx->ovnsb_idl_txn) {
        return;
    }

    create_service_monitor_data(srv_mon_input, sbrec_sb_global_table,
                                srv_mon_data);

    struct service_monitor_info *svc_mon;
    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, &srv_mon_data->pushed_svcs_map) {
        const struct sbrec_service_monitor *db_rec = svc_mon->db_rec.sb_rec;
        const struct icsbrec_service_monitor *ic_rec =
            lookup_icsb_svc_rec(srv_mon_input, svc_mon);

        if (ic_rec) {
            sbrec_service_monitor_set_status(db_rec, ic_rec->status);
        } else {
            ic_rec = icsbrec_service_monitor_insert(eng_ctx->ovnisb_idl_txn);
            icsbrec_service_monitor_set_type(ic_rec, db_rec->type);
            icsbrec_service_monitor_set_ip(ic_rec, db_rec->ip);
            icsbrec_service_monitor_set_port(ic_rec, db_rec->port);
            icsbrec_service_monitor_set_src_ip(ic_rec, db_rec->src_ip);
            icsbrec_service_monitor_set_src_mac(ic_rec,
                srv_mon_data->prpg_svc_monitor_mac);
            icsbrec_service_monitor_set_protocol(ic_rec, db_rec->protocol);
            icsbrec_service_monitor_set_logical_port(ic_rec,
                db_rec->logical_port);
            icsbrec_service_monitor_set_target_availability_zone(ic_rec,
                svc_mon->dst_az_name);
            icsbrec_service_monitor_set_source_availability_zone(ic_rec,
                svc_mon->src_az_name);
        }

        /* Always update options because they change from NB. */
        icsbrec_service_monitor_set_options(ic_rec, &db_rec->options);
        refresh_ic_record_cache(&srv_mon_data->local_ic_svcs_map, ic_rec);
    }

    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, &srv_mon_data->synced_svcs_map) {
        const struct icsbrec_service_monitor *db_rec =
            svc_mon->db_rec.ic_rec;
        const struct sbrec_service_monitor *sb_rec =
            lookup_sb_svc_rec(srv_mon_input, svc_mon);

        if (sb_rec) {
            icsbrec_service_monitor_set_status(svc_mon->db_rec.ic_rec,
                                               sb_rec->status);
        } else {
            sb_rec = sbrec_service_monitor_insert(eng_ctx->ovnsb_idl_txn);
            sbrec_service_monitor_set_type(sb_rec, db_rec->type);
            sbrec_service_monitor_set_ip(sb_rec, db_rec->ip);
            sbrec_service_monitor_set_port(sb_rec, db_rec->port);
            sbrec_service_monitor_set_src_ip(sb_rec, db_rec->src_ip);
            /* Set svc_monitor_mac from local SBDB. */
            sbrec_service_monitor_set_src_mac(sb_rec,
                srv_mon_data->prpg_svc_monitor_mac);
            sbrec_service_monitor_set_protocol(sb_rec,
                db_rec->protocol);
            sbrec_service_monitor_set_logical_port(sb_rec,
                db_rec->logical_port);
            sbrec_service_monitor_set_remote(sb_rec, false);
            sbrec_service_monitor_set_ic_learned(sb_rec, true);
        }

        /* Always update options since they may change via
         * NB configuration. Also update chassis_name if
         * the port has been reassigned to a different chassis.
         */
        if (svc_mon->chassis_name) {
            sbrec_service_monitor_set_chassis_name(sb_rec,
                svc_mon->chassis_name);
        }
        sbrec_service_monitor_set_options(sb_rec, &db_rec->options);
        refresh_sb_record_cache(&srv_mon_data->local_sb_svcs_map, sb_rec);
    }

    /* Delete local created records that are no longer used. */
    remove_unused_ic_records(&srv_mon_data->local_ic_svcs_map);
    remove_unused_sb_records(&srv_mon_data->local_sb_svcs_map);
}

static void
create_service_monitor_info(struct hmap *svc_map,
                            const void *db_rec,
                            const struct uuid *uuid,
                            const char *src_az_name,
                            const char *target_az_name,
                            const char *chassis_name,
                            bool ic_rec)
{
    struct service_monitor_info *svc_mon = xzalloc(sizeof(*svc_mon));
    size_t hash = uuid_hash(uuid);

    if (ic_rec) {
        svc_mon->db_rec.ic_rec =
            (const struct icsbrec_service_monitor *) db_rec;
    } else {
        svc_mon->db_rec.sb_rec =
            (const struct sbrec_service_monitor *) db_rec;
    }

    svc_mon->dst_az_name = target_az_name ? xstrdup(target_az_name) : NULL;
    svc_mon->chassis_name = chassis_name ? xstrdup(chassis_name) : NULL;
    svc_mon->src_az_name = xstrdup(src_az_name);

    hmap_insert(svc_map, &svc_mon->hmap_node, hash);
}

static void
destroy_service_monitor_info(struct service_monitor_info *svc_mon)
{
    free(svc_mon->src_az_name);
    free(svc_mon->dst_az_name);
    free(svc_mon->chassis_name);
    free(svc_mon);
}

static void
refresh_sb_record_cache(struct hmap *svc_mon_map,
                        const struct sbrec_service_monitor *lookup_rec)
{
    size_t hash = uuid_hash(&lookup_rec->header_.uuid);
    struct service_monitor_info *svc_mon;

    HMAP_FOR_EACH_WITH_HASH (svc_mon, hmap_node, hash, svc_mon_map) {
        ovs_assert(svc_mon->db_rec.sb_rec);
        if (svc_mon->db_rec.sb_rec == lookup_rec) {
            hmap_remove(svc_mon_map, &svc_mon->hmap_node);
            destroy_service_monitor_info(svc_mon);
            return;
        }
    }
}

static void
refresh_ic_record_cache(struct hmap *svc_mon_map,
                        const struct icsbrec_service_monitor *lookup_rec)
{
    size_t hash = uuid_hash(&lookup_rec->header_.uuid);
    struct service_monitor_info *svc_mon;

    HMAP_FOR_EACH_WITH_HASH (svc_mon, hmap_node, hash, svc_mon_map) {
        ovs_assert(svc_mon->db_rec.ic_rec);
        if (svc_mon->db_rec.ic_rec == lookup_rec) {
            hmap_remove(svc_mon_map, &svc_mon->hmap_node);
            destroy_service_monitor_info(svc_mon);
            return;
        }
    }
}

static void
remove_unused_ic_records(struct hmap *local_ic_svcs_map)
{
    struct service_monitor_info *svc_mon;
    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, local_ic_svcs_map) {
        icsbrec_service_monitor_delete(svc_mon->db_rec.ic_rec);
        destroy_service_monitor_info(svc_mon);
    }

    hmap_destroy(local_ic_svcs_map);
}

static void
remove_unused_sb_records(struct hmap *local_sb_svcs_map)
{
    struct service_monitor_info *svc_mon;
    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, local_sb_svcs_map) {
        sbrec_service_monitor_delete(svc_mon->db_rec.sb_rec);
        destroy_service_monitor_info(svc_mon);
    }

    hmap_destroy(local_sb_svcs_map);
}

static void
create_pushed_svcs_mon(struct srv_mon_input *srv_mon_input,
                       struct hmap *pushed_svcs_map)
{
    struct sbrec_service_monitor *key =
        sbrec_service_monitor_index_init_row(
            srv_mon_input->sbrec_service_monitor_by_remote_type);

    sbrec_service_monitor_index_set_remote(key, true);

    const struct sbrec_service_monitor *sb_rec;
    SBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (sb_rec, key,
        srv_mon_input->sbrec_service_monitor_by_remote_type) {
        const char *target_az_name = smap_get(&sb_rec->options,
                                              "az-name");
        if (!target_az_name) {
            continue;
        }
        create_service_monitor_info(pushed_svcs_map, sb_rec,
                                    &sb_rec->header_.uuid,
                                    srv_mon_input->runned_az->name,
                                    target_az_name, NULL, false);
    }

    sbrec_service_monitor_index_destroy_row(key);
}

static void
create_synced_svcs_mon(struct srv_mon_input *srv_mon_input,
                       struct hmap *synced_svcs_map)
{
    struct icsbrec_service_monitor *key =
        icsbrec_service_monitor_index_init_row(
          srv_mon_input->icsbrec_service_monitor_by_target_az);

    icsbrec_service_monitor_index_set_target_availability_zone(
        key, srv_mon_input->runned_az->name);

    const struct icsbrec_service_monitor *ic_rec;
    ICSBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (ic_rec, key,
        srv_mon_input->icsbrec_service_monitor_by_target_az) {

        const struct sbrec_port_binding *pb =
            find_sb_pb_by_name(srv_mon_input->sbrec_port_binding_by_name,
                               ic_rec->logical_port);

        if (!pb || !pb->up) {
            continue;
        }

        const char *chassis_name = pb->chassis ? pb->chassis->name : NULL;
        create_service_monitor_info(synced_svcs_map, ic_rec,
                                    &ic_rec->header_.uuid,
                                    srv_mon_input->runned_az->name, NULL,
                                    chassis_name, true);
    }

    icsbrec_service_monitor_index_destroy_row(key);
}

static void
create_local_ic_svcs_map(struct srv_mon_input *srv_mon_input,
                         struct hmap *owned_svc_map)
{
    struct icsbrec_service_monitor *key =
        icsbrec_service_monitor_index_init_row(
          srv_mon_input->icsbrec_service_monitor_by_source_az);

    icsbrec_service_monitor_index_set_source_availability_zone(
        key, srv_mon_input->runned_az->name);

    const struct icsbrec_service_monitor *ic_rec;
    ICSBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (ic_rec, key,
        srv_mon_input->icsbrec_service_monitor_by_source_az) {
        create_service_monitor_info(owned_svc_map, ic_rec,
                                    &ic_rec->header_.uuid,
                                    srv_mon_input->runned_az->name, NULL,
                                    NULL, true);
    }

    icsbrec_service_monitor_index_destroy_row(key);
}

static void
create_local_sb_svcs_map(struct srv_mon_input *srv_mon_input,
                         struct hmap *owned_svc_map)
{
    struct sbrec_service_monitor *key =
        sbrec_service_monitor_index_init_row(
          srv_mon_input->sbrec_service_monitor_by_ic_learned);

    sbrec_service_monitor_index_set_ic_learned(
        key, true);

    const struct sbrec_service_monitor *sb_rec;
    SBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (sb_rec, key,
        srv_mon_input->sbrec_service_monitor_by_ic_learned) {
        create_service_monitor_info(owned_svc_map, sb_rec,
                                    &sb_rec->header_.uuid,
                                    srv_mon_input->runned_az->name, NULL,
                                    NULL, false);
    }

    sbrec_service_monitor_index_destroy_row(key);
}

static const struct sbrec_service_monitor *
lookup_sb_svc_rec(struct srv_mon_input *srv_mon_input,
                  const struct service_monitor_info *svc_mon)
{
    const struct icsbrec_service_monitor *db_rec =
        svc_mon->db_rec.ic_rec;
    struct sbrec_service_monitor *key =
        sbrec_service_monitor_index_init_row(
            srv_mon_input->sbrec_service_monitor_by_remote_type_logical_port);

    sbrec_service_monitor_index_set_remote(key, false);
    sbrec_service_monitor_index_set_logical_port(key, db_rec->logical_port);

    const struct sbrec_service_monitor *sb_rec;
    SBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (sb_rec, key,
        srv_mon_input->sbrec_service_monitor_by_remote_type_logical_port) {
        if (db_rec->port == sb_rec->port &&
            ((db_rec->type && sb_rec->type &&
              !strcmp(db_rec->type, sb_rec->type)) ||
             (!db_rec->type && !sb_rec->type)) &&
            !strcmp(db_rec->ip, sb_rec->ip) &&
            !strcmp(db_rec->src_ip, sb_rec->src_ip) &&
            !strcmp(db_rec->protocol, sb_rec->protocol)) {
            sbrec_service_monitor_index_destroy_row(key);
            return sb_rec;
        }
    }

    sbrec_service_monitor_index_destroy_row(key);

    return NULL;
}

static const struct icsbrec_service_monitor *
lookup_icsb_svc_rec(struct srv_mon_input *srv_mon_input,
                    const struct service_monitor_info *svc_mon)
{
    const struct sbrec_service_monitor *db_rec =
       svc_mon->db_rec.sb_rec;
    struct icsbrec_service_monitor *key =
        icsbrec_service_monitor_index_init_row(
        srv_mon_input->icsbrec_service_monitor_by_target_az_logical_port);

    ovs_assert(svc_mon->dst_az_name);
    icsbrec_service_monitor_index_set_target_availability_zone(
        key, svc_mon->dst_az_name);

    icsbrec_service_monitor_index_set_logical_port(
        key, db_rec->logical_port);

    const struct icsbrec_service_monitor *ic_rec;
    ICSBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (ic_rec, key,
        srv_mon_input->icsbrec_service_monitor_by_target_az_logical_port) {
        if (db_rec->port == ic_rec->port &&
            ((db_rec->type && ic_rec->type &&
              !strcmp(db_rec->type, ic_rec->type)) ||
             (!db_rec->type && !ic_rec->type)) &&
            !strcmp(db_rec->ip, ic_rec->ip) &&
            !strcmp(db_rec->src_ip, ic_rec->src_ip) &&
            !strcmp(db_rec->protocol, ic_rec->protocol) &&
            !strcmp(db_rec->logical_port, ic_rec->logical_port)) {
            icsbrec_service_monitor_index_destroy_row(key);
            return ic_rec;
        }
    }

    icsbrec_service_monitor_index_destroy_row(key);

    return NULL;
}

static void
create_service_monitor_data(struct srv_mon_input *srv_mon_input,
    const struct sbrec_sb_global_table *sbrec_sb_global_table,
    struct ed_type_sync_service_monitor *sync_data)
{
    const struct sbrec_sb_global *ic_sb =
        sbrec_sb_global_table_first(sbrec_sb_global_table);
    const char *svc_monitor_mac = smap_get(&ic_sb->options,
                                           "svc_monitor_mac");

    if (!svc_monitor_mac) {
        return;
    }

    sync_data->prpg_svc_monitor_mac = xstrdup(svc_monitor_mac);
    create_pushed_svcs_mon(srv_mon_input, &sync_data->pushed_svcs_map);
    create_synced_svcs_mon(srv_mon_input, &sync_data->synced_svcs_map);
    create_local_ic_svcs_map(srv_mon_input, &sync_data->local_ic_svcs_map);
    create_local_sb_svcs_map(srv_mon_input, &sync_data->local_sb_svcs_map);
}

static void
destroy_service_monitor_data(struct ed_type_sync_service_monitor *sync_data)
{
    struct service_monitor_info *svc_mon;
    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, &sync_data->pushed_svcs_map) {
        destroy_service_monitor_info(svc_mon);
    }

    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, &sync_data->synced_svcs_map) {
        destroy_service_monitor_info(svc_mon);
    }

    hmap_destroy(&sync_data->pushed_svcs_map);
    hmap_destroy(&sync_data->synced_svcs_map);
    free(sync_data->prpg_svc_monitor_mac);
}
