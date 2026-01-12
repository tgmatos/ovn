/*
 * Copyright (c) 2020 eBay Inc.
 *
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

#include "bitmap.h"
#include "command-line.h"
#include "daemon.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "lib/ovn-ic-nb-idl.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "memory.h"
#include "openvswitch/poll-loop.h"
#include "ovsdb-idl.h"
#include "simap.h"
#include "smap.h"
#include "sset.h"
#include "stream.h"
#include "stream-ssl.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"
#include "openvswitch/vlog.h"
#include "vec.h"
#include "inc-proc-ic.h"
#include "ovn-ic.h"
#include "stopwatch-names.h"
#include "stopwatch.h"

VLOG_DEFINE_THIS_MODULE(ovn_ic);

static unixctl_cb_func ovn_ic_exit;
static unixctl_cb_func ovn_ic_pause;
static unixctl_cb_func ovn_ic_resume;
static unixctl_cb_func ovn_ic_is_paused;
static unixctl_cb_func ovn_ic_status;

static const char *ovnnb_db;
static const char *ovnsb_db;
static const char *ovn_ic_nb_db;
static const char *ovn_ic_sb_db;
static const char *unixctl_path;

/* SSL/TLS options. */
static const char *ssl_private_key_file;
static const char *ssl_certificate_file;
static const char *ssl_ca_cert_file;


static void
usage(void)
{
    printf("\
%s: OVN interconnection management daemon\n\
usage: %s [OPTIONS]\n\
\n\
Options:\n\
  --ovnnb-db=DATABASE       connect to ovn-nb database at DATABASE\n\
                            (default: %s)\n\
  --ovnsb-db=DATABASE       connect to ovn-sb database at DATABASE\n\
                            (default: %s)\n\
  --ic-nb-db=DATABASE       connect to ovn-ic-nb database at DATABASE\n\
                            (default: %s)\n\
  --ic-sb-db=DATABASE       connect to ovn-ic-sb database at DATABASE\n\
                            (default: %s)\n\
  --unixctl=SOCKET          override default control socket name\n\
  -h, --help                display this help message\n\
  -o, --options             list available options\n\
  -V, --version             display version information\n\
", program_name, program_name, default_nb_db(), default_sb_db(),
    default_ic_nb_db(), default_ic_sb_db());
    daemon_usage();
    vlog_usage();
    stream_usage("database", true, true, false);
}

const struct icsbrec_availability_zone *
az_run(struct ovsdb_idl *ovnnb_idl,
       struct ovsdb_idl *ovnisb_idl,
       struct ovsdb_idl_txn *ovnisb_idl_txn)
{
    const struct nbrec_nb_global *nb_global =
        nbrec_nb_global_first(ovnnb_idl);

    if (!nb_global) {
        VLOG_INFO("NB Global not exist.");
        return NULL;
    }

    /* Update old AZ if name changes.  Note: if name changed when ovn-ic
     * is not running, one has to manually delete/update the old AZ with:
     * "ovn-ic-sbctl destroy avail <az>". */
    static char *az_name;
    const struct icsbrec_availability_zone *az;
    if (ovnisb_idl_txn && az_name && strcmp(az_name, nb_global->name)) {
        ICSBREC_AVAILABILITY_ZONE_FOR_EACH (az, ovnisb_idl) {
            /* AZ name update locally need to update az in ISB. */
            if (nb_global->name[0] && !strcmp(az->name, az_name)) {
                icsbrec_availability_zone_set_name(az, nb_global->name);
                break;
            } else if (!nb_global->name[0] && !strcmp(az->name, az_name)) {
                icsbrec_availability_zone_delete(az);
                break;
            }
        }
        free(az_name);
        az_name = NULL;
    }

    if (!nb_global->name[0]) {
        return NULL;
    }

    if (!az_name) {
        az_name = xstrdup(nb_global->name);
    }

    if (ovnisb_idl_txn) {
        ovsdb_idl_txn_add_comment(ovnisb_idl_txn, "AZ %s", az_name);
    }

    ICSBREC_AVAILABILITY_ZONE_FOR_EACH (az, ovnisb_idl) {
        if (!strcmp(az->name, az_name)) {
            return (struct icsbrec_availability_zone *) az;
        }
    }

    /* Create AZ in ISB */
    if (ovnisb_idl_txn) {
        VLOG_INFO("Register AZ %s to interconnection DB.", az_name);
        az = icsbrec_availability_zone_insert(ovnisb_idl_txn);
        icsbrec_availability_zone_set_name(az, az_name);
        return (struct icsbrec_availability_zone *) az;
    }
    return NULL;
}

static uint32_t
allocate_dp_key(struct hmap *dp_tnlids, bool vxlan_mode, const char *name)
{
    uint32_t hint = vxlan_mode ? OVN_MIN_DP_VXLAN_KEY_GLOBAL
                               : OVN_MIN_DP_KEY_GLOBAL;
    return ovn_allocate_tnlid(dp_tnlids, name, hint,
            vxlan_mode ? OVN_MAX_DP_VXLAN_KEY_GLOBAL : OVN_MAX_DP_KEY_GLOBAL,
            &hint);
}

enum ic_port_binding_type
ic_pb_get_type(const struct icsbrec_port_binding *isb_pb)
{
    if (isb_pb->type && !strcmp(isb_pb->type, "transit-router-port")) {
        return IC_ROUTER_PORT;
    }

    return IC_SWITCH_PORT;
}

static void
ts_run(struct engine_context *ctx,
       struct ic_input *ic,
       struct hmap *dp_tnlids,
       struct shash *isb_ts_dps)
{
    const struct icnbrec_transit_switch *ts;
    bool dp_key_refresh = false;
    bool vxlan_mode = false;
    const struct icnbrec_ic_nb_global *ic_nb =
        icnbrec_ic_nb_global_table_first(ic->icnbrec_ic_nb_global_table);

    if (ic_nb && smap_get_bool(&ic_nb->options, "vxlan_mode", false)) {
        const struct icsbrec_encap *encap;
        ICSBREC_ENCAP_TABLE_FOR_EACH (encap, ic->icsbrec_encap_table) {
            if (!strcmp(encap->type, "vxlan")) {
                vxlan_mode = true;
                break;
            }
        }
    }

    /* Sync INB TS to AZ NB */
    if (ctx->ovnnb_idl_txn) {
        struct shash nb_tses = SHASH_INITIALIZER(&nb_tses);
        const struct nbrec_logical_switch *ls;

        /* Get current NB Logical_Switch with other_config:interconn-ts */
        NBREC_LOGICAL_SWITCH_TABLE_FOR_EACH (ls,
                                             ic->nbrec_logical_switch_table) {
            const char *ts_name = smap_get(&ls->other_config, "interconn-ts");
            if (ts_name) {
                shash_add(&nb_tses, ts_name, ls);
            }
        }

        /* Create/update NB Logical_Switch for each TS */
        ICNBREC_TRANSIT_SWITCH_TABLE_FOR_EACH (ts,
            ic->icnbrec_transit_switch_table) {
            ls = shash_find_and_delete(&nb_tses, ts->name);
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

            const struct icsbrec_datapath_binding *isb_dp;
            isb_dp = shash_find_data(isb_ts_dps, ts->name);
            if (!isb_dp) {
                const struct icsbrec_datapath_binding *raw;
                ICSBREC_DATAPATH_BINDING_TABLE_FOR_EACH (raw,
                    ic->icsbrec_datapath_binding_table) {
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
    if (ctx->ovnisb_idl_txn) {
        /* Create ISB Datapath_Binding */
        ICNBREC_TRANSIT_SWITCH_TABLE_FOR_EACH (ts,
            ic->icnbrec_transit_switch_table) {
            const struct icsbrec_datapath_binding *isb_dp =
                shash_find_and_delete(isb_ts_dps, ts->name);

            if (!isb_dp) {
                const struct icsbrec_datapath_binding *raw_isb;
                ICSBREC_DATAPATH_BINDING_TABLE_FOR_EACH (raw_isb,
                    ic->icsbrec_datapath_binding_table) {
                    if (raw_isb->n_nb_ic_uuid > 0 &&
                        uuid_equals(&raw_isb->nb_ic_uuid[0],
                                    &ts->header_.uuid)) {
                        isb_dp = raw_isb;
                        if (isb_dp->transit_switch) {
                            shash_find_and_delete(isb_ts_dps,
                                                  isb_dp->transit_switch);
                        }
                        break;
                    }
                }
            }

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
                icsbrec_datapath_binding_set_nb_ic_uuid(isb_dp,
                                                        &ts->header_.uuid, 1);
                icsbrec_datapath_binding_set_type(isb_dp, "transit-switch");
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

        struct shash_node *node, *next;
        SHASH_FOR_EACH_SAFE (node, next, isb_ts_dps) {
            struct icsbrec_datapath_binding *isb_dp_to_del = node->data;
            if (isb_dp_to_del->n_nb_ic_uuid > 0) {
                icsbrec_datapath_binding_delete(isb_dp_to_del);
            }
            shash_delete(isb_ts_dps, node);
        }
    }
}

static void
tr_run(struct engine_context *ctx,
       struct ic_input *ic,
       struct hmap *dp_tnlids,
       struct shash *isb_tr_dps)
{
    const struct nbrec_logical_router *lr;

    if (ctx->ovnnb_idl_txn) {
        struct shash nb_tres = SHASH_INITIALIZER(&nb_tres);
        NBREC_LOGICAL_ROUTER_TABLE_FOR_EACH (lr,
                                             ic->nbrec_logical_router_table) {
            const char *tr_name = smap_get(&lr->options, "interconn-tr");
            if (tr_name) {
                shash_add(&nb_tres, tr_name, lr);
            }
        }

        const struct icnbrec_transit_router *tr;
        ICNBREC_TRANSIT_ROUTER_TABLE_FOR_EACH (tr,
            ic->icnbrec_transit_router_table) {
            lr = shash_find_and_delete(&nb_tres, tr->name);
            if (!lr) {
                lr = nbrec_logical_router_insert(ctx->ovnnb_idl_txn);
                nbrec_logical_router_set_name(lr, tr->name);
                nbrec_logical_router_update_options_setkey(
                    lr, "interconn-tr", tr->name);
            }
            char *uuid_str = uuid_to_string(&tr->header_.uuid);
            struct icsbrec_datapath_binding *isb_dp = shash_find_data(
                isb_tr_dps, uuid_str);
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
    if (ctx->ovnisb_idl_txn) {
        /* Create ISB Datapath_Binding */
        const struct icnbrec_transit_router *tr;
        ICNBREC_TRANSIT_ROUTER_TABLE_FOR_EACH (tr,
            ic->icnbrec_transit_router_table) {
            char *uuid_str = uuid_to_string(&tr->header_.uuid);
            struct icsbrec_datapath_binding *isb_dp =
                shash_find_and_delete(isb_tr_dps, uuid_str);
            free(uuid_str);

            if (!isb_dp) {
                int dp_key = allocate_dp_key(dp_tnlids, false,
                                             "transit router datapath");
                if (!dp_key) {
                    continue;
                }

                isb_dp = icsbrec_datapath_binding_insert(ctx->ovnisb_idl_txn);
                icsbrec_datapath_binding_set_tunnel_key(isb_dp, dp_key);
                icsbrec_datapath_binding_set_nb_ic_uuid(isb_dp,
                                                        &tr->header_.uuid, 1);
                icsbrec_datapath_binding_set_type(isb_dp, "transit-router");
            }
        }

        struct shash_node *node;
        SHASH_FOR_EACH (node, isb_tr_dps) {
            icsbrec_datapath_binding_delete(node->data);
        }
    }
}

const struct nbrec_logical_router_port *
get_lrp_by_lrp_name(struct ovsdb_idl_index *nbrec_lrp_by_name,
                    const char *lrp_name)
{
    const struct nbrec_logical_router_port *lrp;
    const struct nbrec_logical_router_port *lrp_key =
        nbrec_logical_router_port_index_init_row(nbrec_lrp_by_name);
    nbrec_logical_router_port_index_set_name(lrp_key, lrp_name);
    lrp =
        nbrec_logical_router_port_index_find(nbrec_lrp_by_name, lrp_key);
    nbrec_logical_router_port_index_destroy_row(lrp_key);

    return lrp;
}

const struct nbrec_logical_switch *
find_ts_in_nb(struct ovsdb_idl_index *nbrec_ls_by_name, char *ts_name)
{
    const struct nbrec_logical_switch *key =
        nbrec_logical_switch_index_init_row(nbrec_ls_by_name);
    nbrec_logical_switch_index_set_name(key, ts_name);

    const struct nbrec_logical_switch *ls;
    bool found = false;
    NBREC_LOGICAL_SWITCH_FOR_EACH_EQUAL (ls, key, nbrec_ls_by_name) {
        const char *ls_ts_name = smap_get(&ls->other_config, "interconn-ts");
        if (ls_ts_name && !strcmp(ts_name, ls_ts_name)) {
            found = true;
            break;
        }
    }
    nbrec_logical_switch_index_destroy_row(key);

    if (found) {
        return ls;
    }
    return NULL;
}

const struct nbrec_logical_switch_port *
get_lsp_by_ts_port_name(struct ovsdb_idl_index *nbrec_port_by_name,
                        const char *ts_port_name)
{
    const struct nbrec_logical_switch_port *lsp, *key;

    key = nbrec_logical_switch_port_index_init_row(nbrec_port_by_name);
    nbrec_logical_switch_port_index_set_name(key, ts_port_name);
    lsp = nbrec_logical_switch_port_index_find(nbrec_port_by_name, key);
    nbrec_logical_switch_port_index_destroy_row(key);

    return lsp;
}

const struct sbrec_port_binding *
find_sb_pb_by_name(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                   const char *name)
{
    const struct sbrec_port_binding *key =
        sbrec_port_binding_index_init_row(sbrec_port_binding_by_name);
    sbrec_port_binding_index_set_logical_port(key, name);

    const struct sbrec_port_binding *pb =
        sbrec_port_binding_index_find(sbrec_port_binding_by_name, key);
    sbrec_port_binding_index_destroy_row(key);

    return pb;
}

/*
 * Data structures and functions related to
 * synchronize health checks for load balancers
 * between availability zones.
 */
struct sync_service_monitor_data {
    /* Map of service monitors to be pushed to other AZs. */
    struct hmap pushed_svcs_map;
    /* Map of service monitors synced from other AZs to our. */
    struct hmap synced_svcs_map;
    /* Map of local service monitors in the ICSBDB. */
    struct hmap local_ic_svcs_map;
    /* Map of local service monitors in SBDB. */
    struct hmap local_sb_svcs_map;
    /* MAC address used for service monitor.  */
    char *prpg_svc_monitor_mac;
};

struct service_monitor_info {
    struct hmap_node hmap_node;
    union {
        const struct sbrec_service_monitor *sb_rec;
        const struct icsbrec_service_monitor *ic_rec;
    } db_rec;
    /* Destination availability zone name. */
    char *dst_az_name;
    /* Source availability zone name. */
    char *src_az_name;
    /* Chassis name associated with monitor logical port. */
    char *chassis_name;
};

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
create_pushed_svcs_mon(struct ic_input *ic,
                       struct hmap *pushed_svcs_map)
{
    struct sbrec_service_monitor *key =
        sbrec_service_monitor_index_init_row(
            ic->sbrec_service_monitor_by_remote_type);

    sbrec_service_monitor_index_set_remote(key, true);

    const struct sbrec_service_monitor *sb_rec;
    SBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (sb_rec, key,
        ic->sbrec_service_monitor_by_remote_type) {
        const char *target_az_name = smap_get(&sb_rec->options,
                                              "az-name");
        if (!target_az_name) {
            continue;
        }
        create_service_monitor_info(pushed_svcs_map, sb_rec,
                                    &sb_rec->header_.uuid,
                                    ic->runned_az->name, target_az_name,
                                    NULL, false);
    }

    sbrec_service_monitor_index_destroy_row(key);
}

static void
create_synced_svcs_mon(struct ic_input *ic,
                       struct hmap *synced_svcs_map)
{
    struct icsbrec_service_monitor *key =
        icsbrec_service_monitor_index_init_row(
          ic->icsbrec_service_monitor_by_target_az);

    icsbrec_service_monitor_index_set_target_availability_zone(
        key, ic->runned_az->name);

    const struct icsbrec_service_monitor *ic_rec;
    ICSBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (ic_rec, key,
        ic->icsbrec_service_monitor_by_target_az) {

        const struct sbrec_port_binding *pb =
            find_sb_pb_by_name(ic->sbrec_port_binding_by_name,
                               ic_rec->logical_port);

        if (!pb || !pb->up) {
            continue;
        }

        const char *chassis_name = pb->chassis ? pb->chassis->name : NULL;
        create_service_monitor_info(synced_svcs_map, ic_rec,
                                    &ic_rec->header_.uuid,
                                    ic->runned_az->name,
                                    NULL, chassis_name, true);
    }

    icsbrec_service_monitor_index_destroy_row(key);
}

static void
create_local_ic_svcs_map(struct ic_input *ic,
                         struct hmap *owned_svc_map)
{
    struct icsbrec_service_monitor *key =
        icsbrec_service_monitor_index_init_row(
          ic->icsbrec_service_monitor_by_source_az);

    icsbrec_service_monitor_index_set_source_availability_zone(
        key, ic->runned_az->name);

    const struct icsbrec_service_monitor *ic_rec;
    ICSBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (ic_rec, key,
        ic->icsbrec_service_monitor_by_source_az) {
        create_service_monitor_info(owned_svc_map, ic_rec,
                                    &ic_rec->header_.uuid,
                                    ic->runned_az->name, NULL,
                                    NULL, true);
    }

    icsbrec_service_monitor_index_destroy_row(key);
}

static void
create_local_sb_svcs_map(struct ic_input *ic,
                         struct hmap *owned_svc_map)
{
    struct sbrec_service_monitor *key =
        sbrec_service_monitor_index_init_row(
          ic->sbrec_service_monitor_by_ic_learned);

    sbrec_service_monitor_index_set_ic_learned(
        key, true);

    const struct sbrec_service_monitor *sb_rec;
    SBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (sb_rec, key,
        ic->sbrec_service_monitor_by_ic_learned) {
        create_service_monitor_info(owned_svc_map, sb_rec,
                                    &sb_rec->header_.uuid,
                                    ic->runned_az->name, NULL,
                                    NULL, false);
    }

    sbrec_service_monitor_index_destroy_row(key);
}

static const struct sbrec_service_monitor *
lookup_sb_svc_rec(struct ic_input *ic,
                  const struct service_monitor_info *svc_mon)
{
    const struct icsbrec_service_monitor *db_rec =
        svc_mon->db_rec.ic_rec;
    struct sbrec_service_monitor *key =
        sbrec_service_monitor_index_init_row(
            ic->sbrec_service_monitor_by_remote_type_logical_port);

    sbrec_service_monitor_index_set_remote(key, false);
    sbrec_service_monitor_index_set_logical_port(key, db_rec->logical_port);

    const struct sbrec_service_monitor *sb_rec;
    SBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (sb_rec, key,
        ic->sbrec_service_monitor_by_remote_type_logical_port) {
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
lookup_icsb_svc_rec(struct ic_input *ic,
                    const struct service_monitor_info *svc_mon)
{
    const struct sbrec_service_monitor *db_rec =
       svc_mon->db_rec.sb_rec;
    struct icsbrec_service_monitor *key =
        icsbrec_service_monitor_index_init_row(
        ic->icsbrec_service_monitor_by_target_az_logical_port);

    ovs_assert(svc_mon->dst_az_name);
    icsbrec_service_monitor_index_set_target_availability_zone(
        key, svc_mon->dst_az_name);

    icsbrec_service_monitor_index_set_logical_port(
        key, db_rec->logical_port);

    const struct icsbrec_service_monitor *ic_rec;
    ICSBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (ic_rec, key,
        ic->icsbrec_service_monitor_by_target_az_logical_port) {
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
create_service_monitor_data(struct ic_input *ic,
                            struct sync_service_monitor_data *sync_data)
{
    const struct sbrec_sb_global *ic_sb =
        sbrec_sb_global_table_first(ic->sbrec_sb_global_table);
    const char *svc_monitor_mac = smap_get(&ic_sb->options,
                                           "svc_monitor_mac");

    if (!svc_monitor_mac) {
        return;
    }

    sync_data->prpg_svc_monitor_mac = xstrdup(svc_monitor_mac);
    create_pushed_svcs_mon(ic, &sync_data->pushed_svcs_map);
    create_synced_svcs_mon(ic, &sync_data->synced_svcs_map);
    create_local_ic_svcs_map(ic, &sync_data->local_ic_svcs_map);
    create_local_sb_svcs_map(ic, &sync_data->local_sb_svcs_map);
}

static void
destroy_service_monitor_data(struct sync_service_monitor_data *sync_data)
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

static void
sync_service_monitor(struct engine_context *ctx,
                     struct ic_input *ic)
{
    if (!ctx->ovnisb_idl_txn || !ctx->ovnsb_idl_txn) {
        return;
    }

    struct sync_service_monitor_data sync_data;
    memset(&sync_data, 0, sizeof(sync_data));
    hmap_init(&sync_data.pushed_svcs_map);
    hmap_init(&sync_data.synced_svcs_map);
    hmap_init(&sync_data.local_ic_svcs_map);
    hmap_init(&sync_data.local_sb_svcs_map);

    create_service_monitor_data(ic, &sync_data);

    struct service_monitor_info *svc_mon;
    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, &sync_data.pushed_svcs_map) {
        const struct sbrec_service_monitor *db_rec = svc_mon->db_rec.sb_rec;
        const struct icsbrec_service_monitor *ic_rec =
            lookup_icsb_svc_rec(ic, svc_mon);

        if (ic_rec) {
            sbrec_service_monitor_set_status(db_rec, ic_rec->status);
        } else {
            ic_rec = icsbrec_service_monitor_insert(ctx->ovnisb_idl_txn);
            icsbrec_service_monitor_set_type(ic_rec, db_rec->type);
            icsbrec_service_monitor_set_ip(ic_rec, db_rec->ip);
            icsbrec_service_monitor_set_port(ic_rec, db_rec->port);
            icsbrec_service_monitor_set_src_ip(ic_rec, db_rec->src_ip);
            icsbrec_service_monitor_set_src_mac(ic_rec,
                sync_data.prpg_svc_monitor_mac);
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
        refresh_ic_record_cache(&sync_data.local_ic_svcs_map, ic_rec);
    }

    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, &sync_data.synced_svcs_map) {
        const struct icsbrec_service_monitor *db_rec =
            svc_mon->db_rec.ic_rec;
        const struct sbrec_service_monitor *sb_rec =
            lookup_sb_svc_rec(ic, svc_mon);

        if (sb_rec) {
            icsbrec_service_monitor_set_status(svc_mon->db_rec.ic_rec,
                                               sb_rec->status);
        } else {
            sb_rec = sbrec_service_monitor_insert(ctx->ovnsb_idl_txn);
            sbrec_service_monitor_set_type(sb_rec, db_rec->type);
            sbrec_service_monitor_set_ip(sb_rec, db_rec->ip);
            sbrec_service_monitor_set_port(sb_rec, db_rec->port);
            sbrec_service_monitor_set_src_ip(sb_rec, db_rec->src_ip);
            /* Set svc_monitor_mac from local SBDB. */
            sbrec_service_monitor_set_src_mac(sb_rec,
                sync_data.prpg_svc_monitor_mac);
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
        refresh_sb_record_cache(&sync_data.local_sb_svcs_map, sb_rec);
    }

    /* Delete local created records that are no longer used. */
    remove_unused_ic_records(&sync_data.local_ic_svcs_map);
    remove_unused_sb_records(&sync_data.local_sb_svcs_map);

    destroy_service_monitor_data(&sync_data);
}

/*
 * This function implements a sequence number protocol that can be used by
 * the INB end user to verify that ISB is synced with all the changes that
 * are done be the user/AZs-controllers:
 *
 * Since we have multiple IC instances running in different regions
 * we can't rely on one of them to update the ISB and sync that update
 * to INB since other ICs can make changes in parallel.
 * So to have a sequence number protocol working properly we must
 * make sure that all the IC instances are synced with the ISB first
 * and then update the INB.
 *
 * To guarantee that all instances are synced with ISB first, each IC
 * will do the following steps:
 *
 * 1. when local ovn-ic sees that INB:nb_ic_cfg has updated we will set
 *    the ic_sb_loop->next_cfg to match the INB:nb_ic_cfg and increment
 *    the value of AZ:nb_ic_cfg and wait until we get confirmation from
 *    the server.
 *
 * 2. once this IC instance changes for ISB are committed successfully
 *    (next loop), the value of cur_cfg will be updated to match
 *    the INB:nb_ic_cfg that indicate that our local instance is up to date
 *    and no more changes need to be done for ISB.
 *
 * 3. validate that the AZ:nb_ic_cfg to match the INB:nb_ic_cfg.
 *
 * 4. Go through all the AZs and check if all have the same value of
 *    AZ:nb_ic_cfg that means all the AZs are done with ISB changes and ISB are
 *    up to date with INB, so we can set the values of ISB:nb_ic_cfg to
 *    INB:nb_ic_cfg and INB:sb_ic_cfg to INB:nb_ic_cfg.
 */
static void
update_sequence_numbers(struct ovsdb_idl *ovninb_idl,
                        struct ovsdb_idl *ovnisb_idl,
                        struct ovsdb_idl_txn *ovninb_txn,
                        struct ovsdb_idl_txn *ovnisb_txn,
                        struct ovsdb_idl_loop *ic_sb_loop,
                        const struct icsbrec_availability_zone *az)
{
    if (!ovnisb_txn || !ovninb_txn) {
        return;
    }

    const struct icnbrec_ic_nb_global *ic_nb = icnbrec_ic_nb_global_first(
                                               ovninb_idl);
    if (!ic_nb) {
        ic_nb = icnbrec_ic_nb_global_insert(ovninb_txn);
    }
    const struct icsbrec_ic_sb_global *ic_sb = icsbrec_ic_sb_global_first(
                                               ovnisb_idl);
    if (!ic_sb) {
        ic_sb = icsbrec_ic_sb_global_insert(ovnisb_txn);
    }

    if ((ic_nb->nb_ic_cfg != ic_sb->nb_ic_cfg) &&
                          (ic_nb->nb_ic_cfg != az->nb_ic_cfg)) {
        /* Deal with potential overflows. */
        if (az->nb_ic_cfg == INT64_MAX) {
            icsbrec_availability_zone_set_nb_ic_cfg(az, 0);
        }
        ic_sb_loop->next_cfg = ic_nb->nb_ic_cfg;
        ovsdb_idl_txn_increment(ovnisb_txn, &az->header_,
            &icsbrec_availability_zone_col_nb_ic_cfg, true);
        return;
    }

    /* handle cases where accidentally AZ:ic_nb_cfg exceeds
     * the INB:ic_nb_cfg.
     */
    if (az->nb_ic_cfg != ic_sb_loop->cur_cfg) {
        icsbrec_availability_zone_set_nb_ic_cfg(az,
                                                ic_sb_loop->cur_cfg);
        return;
    }

    const struct icsbrec_availability_zone *other_az;
    ICSBREC_AVAILABILITY_ZONE_FOR_EACH (other_az, ovnisb_idl) {
        if (other_az->nb_ic_cfg != az->nb_ic_cfg) {
            return;
        }
    }
    /* All the AZs are updated successfully, update SB/NB counter. */
    if (ic_nb->nb_ic_cfg != ic_sb->nb_ic_cfg) {
        icsbrec_ic_sb_global_set_nb_ic_cfg(ic_sb, az->nb_ic_cfg);
        icnbrec_ic_nb_global_set_sb_ic_cfg(ic_nb, az->nb_ic_cfg);
    }
}

static void
inc_proc_graph_dump(const char *end_node)
{
    struct ovsdb_idl_loop ovnnb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create_unconnected(&nbrec_idl_class, true));
    struct ovsdb_idl_loop ovnsb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create_unconnected(&sbrec_idl_class, true));
    struct ovsdb_idl_loop ovninb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create_unconnected(&icnbrec_idl_class, true));
    struct ovsdb_idl_loop ovnisb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create_unconnected(&icsbrec_idl_class, true));

    inc_proc_ic_init(&ovnnb_idl_loop, &ovnsb_idl_loop,
                     &ovninb_idl_loop, &ovnisb_idl_loop);
    engine_dump_graph(end_node);

    ovsdb_idl_loop_destroy(&ovnnb_idl_loop);
    ovsdb_idl_loop_destroy(&ovnsb_idl_loop);
    ovsdb_idl_loop_destroy(&ovninb_idl_loop);
    ovsdb_idl_loop_destroy(&ovnisb_idl_loop);
}

void
ovn_db_run(struct ic_input *input_data,
           struct ic_data *ic_data,
           struct engine_context *eng_ctx)
{
    ts_run(eng_ctx, input_data, ic_data->dp_tnlids, ic_data->isb_ts_dps);
    tr_run(eng_ctx, input_data, ic_data->dp_tnlids, ic_data->isb_tr_dps);
    sync_service_monitor(eng_ctx, input_data);
}

static void
parse_options(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum {
        OVN_DAEMON_OPTION_ENUMS,
        VLOG_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
        OPT_DUMP_INC_PROC_GRAPH,
    };
    static const struct option long_options[] = {
        {"ovnsb-db", required_argument, NULL, 'd'},
        {"ovnnb-db", required_argument, NULL, 'D'},
        {"ic-sb-db", required_argument, NULL, 'i'},
        {"ic-nb-db", required_argument, NULL, 'I'},
        {"unixctl", required_argument, NULL, 'u'},
        {"help", no_argument, NULL, 'h'},
        {"options", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        {"dump-inc-proc-graph", optional_argument, NULL,
         OPT_DUMP_INC_PROC_GRAPH},
        OVN_DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        OVN_DAEMON_OPTION_HANDLERS;
        VLOG_OPTION_HANDLERS;

        case 'p':
            ssl_private_key_file = optarg;
            break;

        case 'c':
            ssl_certificate_file = optarg;
            break;

        case 'C':
            ssl_ca_cert_file = optarg;
            break;

        case OPT_SSL_PROTOCOLS:
            stream_ssl_set_protocols(optarg);
            break;

        case OPT_SSL_CIPHERS:
            stream_ssl_set_ciphers(optarg);
            break;

        case OPT_SSL_CIPHERSUITES:
            stream_ssl_set_ciphersuites(optarg);
            break;

        case OPT_SSL_SERVER_NAME:
            stream_ssl_set_server_name(optarg);
            break;

        case 'd':
            ovnsb_db = optarg;
            break;

        case 'D':
            ovnnb_db = optarg;
            break;

        case 'i':
            ovn_ic_sb_db = optarg;
            break;

        case 'I':
            ovn_ic_nb_db = optarg;
            break;

        case 'u':
            unixctl_path = optarg;
            break;

        case 'h':
            usage();
            exit(EXIT_SUCCESS);

        case 'o':
            ovs_cmdl_print_options(long_options);
            exit(EXIT_SUCCESS);

        case 'V':
            ovn_print_version(0, 0);
            exit(EXIT_SUCCESS);

        /* --dump-inc-proc-graph[=<i-p-node>]: Whether to dump the I-P engine
         * graph representation in DOT format to stdout.  Optionally only up
         * to <i-p-node>.
         */
        case OPT_DUMP_INC_PROC_GRAPH:
            inc_proc_graph_dump(optarg);
            exit(EXIT_SUCCESS);

        default:
            break;
        }
    }

    if (!ovnsb_db) {
        ovnsb_db = default_sb_db();
    }

    if (!ovnnb_db) {
        ovnnb_db = default_nb_db();
    }

    if (!ovn_ic_sb_db) {
        ovn_ic_sb_db = default_ic_sb_db();
    }

    if (!ovn_ic_nb_db) {
        ovn_ic_nb_db = default_ic_nb_db();
    }

    free(short_options);
}

static void OVS_UNUSED
add_column_noalert(struct ovsdb_idl *idl,
                   const struct ovsdb_idl_column *column)
{
    ovsdb_idl_add_column(idl, column);
    ovsdb_idl_omit_alert(idl, column);
}

static void
update_ssl_config(void)
{
    if (ssl_private_key_file && ssl_certificate_file) {
        stream_ssl_set_key_and_cert(ssl_private_key_file,
                                    ssl_certificate_file);
    }
    if (ssl_ca_cert_file) {
        stream_ssl_set_ca_cert_file(ssl_ca_cert_file, false);
    }
}

static void
update_idl_probe_interval(struct ovsdb_idl *ovn_sb_idl,
                          struct ovsdb_idl *ovn_nb_idl,
                          struct ovsdb_idl *ovn_icsb_idl,
                          struct ovsdb_idl *ovn_icnb_idl)
{
    const struct nbrec_nb_global *nb = nbrec_nb_global_first(ovn_nb_idl);
    int interval = -1;
    if (nb) {
        interval = smap_get_int(&nb->options, "ic_probe_interval", interval);
    }
    set_idl_probe_interval(ovn_sb_idl, ovnsb_db, interval);
    set_idl_probe_interval(ovn_nb_idl, ovnnb_db, interval);

    const struct icnbrec_ic_nb_global *icnb =
        icnbrec_ic_nb_global_first(ovn_icnb_idl);
    int ic_interval = -1;
    if (icnb) {
        ic_interval = smap_get_int(&icnb->options, "ic_probe_interval",
                                   ic_interval);
    }
    set_idl_probe_interval(ovn_icsb_idl, ovn_ic_sb_db, ic_interval);
    set_idl_probe_interval(ovn_icnb_idl, ovn_ic_nb_db, ic_interval);
}

int
main(int argc, char *argv[])
{
    int res = EXIT_SUCCESS;
    struct unixctl_server *unixctl;
    int retval;
    bool exiting;
    struct ic_state state;

    fatal_ignore_sigpipe();
    ovs_cmdl_proctitle_init(argc, argv);
    ovn_set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv);

    daemonize_start(false, false);

    char *abs_unixctl_path = get_abs_unix_ctl_path(unixctl_path);
    retval = unixctl_server_create(abs_unixctl_path, &unixctl);
    free(abs_unixctl_path);

    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, ovn_ic_exit, &exiting);
    unixctl_command_register("pause", "", 0, 0, ovn_ic_pause, &state);
    unixctl_command_register("resume", "", 0, 0, ovn_ic_resume, &state);
    unixctl_command_register("is-paused", "", 0, 0, ovn_ic_is_paused, &state);
    unixctl_command_register("status", "", 0, 0, ovn_ic_status, &state);

    daemonize_complete();

    /* ovn-ic-nb db. */
    struct ovsdb_idl_loop ovninb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovn_ic_nb_db, &icnbrec_idl_class, true, true));
    ovsdb_idl_track_add_all(ovninb_idl_loop.idl);

    /* ovn-ic-sb db. */
    struct ovsdb_idl_loop ovnisb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovn_ic_sb_db, &icsbrec_idl_class, true, true));
    ovsdb_idl_track_add_all(ovnisb_idl_loop.idl);

    /* ovn-nb db. */
    struct ovsdb_idl_loop ovnnb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnnb_db, &nbrec_idl_class, false, true));

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_nb_global);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_nb_global_col_name);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_nb_global_col_options);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl,
                        &nbrec_table_logical_router_static_route);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_route_table);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_ip_prefix);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_nexthop);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_external_ids);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_options);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_policy);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_logical_router);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_name);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_static_routes);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_ports);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_options);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_external_ids);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_enabled);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_load_balancer);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_load_balancer_group);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_logical_router_port);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_port_col_mac);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_port_col_name);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_port_col_networks);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_port_col_external_ids);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_port_col_options);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_logical_switch);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_col_name);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_col_ports);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_col_other_config);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_col_external_ids);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_logical_switch_port);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_name);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_addresses);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_options);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_type);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_up);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_addresses);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_enabled);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_external_ids);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_load_balancer);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_load_balancer_col_vips);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_load_balancer_group);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_load_balancer_group_col_load_balancer);

    /* ovn-sb db. */
    struct ovsdb_idl_loop ovnsb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnsb_db, &sbrec_idl_class, false, true));

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_sb_global);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_sb_global_col_options);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_chassis);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_chassis_col_encaps);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_chassis_col_name);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_chassis_col_hostname);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_chassis_col_other_config);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_encap);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_encap_col_chassis_name);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_encap_col_type);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_encap_col_ip);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_encap_col_options);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_datapath_binding);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_datapath_binding_col_type);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_datapath_binding_col_external_ids);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_datapath_binding_col_nb_uuid);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_port_binding);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_datapath);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_mac);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_options);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_logical_port);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_external_ids);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_chassis);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_up);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_service_monitor);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_chassis_name);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_external_ids);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_type);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_ip);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_logical_port);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_port);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_protocol);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_src_ip);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_src_mac);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_remote);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_ic_learned);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_status);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_options);

    unixctl_command_register("nb-connection-status", "", 0, 0,
                             ovn_conn_show, ovnnb_idl_loop.idl);
    unixctl_command_register("sb-connection-status", "", 0, 0,
                             ovn_conn_show, ovnsb_idl_loop.idl);
    unixctl_command_register("ic-nb-connection-status", "", 0, 0,
                             ovn_conn_show, ovninb_idl_loop.idl);
    unixctl_command_register("ic-sb-connection-status", "", 0, 0,
                             ovn_conn_show, ovnisb_idl_loop.idl);

    stopwatch_create(OVN_IC_LOOP_STOPWATCH_NAME, SW_MS);
    stopwatch_create(IC_OVN_DB_RUN_STOPWATCH_NAME, SW_MS);
    stopwatch_create(OVN_IC_ENUM_DATAPATHS_RUN_STOPWATCH_NAME, SW_MS);
    stopwatch_create(OVN_IC_PORT_BINDING_RUN_STOPWATCH_NAME, SW_MS);
    stopwatch_create(OVN_IC_ROUTE_RUN_STOPWATCH_NAME, SW_MS);
    stopwatch_create(OVN_IC_GATEWAY_RUN_STOPWATCH_NAME, SW_MS);

    /* Initialize incremental processing engine for ovn-northd */
    inc_proc_ic_init(&ovnnb_idl_loop, &ovnsb_idl_loop,
                     &ovninb_idl_loop, &ovnisb_idl_loop);

    unsigned int ovnnb_cond_seqno = UINT_MAX;
    unsigned int ovnsb_cond_seqno = UINT_MAX;
    unsigned int ovninb_cond_seqno = UINT_MAX;
    unsigned int ovnisb_cond_seqno = UINT_MAX;

    /* Main loop. */
    struct ic_engine_context  eng_ctx = {0};

    exiting = false;
    state.had_lock = false;
    state.paused = false;

    while (!exiting) {
        update_ssl_config();
        update_idl_probe_interval(ovnsb_idl_loop.idl, ovnnb_idl_loop.idl,
                                  ovnisb_idl_loop.idl, ovninb_idl_loop.idl);
        memory_run();
        if (memory_should_report()) {
            struct simap usage = SIMAP_INITIALIZER(&usage);

            /* Nothing special to report yet. */
            memory_report(&usage);
            simap_destroy(&usage);
        }

        bool clear_idl_track = true;
        if (!state.paused) {
            if (!ovsdb_idl_has_lock(ovnsb_idl_loop.idl) &&
                !ovsdb_idl_is_lock_contended(ovnsb_idl_loop.idl))
            {
                /* Ensure that only a single ovn-ic is active in the deployment
                 * by acquiring a lock called "ovn_ic" on the southbound
                 * database and then only performing DB transactions if the
                 * lock is held. */
                ovsdb_idl_set_lock(ovnsb_idl_loop.idl, "ovn_ic");
            }

            struct ovsdb_idl_txn *ovnnb_txn =
                run_idl_loop(&ovnnb_idl_loop, "OVN_Northbound",
                             &eng_ctx.nb_idl_duration_ms);
            unsigned int new_ovnnb_cond_seqno =
                        ovsdb_idl_get_condition_seqno(ovnnb_idl_loop.idl);
            if (new_ovnnb_cond_seqno != ovnnb_cond_seqno) {
                if (!new_ovnnb_cond_seqno) {
                    VLOG_INFO("OVN NB IDL reconnected, force recompute.");
                    inc_proc_ic_force_recompute();
                }
                ovnnb_cond_seqno = new_ovnnb_cond_seqno;
            }

            struct ovsdb_idl_txn *ovnsb_txn =
                run_idl_loop(&ovnsb_idl_loop, "OVN_Southbound",
                             &eng_ctx.sb_idl_duration_ms);
            unsigned int new_ovnsb_cond_seqno =
                        ovsdb_idl_get_condition_seqno(ovnsb_idl_loop.idl);
            if (new_ovnsb_cond_seqno != ovnsb_cond_seqno) {
                if (!new_ovnsb_cond_seqno) {
                    VLOG_INFO("OVN SB IDL reconnected, force recompute.");
                    inc_proc_ic_force_recompute();
                }
                ovnsb_cond_seqno = new_ovnsb_cond_seqno;
            }

            struct ovsdb_idl_txn *ovninb_txn =
                run_idl_loop(&ovninb_idl_loop, "OVN_IC_Northbound",
                             &eng_ctx.inb_idl_duration_ms);
            unsigned int new_ovninb_cond_seqno =
                        ovsdb_idl_get_condition_seqno(ovninb_idl_loop.idl);
            if (new_ovninb_cond_seqno != ovninb_cond_seqno) {
                if (!new_ovninb_cond_seqno) {
                    VLOG_INFO("OVN INB IDL reconnected, force recompute.");
                    inc_proc_ic_force_recompute();
                }
                ovninb_cond_seqno = new_ovninb_cond_seqno;
            }

            struct ovsdb_idl_txn *ovnisb_txn =
                run_idl_loop(&ovnisb_idl_loop, "OVN_IC_Southbound",
                             &eng_ctx.isb_idl_duration_ms);
            unsigned int new_ovnisb_cond_seqno =
                        ovsdb_idl_get_condition_seqno(ovnisb_idl_loop.idl);
            if (new_ovnisb_cond_seqno != ovnisb_cond_seqno) {
                if (!new_ovnisb_cond_seqno) {
                    VLOG_INFO("OVN ISB IDL reconnected, force recompute.");
                    inc_proc_ic_force_recompute();
                }
                ovnisb_cond_seqno = new_ovnisb_cond_seqno;
            }

            if (!state.had_lock && ovsdb_idl_has_lock(ovnsb_idl_loop.idl)) {
                VLOG_INFO("ovn-ic lock acquired. "
                            "This ovn-ic instance is now active.");
                state.had_lock = true;
            } else if (state.had_lock &&
                       !ovsdb_idl_has_lock(ovnsb_idl_loop.idl)) {
                VLOG_INFO("ovn-ic lock lost. "
                            "This ovn-ic instance is now on standby.");
                state.had_lock = false;
            }

            if (ovsdb_idl_has_lock(ovnsb_idl_loop.idl) &&
                ovsdb_idl_has_ever_connected(ovnnb_idl_loop.idl) &&
                ovsdb_idl_has_ever_connected(ovnsb_idl_loop.idl) &&
                ovsdb_idl_has_ever_connected(ovninb_idl_loop.idl) &&
                ovsdb_idl_has_ever_connected(ovnisb_idl_loop.idl)) {
                if (ovnnb_txn && ovnsb_txn && ovninb_txn &&
                    ovnisb_txn && inc_proc_ic_can_run(&eng_ctx)) {
                    const struct icsbrec_availability_zone *az =
                        az_run(ovnnb_idl_loop.idl,
                               ovnisb_idl_loop.idl,
                               ovnisb_txn);
                    VLOG_DBG("Availability zone: %s", az ?
                             az->name : "not created yet.");
                    if (az) {
                        (void) inc_proc_ic_run(ovnnb_txn,
                                               ovnsb_txn,
                                               ovninb_txn,
                                               ovnisb_txn,
                                               &eng_ctx,
                                               az);
                        update_sequence_numbers(ovninb_idl_loop.idl,
                                                ovnisb_idl_loop.idl,
                                                ovninb_txn,
                                                ovnisb_txn,
                                                &ovnisb_idl_loop,
                                                az);
                    }
                } else if (!inc_proc_ic_get_force_recompute()) {
                    clear_idl_track = false;
                }
                /* If there are any errors, we force a full recompute in order
                 * to ensure we handle all changes. */
                if (!ovsdb_idl_loop_commit_and_wait(&ovnnb_idl_loop)) {
                    VLOG_INFO("OVNNB commit failed, "
                                "force recompute next time.");
                    inc_proc_ic_force_recompute_immediate();
                }

                if (!ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop)) {
                    VLOG_INFO("OVNSB commit failed, "
                                "force recompute next time.");
                    inc_proc_ic_force_recompute_immediate();
                }

                if (!ovsdb_idl_loop_commit_and_wait(&ovninb_idl_loop)) {
                    VLOG_INFO("OVNINB commit failed, "
                                "force recompute next time.");
                    inc_proc_ic_force_recompute_immediate();
                }

                if (!ovsdb_idl_loop_commit_and_wait(&ovnisb_idl_loop)) {
                    VLOG_INFO("OVNISB commit failed, "
                                "force recompute next time.");
                    inc_proc_ic_force_recompute_immediate();
                }
            } else {
                /* Make sure we send any pending requests, e.g., lock. */
                int rc1 = ovsdb_idl_loop_commit_and_wait(&ovnnb_idl_loop);
                int rc2 = ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop);
                int rc3 = ovsdb_idl_loop_commit_and_wait(&ovninb_idl_loop);
                int rc4 = ovsdb_idl_loop_commit_and_wait(&ovnisb_idl_loop);
                if (!rc1 || !rc2 || !rc3 || !rc4) {
                    VLOG_DBG(" a transaction failed in: %s %s %s %s",
                            !rc1 ? "nb" : "", !rc2 ? "sb" : "",
                            !rc3 ? "ic_nb" : "", !rc4 ? "ic_sb" : "");
                    /* A transaction failed. Wake up immediately to give
                    * opportunity to send the proper transaction
                    */
                }
                /* Force a full recompute next time we become active. */
                inc_proc_ic_force_recompute();
            }
        } else {
            /* ovn-ic is paused
             *    - we still want to handle any db updates and update the
             *      local IDL. Otherwise, when it is resumed, the local IDL
             *      copy will be out of sync.
             *    - but we don't want to create any txns.
             * */
            if (ovsdb_idl_has_lock(ovnsb_idl_loop.idl) ||
                ovsdb_idl_is_lock_contended(ovnsb_idl_loop.idl))
            {
                /* make sure we don't hold the lock while paused */
                VLOG_INFO("This ovn-ic instance is now paused.");
                ovsdb_idl_set_lock(ovnsb_idl_loop.idl, NULL);
                state.had_lock = false;
            }

            ovsdb_idl_run(ovnnb_idl_loop.idl);
            ovsdb_idl_run(ovnsb_idl_loop.idl);
            ovsdb_idl_run(ovninb_idl_loop.idl);
            ovsdb_idl_run(ovnisb_idl_loop.idl);
            ovsdb_idl_wait(ovnnb_idl_loop.idl);
            ovsdb_idl_wait(ovnsb_idl_loop.idl);
            ovsdb_idl_wait(ovninb_idl_loop.idl);
            ovsdb_idl_wait(ovnisb_idl_loop.idl);

            /* Force a full recompute next time we become active. */
            inc_proc_ic_force_recompute_immediate();
        }

        if (clear_idl_track) {
            ovsdb_idl_track_clear(ovnnb_idl_loop.idl);
            ovsdb_idl_track_clear(ovnsb_idl_loop.idl);
            ovsdb_idl_track_clear(ovninb_idl_loop.idl);
            ovsdb_idl_track_clear(ovnisb_idl_loop.idl);
        }

        unixctl_server_run(unixctl);
        unixctl_server_wait(unixctl);
        memory_wait();
        if (exiting) {
            poll_immediate_wake();
        }

        stopwatch_stop(NORTHD_LOOP_STOPWATCH_NAME, time_msec());
        poll_block();
        if (should_service_stop()) {
            exiting = true;
        }
        stopwatch_start(NORTHD_LOOP_STOPWATCH_NAME, time_msec());
    }
    inc_proc_ic_cleanup();

    unixctl_server_destroy(unixctl);
    ovsdb_idl_loop_destroy(&ovnnb_idl_loop);
    ovsdb_idl_loop_destroy(&ovnsb_idl_loop);
    ovsdb_idl_loop_destroy(&ovninb_idl_loop);
    ovsdb_idl_loop_destroy(&ovnisb_idl_loop);
    service_stop();

    exit(res);
}

static void
ovn_ic_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
            const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;

    unixctl_command_reply(conn, NULL);
}

static void
ovn_ic_pause(struct unixctl_conn *conn, int argc OVS_UNUSED,
             const char *argv[] OVS_UNUSED, void *state_)
{
    struct ic_state *state = state_;
    state->paused = true;

    unixctl_command_reply(conn, NULL);
}

static void
ovn_ic_resume(struct unixctl_conn *conn, int argc OVS_UNUSED,
              const char *argv[] OVS_UNUSED, void *state_)
{
    struct ic_state *state = state_;
    state->paused = false;
    poll_immediate_wake();
    unixctl_command_reply(conn, NULL);
}

static void
ovn_ic_is_paused(struct unixctl_conn *conn, int argc OVS_UNUSED,
                 const char *argv[] OVS_UNUSED, void *state_)
{
    struct ic_state *state = state_;
    if (state->paused) {
        unixctl_command_reply(conn, "true");
    } else {
        unixctl_command_reply(conn, "false");
    }
}

static void
ovn_ic_status(struct unixctl_conn *conn, int argc OVS_UNUSED,
              const char *argv[] OVS_UNUSED, void *state_)
{
    struct ic_state *state = state_;
    char *status;

    if (state->paused) {
        status = "paused";
    } else {
        status = state->had_lock ? "active" : "standby";
    }

    /*
     * Use a labelled formatted output so we can add more to the status
     * command later without breaking any consuming scripts
     */
    struct ds s = DS_EMPTY_INITIALIZER;
    ds_put_format(&s, "Status: %s\n", status);
    unixctl_command_reply(conn, ds_cstr(&s));
    ds_destroy(&s);
}
