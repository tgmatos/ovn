#ifndef EN_IC_SRV_MONITOR_RUN_H
#define EN_IC_SRV_MONITOR_RUN_H 1

#include <config.h>

#include <stdbool.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

/* OVS includes. */
#include "openvswitch/hmap.h"

/* OVN includes. */
#include "lib/inc-proc-eng.h"

/*
 * Data structures and functions related to
 * synchronize health checks for load balancers
 * between availability zones.
 */
struct ed_type_sync_service_monitor {
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

    bool tracked;
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

struct srv_mon_input {
    /* Indexes */
    const struct icsbrec_availability_zone *runned_az;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    struct ovsdb_idl_index *sbrec_service_monitor_by_remote_type;
    struct ovsdb_idl_index *sbrec_service_monitor_by_ic_learned;
    struct ovsdb_idl_index *sbrec_service_monitor_by_remote_type_logical_port;
    struct ovsdb_idl_index *icsbrec_service_monitor_by_source_az;
    struct ovsdb_idl_index *icsbrec_service_monitor_by_target_az;
    struct ovsdb_idl_index *icsbrec_service_monitor_by_target_az_logical_port;
};

void *en_srv_mon_init(struct engine_node *, struct engine_arg *);
enum engine_node_state en_srv_mon_run(struct engine_node *, void *data);
void en_srv_mon_cleanup(void *data);

#endif
