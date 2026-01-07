#ifndef EN_IC_ENUM_DATAPATHS_H
#define EN_IC_ENUM_DATAPATHS_H 1

#include <config.h>

#include <stdbool.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

/* OVS includes. */
#include "lib/hmapx.h"
#include "openvswitch/hmap.h"
#include "openvswitch/shash.h"

/* OVN includes. */
#include "lib/inc-proc-eng.h"

/* struct which maintains the data of the engine node enumerate datapaths. */
struct ed_type_enum_datapaths {
    struct hmap dp_tnlids;
    struct shash isb_ts_dps;
    struct shash isb_tr_dps;
    bool tracked;

    struct hmap tracked_data;
};

enum ic_db_change_type {
    IC_DB_ADD,
    IC_DB_UPDATE,
    IC_DB_DELETE
};

struct enum_datapaths_tracked {
    struct hmap_node node;
    const struct icsbrec_datapath_binding *isb_dp;
    const struct nbrec_logical_switch *nb_ls;
    const struct icnbrec_transit_switch *nb_ic_ts;
    enum ic_db_change_type change_type;
};

void *en_enum_datapaths_init(struct engine_node *, struct engine_arg *);
enum engine_node_state en_enum_datapaths_run(struct engine_node *, void *data);
void en_enum_datapaths_cleanup(void *data);
void en_enum_datapaths_clear_tracked_data(void *data);

enum engine_input_handler_result
    icsb_datapath_binding_handler(struct engine_node *, void *data);
enum engine_input_handler_result
    nb_logical_switch_handler(struct engine_node *, void *data);
enum engine_input_handler_result
    icnb_transit_switch_handler(struct engine_node *, void *data);

#endif