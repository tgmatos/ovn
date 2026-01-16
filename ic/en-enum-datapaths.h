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

struct enum_datapaths_tracked {
    struct shash crupdated_ls;
    struct shash deleted_ls;

    struct shash crupdated_datapaths;
    struct shash deleted_datapaths;
};

/* struct which maintains the data of the engine node enumerate datapaths. */
struct ed_type_enum_datapaths {
    struct hmap dp_tnlids;
    struct shash isb_ts_dps;
    struct shash isb_tr_dps;
    bool tracked;
    struct enum_datapaths_tracked tracked_data;
};

void *en_enum_datapaths_init(struct engine_node *, struct engine_arg *);
enum engine_node_state en_enum_datapaths_run(struct engine_node *, void *data);
void en_enum_datapaths_cleanup(void *data);
void en_enum_datapaths_clear_tracked_data(void *data);

enum engine_input_handler_result
    icsb_datapath_binding_handler(struct engine_node *, void *data);
enum engine_input_handler_result
    nb_logical_switch_handler(struct engine_node *, void *data);

#endif
