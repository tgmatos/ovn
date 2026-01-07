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
};

void *en_enum_datapaths_init(struct engine_node *, struct engine_arg *);
enum engine_node_state en_enum_datapaths_run(struct engine_node *, void *data);
void en_enum_datapaths_cleanup(void *data);

#endif