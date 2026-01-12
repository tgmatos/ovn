#ifndef EN_IC_TR_RUN_H
#define EN_IC_TR_RUN_H 1

#include <config.h>

#include <stdbool.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

/* OVN includes. */
#include "lib/inc-proc-eng.h"

struct ed_type_transit_router {
    struct hmap dp_tnlids;
    struct shash isb_tr_dps;
};

void *en_tr_init(struct engine_node *, struct engine_arg *);
enum engine_node_state en_tr_run(struct engine_node *, void *data);
void en_tr_cleanup(void *data);

#endif
