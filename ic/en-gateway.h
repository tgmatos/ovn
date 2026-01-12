#ifndef EN_IC_GATEWAY_H
#define EN_IC_GATEWAY_H 1

#include <config.h>

#include <stdbool.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

/* OVN includes. */
#include "lib/inc-proc-eng.h"

struct ed_type_gateway {
    struct shash local_gws;
    struct shash remote_gws;
};

struct gateway_input {
    /* Indexes */
    const struct icsbrec_availability_zone *runned_az;
};

void *en_gateway_init(struct engine_node *, struct engine_arg *);
enum engine_node_state en_gateway_run(struct engine_node *, void *data);
void en_gateway_cleanup(void *data);

#endif
