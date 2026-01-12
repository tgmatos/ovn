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
    bool tracked;

    struct hmap tracked_data;
};

struct gateway_input {
    /* Table references */
    const struct icsbrec_gateway_table *icsbrec_gateway_table;
    const struct sbrec_chassis_table *sb_chassis_table;

    /* Indexes */
    const struct icsbrec_availability_zone *runned_az;
};

enum ic_gw_change_type {
    IC_GW_ADD,
    IC_GW_UPDATE,
    IC_GW_DELETE
};

struct gateway_tracked {
    struct hmap_node node;
    enum ic_gw_change_type change_type;
};

void *en_gateway_init(struct engine_node *, struct engine_arg *);
enum engine_node_state en_gateway_run(struct engine_node *, void *data);
void en_gateway_cleanup(void *data);
void en_gateway_clear_tracked_data(void *data);

#endif
