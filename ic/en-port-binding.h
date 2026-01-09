#ifndef EN_IC_PORT_BINDING_H
#define EN_IC_PORT_BINDING_H 1

#include <config.h>

#include <stdbool.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

/* OVN includes. */
#include "lib/inc-proc-eng.h"

struct ed_type_port_binding {
    struct hmap pb_tnlids;
    struct shash switch_all_local_pbs;
    struct shash router_all_local_pbs;
};

struct pb_input {
    /* Indexes */
    const struct icsbrec_availability_zone *runned_az;
    struct ovsdb_idl_index *nbrec_ls_by_name;
    struct ovsdb_idl_index *nbrec_port_by_name;
    struct ovsdb_idl_index *nbrec_lr_by_name;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    struct ovsdb_idl_index *sbrec_chassis_by_name;
    struct ovsdb_idl_index *icsbrec_port_binding_by_az;
    struct ovsdb_idl_index *icsbrec_port_binding_by_ts;
};

void *en_port_binding_init(struct engine_node *, struct engine_arg *);
enum engine_node_state en_port_binding_run(struct engine_node *, void *data);
void en_port_binding_cleanup(void *data);

#endif
