#ifndef EN_IC_ROUTE_H
#define EN_IC_ROUTE_H 1

#include <config.h>

#include <stdbool.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include "vec.h"

/* OVN includes. */
#include "lib/inc-proc-eng.h"

struct ed_type_route {
    struct hmap pb_tnlids;
    struct shash switch_all_local_pbs;
    struct shash router_all_local_pbs;
};

struct ic_router_info {
    struct hmap_node node;
    const struct nbrec_logical_router *lr; /* key of hmap */
    struct vector isb_pbs; /* Vector of const struct icsbrec_port_binding *. */
    struct hmap routes_learned;
};

/* Represents an interconnection route entry. */
struct ic_route_info {
    struct hmap_node node;
    struct in6_addr prefix;
    unsigned int plen;
    struct in6_addr nexthop;
    const char *origin;
    const char *route_table;
    const char *route_tag;

    const struct nbrec_logical_router *nb_lr;

    /* One of nb_route, nb_lrp, nb_lb is set and the other ones must be NULL.
     * - For a route that is learned from IC-SB, or a static route that is
     *   generated from a route that is configured in NB, the "nb_route"
     *   is set.
     * - For a route that is generated from a direct-connect subnet of
     *   a logical router port, the "nb_lrp" is set.
     * - For a route that is generated from a load-balancer vip of
     *   a logical router, the "nb_lb" is set. */
    const struct nbrec_logical_router_static_route *nb_route;
    const struct nbrec_logical_router_port *nb_lrp;
    const struct nbrec_load_balancer *nb_lb;
};

struct route_input {
    /* Indexes */
    const struct icsbrec_availability_zone *runned_az;
    struct ovsdb_idl_index *nbrec_ls_by_name;
    struct ovsdb_idl_index *nbrec_port_by_name;
    struct ovsdb_idl_index *nbrec_lrp_by_name;
    struct ovsdb_idl_index *icsbrec_route_by_az;
    struct ovsdb_idl_index *icsbrec_route_by_ts;
    struct ovsdb_idl_index *icsbrec_route_by_ts_az;
    struct ovsdb_idl_index *icsbrec_port_binding_by_az;
    struct ovsdb_idl_index *icnbrec_transit_switch_by_name;
};

void *en_route_init(struct engine_node *, struct engine_arg *);
enum engine_node_state en_route_run(struct engine_node *, void *data);
void en_route_cleanup(void *data);

#endif
