/*
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
#include "vec.h"

/* OVS includes. */
#include "openvswitch/vlog.h"

/* OVN includes. */
#include "ovn-ic.h"
#include "en-route.h"
#include "inc-proc-ic.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-ic-nb-idl.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-util.h"
#include "lib/stopwatch-names.h"
#include "coverage.h"
#include "stopwatch.h"
#include "stopwatch-names.h"

VLOG_DEFINE_THIS_MODULE(en_route);
COVERAGE_DEFINE(route_run);

static void
route_run(const struct engine_context *eng_ctx,
          struct route_input *route_input,
          struct ed_type_route *route_data,
          const struct nbrec_logical_router_table *nb_lr_table,
          const struct nbrec_nb_global_table *nb_global_table);
static void route_init(struct ed_type_route *data);
static void route_destroy(struct ed_type_route *data);
static void route_clear(struct ed_type_route *data);
static void route_get_input_data(struct engine_node *node,
                                        struct route_input *input_data);

static uint32_t
    ic_route_hash(const struct in6_addr *prefix, unsigned int plen,
                  const struct in6_addr *nexthop, const char *origin,
                  const char *route_table);
static struct ic_route_info *
    ic_route_find(struct hmap *routes, const struct in6_addr *prefix,
                  unsigned int plen, const struct in6_addr *nexthop,
                  const char *origin, const char *route_table, uint32_t hash);
static struct ic_router_info *
    ic_router_find(struct hmap *ic_lrs, const struct nbrec_logical_router *lr);
static bool
    parse_route(const char *s_prefix, const char *s_nexthop,
                struct in6_addr *prefix, unsigned int *plen,
                struct in6_addr *nexthop);
static bool
    add_to_routes_learned(struct hmap *routes_learned,
                      const struct nbrec_logical_router_static_route *nb_route,
                      const struct nbrec_logical_router *nb_lr);
static bool
    get_nexthop_from_lport_addresses(bool is_v4,
                                     const struct lport_addresses *laddr,
                                     struct in6_addr *nexthop);
static bool
    prefix_is_filtered(struct in6_addr *prefix,
                       unsigned int plen,
                       const struct nbrec_logical_router *nb_lr,
                       const struct nbrec_logical_router_port *ts_lrp,
                       bool is_advertisement);
static bool
    prefix_is_deny_filtered(struct in6_addr *prefix,
                            unsigned int plen,
                            const struct smap *nb_options,
                            const struct nbrec_logical_router *nb_lr,
                            const struct nbrec_logical_router_port *ts_lrp,
                            bool is_advertisement);
static bool
    route_need_advertise(const char *policy,
                         struct in6_addr *prefix,
                         unsigned int plen,
                         const struct smap *nb_options,
                         const struct nbrec_logical_router *nb_lr,
                         const struct nbrec_logical_router_port *ts_lrp);
static void
    add_to_routes_ad(struct hmap *routes_ad, const struct in6_addr prefix,
                     unsigned int plen, const struct in6_addr nexthop,
                     const char *origin, const char *route_table,
                     const struct nbrec_logical_router_port *nb_lrp,
                     const struct nbrec_logical_router_static_route *nb_route,
                     const struct nbrec_logical_router *nb_lr,
                     const struct nbrec_load_balancer *nb_lb,
                     const char *route_tag);
static void
    add_static_to_routes_ad(struct hmap *routes_ad,
        const struct nbrec_logical_router_static_route *nb_route,
        const struct nbrec_logical_router *nb_lr,
        const struct lport_addresses *nexthop_addresses,
        const struct smap *nb_options,
        const char *route_tag,
        const struct nbrec_logical_router_port *ts_lrp);
static void
    add_network_to_routes_ad(struct hmap *routes_ad, const char *network,
                            const struct nbrec_logical_router_port *nb_lrp,
                            const struct lport_addresses *nexthop_addresses,
                            const struct smap *nb_options,
                            const struct nbrec_logical_router *nb_lr,
                            const char *route_tag,
                            const struct nbrec_logical_router_port *ts_lrp);
static void
    add_lb_vip_to_routes_ad(struct hmap *routes_ad, const char *vip_key,
                            const struct nbrec_load_balancer *nb_lb,
                            const struct lport_addresses *nexthop_addresses,
                            const struct smap *nb_options,
                            const struct nbrec_logical_router *nb_lr,
                            const char *route_tag,
                            const struct nbrec_logical_router_port *ts_lrp);
static bool
    route_has_local_gw(const struct nbrec_logical_router *lr,
                       const char *route_table, const char *ip_prefix);
static bool
    lrp_has_neighbor_in_ts(const struct nbrec_logical_router_port *lrp,
                           struct in6_addr *nexthop);
static bool
    route_matches_local_lb(const struct nbrec_load_balancer *nb_lb,
                           const char *ip_prefix);
static bool
    route_need_learn(const struct nbrec_logical_router *lr,
                     const struct icsbrec_route *isb_route,
                     struct in6_addr *prefix, unsigned int plen,
                     const struct smap *nb_options,
                     const struct nbrec_logical_router_port *ts_lrp,
                     struct in6_addr *nexthop);
static const char *
    get_lrp_name_by_ts_port_name(struct route_input *ic,
                                 const char *ts_port_name);
static const struct nbrec_logical_router_port *
    find_lrp_of_nexthop(struct route_input *ic,
                        const struct icsbrec_route *isb_route);
static bool
    lrp_is_ts_port(struct route_input *ic, struct ic_router_info *ic_lr,
                   const char *lrp_name);
static void
    sync_learned_routes(const struct engine_context *ctx,
                        struct route_input *ic, struct ic_router_info *ic_lr,
                        const struct nbrec_nb_global_table *nb_global_table);
static void
    ad_route_sync_external_ids(const struct ic_route_info *route_adv,
                               const struct icsbrec_route *isb_route);
static void
    advertise_routes(const struct engine_context *ctx,
                     struct route_input *ic,
                     const struct icsbrec_availability_zone *az,
                     const char *ts_name, struct hmap *routes_ad);
static void
    build_ts_routes_to_adv(struct route_input *ic,
                           struct ic_router_info *ic_lr,
                           struct hmap *routes_ad,
                           struct lport_addresses *ts_port_addrs,
                           const struct nbrec_nb_global *nb_global,
                           const char *ts_route_table,
                           const char *route_tag,
                           const struct nbrec_logical_router_port *ts_lrp);
static void
    collect_lr_routes(struct route_input *ic,
                      struct ic_router_info *ic_lr,
                      struct shash *routes_ad_by_ts,
                      const struct nbrec_nb_global_table *nb_global_table);
static void
    delete_orphan_ic_routes(struct route_input *ic,
                            const struct icsbrec_availability_zone *az);

static void
route_get_input_data(struct engine_node *node,
                     struct route_input *input_data)
{
    /* Indexes */
    input_data->nbrec_ls_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("NB_logical_switch", node),
            "nbrec_ls_by_name");
    input_data->nbrec_port_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("NB_logical_switch", node),
            "nbrec_port_by_name");
    input_data->nbrec_lrp_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("NB_logical_router", node),
            "nbrec_lrp_by_name");
    input_data->icnbrec_transit_switch_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("ICNB_transit_switch", node),
            "icnbrec_transit_switch_by_name");
    input_data->icsbrec_port_binding_by_az =
        engine_ovsdb_node_get_index(
            engine_get_input("ICSB_port_binding", node),
            "icsbrec_port_binding_by_az");
    input_data->icsbrec_route_by_az =
        engine_ovsdb_node_get_index(
            engine_get_input("ICSB_route", node),
            "icsbrec_route_by_az");
    input_data->icsbrec_route_by_ts =
        engine_ovsdb_node_get_index(
            engine_get_input("ICSB_route", node),
            "icsbrec_route_by_ts");
    input_data->icsbrec_route_by_ts_az =
        engine_ovsdb_node_get_index(
            engine_get_input("ICSB_route", node),
            "icsbrec_route_by_ts_az");
}

enum engine_node_state
en_route_run(struct engine_node *node, void *data)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ed_type_route *route_data = data;
    struct route_input route_input;

    route_clear(route_data);

    const struct nbrec_logical_router_table *nb_lr_table =
        EN_OVSDB_GET(engine_get_input("NB_logical_router", node));
    const struct nbrec_nb_global_table *nb_global_table =
        EN_OVSDB_GET(engine_get_input("NB_nb_global", node));

    route_get_input_data(node, &route_input);
    route_input.runned_az = eng_ctx->client_ctx;

    COVERAGE_INC(route_run);
    stopwatch_start(OVN_IC_ROUTE_RUN_STOPWATCH_NAME, time_usec());
    route_run(eng_ctx, &route_input, route_data, nb_lr_table, nb_global_table);
    stopwatch_stop(OVN_IC_ROUTE_RUN_STOPWATCH_NAME, time_usec());

    return EN_UPDATED;
}

void *
en_route_init(struct engine_node *node OVS_UNUSED,
              struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_route *data = xzalloc(sizeof *data);
    route_init(data);
    return data;
}

void
en_route_cleanup(void *data)
{
    route_destroy(data);
}

static void
route_init(struct ed_type_route *data)
{
    hmap_init(&data->pb_tnlids);
    shash_init(&data->switch_all_local_pbs);
    shash_init(&data->router_all_local_pbs);
}

static void
route_destroy(struct ed_type_route *data)
{
    route_clear(data);
    ovn_destroy_tnlids(&data->pb_tnlids);

    shash_destroy(&data->switch_all_local_pbs);
    shash_destroy(&data->router_all_local_pbs);
}

static void
route_clear(struct ed_type_route *data)
{
    ovn_destroy_tnlids(&data->pb_tnlids);
    hmap_init(&data->pb_tnlids);

    shash_clear(&data->switch_all_local_pbs);
    shash_clear(&data->router_all_local_pbs);
}

static void
route_run(const struct engine_context *eng_ctx,
          struct route_input *route_input,
          struct ed_type_route *route_data OVS_UNUSED,
          const struct nbrec_logical_router_table *nb_lr_table,
          const struct nbrec_nb_global_table *nb_global_table)
{
    if (!eng_ctx->ovnisb_idl_txn || !eng_ctx->ovnnb_idl_txn) {
        return;
    }

    delete_orphan_ic_routes(route_input, route_input->runned_az);

    struct hmap ic_lrs = HMAP_INITIALIZER(&ic_lrs);
    const struct icsbrec_port_binding *isb_pb;
    const struct icsbrec_port_binding *isb_pb_key =
        icsbrec_port_binding_index_init_row(
            route_input->icsbrec_port_binding_by_az);
    icsbrec_port_binding_index_set_availability_zone(isb_pb_key,
        route_input->runned_az);

    /* Each port on TS maps to a logical router, which is stored in the
     * external_ids:router-id of the IC SB port_binding record.
     * Here we build info for interconnected Logical Router:
     * collect IC Port Binding to process routes sync later on. */
    ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (isb_pb, isb_pb_key,
        route_input->icsbrec_port_binding_by_az)
    {
        if (ic_pb_get_type(isb_pb) == IC_ROUTER_PORT) {
            continue;
        }
        const struct nbrec_logical_switch_port *nb_lsp;

        nb_lsp = get_lsp_by_ts_port_name(route_input->nbrec_port_by_name,
                                         isb_pb->logical_port);
        if (!strcmp(nb_lsp->type, "switch")) {
            VLOG_DBG("IC-SB Port_Binding '%s' on ts '%s' corresponds to a "
                     "switch port, not considering for route collection.",
                     isb_pb->logical_port, isb_pb->transit_switch);
            continue;
        }

        const char *ts_lrp_name =
            get_lrp_name_by_ts_port_name(route_input, isb_pb->logical_port);
        if (!ts_lrp_name) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "Route sync ignores port %s on ts %s because "
                         "logical router port is not found in NB. Deleting it",
                         isb_pb->logical_port, isb_pb->transit_switch);
            icsbrec_port_binding_delete(isb_pb);
            continue;
        }

        struct uuid lr_uuid;
        if (!smap_get_uuid(&isb_pb->external_ids, "router-id", &lr_uuid)) {
            VLOG_DBG("IC-SB Port_Binding %s doesn't have "
                     "external_ids:router-id set.", isb_pb->logical_port);
            continue;
        }

        const struct nbrec_logical_router *lr
            = nbrec_logical_router_table_get_for_uuid(nb_lr_table, &lr_uuid);
        if (!lr) {
            continue;
        }

        struct ic_router_info *ic_lr = ic_router_find(&ic_lrs, lr);
        if (!ic_lr) {
            ic_lr = xzalloc(sizeof *ic_lr);
            ic_lr->lr = lr;
            ic_lr->isb_pbs =
                VECTOR_EMPTY_INITIALIZER(const struct icsbrec_port_binding *);
            hmap_init(&ic_lr->routes_learned);
            hmap_insert(&ic_lrs, &ic_lr->node, uuid_hash(&lr->header_.uuid));
        }
        vector_push(&ic_lr->isb_pbs, &isb_pb);
    }
    icsbrec_port_binding_index_destroy_row(isb_pb_key);

    struct ic_router_info *ic_lr;
    struct shash routes_ad_by_ts = SHASH_INITIALIZER(&routes_ad_by_ts);
    HMAP_FOR_EACH_SAFE (ic_lr, node, &ic_lrs) {
        collect_lr_routes(route_input, ic_lr, &routes_ad_by_ts,
                          nb_global_table);
        sync_learned_routes(eng_ctx, route_input, ic_lr, nb_global_table);
        vector_destroy(&ic_lr->isb_pbs);
        hmap_destroy(&ic_lr->routes_learned);
        hmap_remove(&ic_lrs, &ic_lr->node);
        free(ic_lr);
    }
    struct shash_node *node;
    SHASH_FOR_EACH (node, &routes_ad_by_ts) {
        advertise_routes(eng_ctx, route_input, route_input->runned_az,
                         node->name, node->data);
        hmap_destroy(node->data);
    }
    shash_destroy_free_data(&routes_ad_by_ts);
    hmap_destroy(&ic_lrs);
}

static uint32_t
ic_route_hash(const struct in6_addr *prefix, unsigned int plen,
              const struct in6_addr *nexthop, const char *origin,
              const char *route_table)
{
    uint32_t basis = hash_bytes(prefix, sizeof *prefix, (uint32_t) plen);
    basis = hash_string(origin, basis);
    basis = hash_string(route_table, basis);
    return hash_bytes(nexthop, sizeof *nexthop, basis);
}

static struct ic_route_info *
ic_route_find(struct hmap *routes, const struct in6_addr *prefix,
              unsigned int plen, const struct in6_addr *nexthop,
              const char *origin, const char *route_table, uint32_t hash)
{
    struct ic_route_info *r;
    if (!hash) {
        hash = ic_route_hash(prefix, plen, nexthop, origin, route_table);
    }
    HMAP_FOR_EACH_WITH_HASH (r, node, hash, routes) {
        if (ipv6_addr_equals(&r->prefix, prefix) &&
            r->plen == plen &&
            ipv6_addr_equals(&r->nexthop, nexthop) &&
            !strcmp(r->origin, origin) &&
            !strcmp(r->route_table ? r->route_table : "", route_table)) {
            return r;
        }
    }
    return NULL;
}

static struct ic_router_info *
ic_router_find(struct hmap *ic_lrs, const struct nbrec_logical_router *lr)
{
    struct ic_router_info *ic_lr;
    HMAP_FOR_EACH_WITH_HASH (ic_lr, node, uuid_hash(&lr->header_.uuid),
                             ic_lrs) {
        if (ic_lr->lr == lr) {
           return ic_lr;
        }
    }
    return NULL;
}

static bool
parse_route(const char *s_prefix, const char *s_nexthop,
            struct in6_addr *prefix, unsigned int *plen,
            struct in6_addr *nexthop)
{
    if (!ip46_parse_cidr(s_prefix, prefix, plen)) {
        return false;
    }

    unsigned int nlen;
    if (strcmp(s_nexthop, "discard") &&
        !ip46_parse_cidr(s_nexthop, nexthop, &nlen)) {
        return false;
    }

    /* Do not learn routes with link-local next hop. */
    return !in6_is_lla(nexthop);
}

/* Return false if can't be added due to bad format. */
static bool
add_to_routes_learned(struct hmap *routes_learned,
                      const struct nbrec_logical_router_static_route *nb_route,
                      const struct nbrec_logical_router *nb_lr)
{
    struct in6_addr prefix, nexthop;
    unsigned int plen;
    if (!parse_route(nb_route->ip_prefix, nb_route->nexthop,
                     &prefix, &plen, &nexthop)) {
        return false;
    }
    const char *origin = smap_get_def(&nb_route->options, "origin", "");
    if (ic_route_find(routes_learned, &prefix, plen, &nexthop, origin,
                      nb_route->route_table, 0)) {
        /* Route was added to learned on previous iteration. */
        return true;
    }

    struct ic_route_info *ic_route = xzalloc(sizeof *ic_route);
    ic_route->prefix = prefix;
    ic_route->plen = plen;
    ic_route->nexthop = nexthop;
    ic_route->nb_route = nb_route;
    ic_route->origin = origin;
    ic_route->route_table = nb_route->route_table;
    ic_route->nb_lr = nb_lr;
    hmap_insert(routes_learned, &ic_route->node,
                ic_route_hash(&prefix, plen, &nexthop, origin,
                              nb_route->route_table));
    return true;
}

static bool
get_nexthop_from_lport_addresses(bool is_v4,
                                 const struct lport_addresses *laddr,
                                 struct in6_addr *nexthop)
{
    if (is_v4) {
        if (!laddr->n_ipv4_addrs) {
            return false;
        }
        in6_addr_set_mapped_ipv4(nexthop, laddr->ipv4_addrs[0].addr);
        return true;
    }

    /* ipv6 */
    if (laddr->n_ipv6_addrs) {
        *nexthop = laddr->ipv6_addrs[0].addr;
        return true;
    }

    /* ipv6 link local */
    in6_generate_lla(laddr->ea, nexthop);
    return true;
}

static bool
prefix_is_filtered(struct in6_addr *prefix,
                   unsigned int plen,
                   const struct nbrec_logical_router *nb_lr,
                   const struct nbrec_logical_router_port *ts_lrp,
                   bool is_advertisement)
{
    struct ds filter_list = DS_EMPTY_INITIALIZER;
    const char *filter_direction = is_advertisement ? "ic-route-filter-adv" :
                                                      "ic-route-filter-learn";
    if (ts_lrp) {
        const char *lrp_route_filter = smap_get(&ts_lrp->options,
                                                filter_direction);
        if (lrp_route_filter) {
            ds_put_format(&filter_list, "%s,", lrp_route_filter);
        }
    }
    const char *lr_route_filter = smap_get(&nb_lr->options,
                                           filter_direction);
    if (lr_route_filter) {
        ds_put_format(&filter_list, "%s,", lr_route_filter);
    }

    struct sset prefix_set = SSET_INITIALIZER(&prefix_set);
    sset_from_delimited_string(&prefix_set, ds_cstr(&filter_list), ",");

    bool matched = true;
    if (!sset_is_empty(&prefix_set)) {
        matched = find_prefix_in_set(prefix, plen, &prefix_set,
                                     filter_direction);
    }

    ds_destroy(&filter_list);
    sset_destroy(&prefix_set);
    return matched;
}

static bool
prefix_is_deny_filtered(struct in6_addr *prefix,
                        unsigned int plen,
                        const struct smap *nb_options,
                        const struct nbrec_logical_router *nb_lr,
                        const struct nbrec_logical_router_port *ts_lrp,
                        bool is_advertisement)
{
    struct ds deny_list = DS_EMPTY_INITIALIZER;
    const char *deny_key = is_advertisement ? "ic-route-deny-adv" :
                                              "ic-route-deny-learn";

    if (ts_lrp) {
        const char *lrp_deny_filter = smap_get(&ts_lrp->options, deny_key);
        if (lrp_deny_filter) {
            ds_put_format(&deny_list, "%s,", lrp_deny_filter);
        }
    }

    if (nb_lr) {
        const char *lr_deny_filter = smap_get(&nb_lr->options, deny_key);
        if (lr_deny_filter) {
            ds_put_format(&deny_list, "%s,", lr_deny_filter);
        }
    }

    if (nb_options) {
        const char *global_deny = smap_get(nb_options, "ic-route-denylist");
        if (!global_deny || !global_deny[0]) {
            global_deny = smap_get(nb_options, "ic-route-blacklist");
        }
        if (global_deny && global_deny[0]) {
            ds_put_format(&deny_list, "%s,", global_deny);
        }
    }

    struct sset prefix_set = SSET_INITIALIZER(&prefix_set);
    sset_from_delimited_string(&prefix_set, ds_cstr(&deny_list), ",");

    bool denied = false;
    if (!sset_is_empty(&prefix_set)) {
        denied = find_prefix_in_set(prefix, plen, &prefix_set, deny_key);
    }

    ds_destroy(&deny_list);
    sset_destroy(&prefix_set);
    return denied;
}

static bool
route_need_advertise(const char *policy,
                     struct in6_addr *prefix,
                     unsigned int plen,
                     const struct smap *nb_options,
                     const struct nbrec_logical_router *nb_lr,
                     const struct nbrec_logical_router_port *ts_lrp)
{
    if (!smap_get_bool(nb_options, "ic-route-adv", false)) {
        return false;
    }

    if (plen == 0 &&
        !smap_get_bool(nb_options, "ic-route-adv-default", false)) {
        return false;
    }

    if (policy && !strcmp(policy, "src-ip")) {
        return false;
    }

    if (prefix_is_link_local(prefix, plen)) {
        return false;
    }

    if (prefix_is_deny_filtered(prefix, plen, nb_options,
                                nb_lr, ts_lrp, true)) {
        return false;
    }

    if (!prefix_is_filtered(prefix, plen, nb_lr, ts_lrp, true)) {
        return false;
    }

    return true;
}

static void
add_to_routes_ad(struct hmap *routes_ad, const struct in6_addr prefix,
                 unsigned int plen, const struct in6_addr nexthop,
                 const char *origin, const char *route_table,
                 const struct nbrec_logical_router_port *nb_lrp,
                 const struct nbrec_logical_router_static_route *nb_route,
                 const struct nbrec_logical_router *nb_lr,
                 const struct nbrec_load_balancer *nb_lb,
                 const char *route_tag)
{
    ovs_assert(nb_route || nb_lrp || nb_lb);

    if (route_table == NULL) {
        route_table = "";
    }

    uint hash = ic_route_hash(&prefix, plen, &nexthop, origin, route_table);

    if (!ic_route_find(routes_ad, &prefix, plen, &nexthop, origin,
                       route_table, hash)) {
        struct ic_route_info *ic_route = xzalloc(sizeof *ic_route);
        ic_route->prefix = prefix;
        ic_route->plen = plen;
        ic_route->nexthop = nexthop;
        ic_route->nb_route = nb_route;
        ic_route->origin = origin;
        ic_route->route_table = route_table;
        ic_route->nb_lrp = nb_lrp;
        ic_route->nb_lr = nb_lr;
        ic_route->nb_lb = nb_lb;
        ic_route->route_tag = route_tag;
        hmap_insert(routes_ad, &ic_route->node, hash);
    } else {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        const char *msg_fmt = "Duplicate %s route advertisement was "
                              "suppressed! NB %s uuid: "UUID_FMT;
        if (nb_route) {
            VLOG_WARN_RL(&rl, msg_fmt, origin, "route",
                         UUID_ARGS(&nb_route->header_.uuid));
        } else if (nb_lb) {
            VLOG_WARN_RL(&rl, msg_fmt, origin, "loadbalancer",
                         UUID_ARGS(&nb_lb->header_.uuid));
        } else {
            VLOG_WARN_RL(&rl, msg_fmt, origin, "lrp",
                         UUID_ARGS(&nb_lrp->header_.uuid));
        }
    }
}

static void
add_static_to_routes_ad(
    struct hmap *routes_ad,
    const struct nbrec_logical_router_static_route *nb_route,
    const struct nbrec_logical_router *nb_lr,
    const struct lport_addresses *nexthop_addresses,
    const struct smap *nb_options,
    const char *route_tag,
    const struct nbrec_logical_router_port *ts_lrp)
{
    struct in6_addr prefix, nexthop;
    unsigned int plen;
    if (!parse_route(nb_route->ip_prefix, nb_route->nexthop,
                     &prefix, &plen, &nexthop)) {
        return;
    }

    if (!route_need_advertise(nb_route->policy, &prefix, plen, nb_options,
                              nb_lr, ts_lrp)) {
        return;
    }

    if (!get_nexthop_from_lport_addresses(IN6_IS_ADDR_V4MAPPED(&prefix),
                                          nexthop_addresses,
                                          &nexthop)) {
        return;
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds msg = DS_EMPTY_INITIALIZER;

        ds_put_format(&msg, "Advertising static route: %s -> %s, ic nexthop: ",
                      nb_route->ip_prefix, nb_route->nexthop);

        if (IN6_IS_ADDR_V4MAPPED(&nexthop)) {
            ds_put_format(&msg, IP_FMT,
                          IP_ARGS(in6_addr_get_mapped_ipv4(&nexthop)));
        } else {
            ipv6_format_addr(&nexthop, &msg);
        }

        ds_put_format(&msg, ", route_table: %s", nb_route->route_table[0]
                                                 ? nb_route->route_table
                                                 : "<main>");

        VLOG_DBG("%s", ds_cstr(&msg));
        ds_destroy(&msg);
    }

    add_to_routes_ad(routes_ad, prefix, plen, nexthop, ROUTE_ORIGIN_STATIC,
                     nb_route->route_table, NULL, nb_route, nb_lr,
                     NULL, route_tag);
}

static void
add_network_to_routes_ad(struct hmap *routes_ad, const char *network,
                         const struct nbrec_logical_router_port *nb_lrp,
                         const struct lport_addresses *nexthop_addresses,
                         const struct smap *nb_options,
                         const struct nbrec_logical_router *nb_lr,
                         const char *route_tag,
                         const struct nbrec_logical_router_port *ts_lrp)
{
    struct in6_addr prefix, nexthop;
    unsigned int plen;
    if (!ip46_parse_cidr(network, &prefix, &plen)) {
        return;
    }

    if (!route_need_advertise(NULL, &prefix, plen, nb_options,
                              nb_lr, ts_lrp)) {
        VLOG_DBG("Route ad: skip network %s of lrp %s.",
                 network, nb_lrp->name);
        return;
    }

    if (!get_nexthop_from_lport_addresses(IN6_IS_ADDR_V4MAPPED(&prefix),
                                          nexthop_addresses,
                                          &nexthop)) {
        return;
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds msg = DS_EMPTY_INITIALIZER;

        ds_put_format(&msg, "Adding direct network route to <main> routing "
                      "table: %s of lrp %s, nexthop ", network, nb_lrp->name);

        if (IN6_IS_ADDR_V4MAPPED(&nexthop)) {
            ds_put_format(&msg, IP_FMT,
                          IP_ARGS(in6_addr_get_mapped_ipv4(&nexthop)));
        } else {
            ipv6_format_addr(&nexthop, &msg);
        }

        VLOG_DBG("%s", ds_cstr(&msg));
        ds_destroy(&msg);
    }

    /* directly-connected routes go to <main> route table */
    add_to_routes_ad(routes_ad, prefix, plen, nexthop, ROUTE_ORIGIN_CONNECTED,
                     NULL, nb_lrp, NULL, nb_lr, NULL, route_tag);
}

static void
add_lb_vip_to_routes_ad(struct hmap *routes_ad, const char *vip_key,
                        const struct nbrec_load_balancer *nb_lb,
                        const struct lport_addresses *nexthop_addresses,
                        const struct smap *nb_options,
                        const struct nbrec_logical_router *nb_lr,
                        const char *route_tag,
                        const struct nbrec_logical_router_port *ts_lrp)
{
    char *vip_str = NULL;
    struct in6_addr vip_ip, nexthop;
    uint16_t vip_port;
    int addr_family;
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

    if (!ip_address_and_port_from_lb_key(vip_key, &vip_str, &vip_ip,
                                         &vip_port, &addr_family)) {
        VLOG_WARN_RL(&rl, "Route ad: Parsing failed for lb vip %s", vip_key);
        return;
    }
    if (vip_str == NULL) {
        return;
    }
    unsigned int plen = (addr_family == AF_INET) ? 32 : 128;
    if (!route_need_advertise(NULL, &vip_ip, plen, nb_options,
                              nb_lr, ts_lrp)) {
        VLOG_DBG("Route ad: skip lb vip %s.", vip_key);
        goto out;
    }
    if (!get_nexthop_from_lport_addresses(IN6_IS_ADDR_V4MAPPED(&vip_ip),
                                          nexthop_addresses,
                                          &nexthop)) {
        VLOG_WARN_RL(&rl, "Route ad: failed to get nexthop for lb vip");
        goto out;
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds msg = DS_EMPTY_INITIALIZER;

        ds_put_format(&msg, "Adding lb vip route to <main> routing "
                      "table: %s, nexthop ", vip_str);

        if (IN6_IS_ADDR_V4MAPPED(&nexthop)) {
            ds_put_format(&msg, IP_FMT,
                          IP_ARGS(in6_addr_get_mapped_ipv4(&nexthop)));
        } else {
            ipv6_format_addr(&nexthop, &msg);
        }

        VLOG_DBG("%s", ds_cstr(&msg));
        ds_destroy(&msg);
    }

    /* Lb vip routes go to <main> route table */
    add_to_routes_ad(routes_ad, vip_ip, plen, nexthop, ROUTE_ORIGIN_LB,
                     NULL, NULL, NULL, nb_lr, nb_lb, route_tag);
out:
    free(vip_str);
}

static bool
route_has_local_gw(const struct nbrec_logical_router *lr,
                   const char *route_table, const char *ip_prefix) {

    const struct nbrec_logical_router_static_route *route;
    for (int i = 0; i < lr->n_static_routes; i++) {
        route = lr->static_routes[i];
        if (!smap_get(&route->external_ids, "ic-learned-route") &&
            !strcmp(route->route_table, route_table) &&
            !strcmp(route->ip_prefix, ip_prefix)) {
            return true;
        }
    }
    return false;
}

static bool
lrp_has_neighbor_in_ts(const struct nbrec_logical_router_port *lrp,
                       struct in6_addr *nexthop)
{
    if (!lrp || !nexthop) {
        return false;
    }

    struct lport_addresses lrp_networks;
    if (!extract_lrp_networks(lrp, &lrp_networks)) {
        destroy_lport_addresses(&lrp_networks);
        return false;
    }

    if (IN6_IS_ADDR_V4MAPPED(nexthop)) {
        ovs_be32 neigh_prefix_v4 = in6_addr_get_mapped_ipv4(nexthop);
        for (size_t i = 0; i < lrp_networks.n_ipv4_addrs; i++) {
            struct ipv4_netaddr address = lrp_networks.ipv4_addrs[i];
            if (address.network == (neigh_prefix_v4 & address.mask)) {
                destroy_lport_addresses(&lrp_networks);
                return true;
            }
        }
    } else {
        for (size_t i = 0; i < lrp_networks.n_ipv6_addrs; i++) {
            struct ipv6_netaddr address = lrp_networks.ipv6_addrs[i];
            struct in6_addr neigh_prefix = ipv6_addr_bitand(nexthop,
                                                            &address.mask);
            if (ipv6_addr_equals(&address.network, &neigh_prefix)) {
                destroy_lport_addresses(&lrp_networks);
                return true;
            }
        }
    }

    destroy_lport_addresses(&lrp_networks);
    return false;
}

static bool
route_matches_local_lb(const struct nbrec_load_balancer *nb_lb,
                       const char *ip_prefix)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
    struct in6_addr prefix;
    unsigned int plen;

    if (!ip46_parse_cidr(ip_prefix, &prefix, &plen)) {
        return false;
    }

    struct smap_node *node;
    SMAP_FOR_EACH (node, &nb_lb->vips) {
        char *vip_str = NULL;
        struct in6_addr vip_ip;
        uint16_t vip_port;
        int addr_family;
        if (ip_address_and_port_from_lb_key(node->key, &vip_str,
                                            &vip_ip, &vip_port,
                                            &addr_family)) {
            if (IN6_IS_ADDR_V4MAPPED(&prefix) && addr_family == AF_INET) {
                ovs_be32 vip = in6_addr_get_mapped_ipv4(&vip_ip);
                ovs_be32 mask = be32_prefix_mask(plen);

                if ((vip & mask) == in6_addr_get_mapped_ipv4(&prefix)) {
                    free(vip_str);
                    return true;
                }
            } else if (!IN6_IS_ADDR_V4MAPPED(&prefix)
                       && addr_family == AF_INET6) {
                struct in6_addr mask = ipv6_create_mask(plen);
                struct in6_addr vip_prefix = ipv6_addr_bitand(&vip_ip, &mask);
                if (ipv6_addr_equals(&prefix, &vip_prefix)) {
                    free(vip_str);
                    return true;
                }
            }
            free(vip_str);
        } else {
            VLOG_WARN_RL(&rl,
                         "Route learn: Parsing failed for local lb vip %s",
                         node->key);
        }
    }
    return false;
}

static bool
route_need_learn(const struct nbrec_logical_router *lr,
                 const struct icsbrec_route *isb_route,
                 struct in6_addr *prefix, unsigned int plen,
                 const struct smap *nb_options,
                 const struct nbrec_logical_router_port *ts_lrp,
                 struct in6_addr *nexthop)
{
    if (!smap_get_bool(nb_options, "ic-route-learn", false)) {
        return false;
    }

    if (plen == 0 &&
        !smap_get_bool(nb_options, "ic-route-learn-default", false)) {
        return false;
    }

    if (!strcmp(isb_route->origin, ROUTE_ORIGIN_LB) &&
        !smap_get_bool(nb_options, "ic-route-learn-lb", false)) {
        return false;
    }

    if (!lrouter_is_enabled(lr)) {
        return false;
    }

    if (prefix_is_link_local(prefix, plen)) {
        return false;
    }

    if (prefix_is_deny_filtered(prefix, plen, nb_options, lr, ts_lrp, false)) {
        return false;
    }

    if (!prefix_is_filtered(prefix, plen, lr, ts_lrp, false)) {
        return false;
    }

    if (route_has_local_gw(lr, isb_route->route_table, isb_route->ip_prefix)) {
        VLOG_DBG("Skip learning %s (rtb:%s) route, as we've got one with "
                 "local GW", isb_route->ip_prefix, isb_route->route_table);
        return false;
    }

    if (!lrp_has_neighbor_in_ts(ts_lrp, nexthop)) {
        return false;
    }

    for (size_t i = 0; i < lr->n_load_balancer; i++) {
        if (route_matches_local_lb(lr->load_balancer[i],
                                   isb_route->ip_prefix)) {
            VLOG_DBG("Skip learning %s (rtb:%s) route, as we've got local"
                     " LB with matching VIP", isb_route->ip_prefix,
                     isb_route->route_table);
            return false;
        }
    }
    for (size_t i = 0; i < lr->n_load_balancer_group; i++) {
        const struct nbrec_load_balancer_group *nb_lbg =
            lr->load_balancer_group[i];
        for (size_t j = 0; j < nb_lbg->n_load_balancer; j++) {
            if (route_matches_local_lb(nb_lbg->load_balancer[j],
                                       isb_route->ip_prefix)) {
                VLOG_DBG("Skip learning %s (rtb:%s) route, as we've got local"
                         " LB with matching VIP", isb_route->ip_prefix,
                         isb_route->route_table);
                return false;
            }
        }
    }

    return true;
}

static const char *
get_lrp_name_by_ts_port_name(struct route_input *ic, const char *ts_port_name)
{
    const struct nbrec_logical_switch_port *nb_lsp;

    nb_lsp = get_lsp_by_ts_port_name(ic->nbrec_port_by_name, ts_port_name);
    if (!nb_lsp) {
        return NULL;
    }

    return smap_get(&nb_lsp->options, "router-port");
}

static const struct nbrec_logical_router_port *
find_lrp_of_nexthop(struct route_input *ic,
                    const struct icsbrec_route *isb_route)
{
    const struct nbrec_logical_router_port *lrp;
    const struct nbrec_logical_switch *ls;
    ls = find_ts_in_nb(ic->nbrec_ls_by_name, isb_route->transit_switch);
    if (!ls) {
        return NULL;
    }

    struct in6_addr nexthop;
    if (!ip46_parse(isb_route->nexthop, &nexthop)) {
        return NULL;
    }

    for (size_t i = 0; i < ls->n_ports; i++) {
        char *lsp_name = ls->ports[i]->name;
        const char *lrp_name = get_lrp_name_by_ts_port_name(ic,
                                                            lsp_name);
        if (!lrp_name) {
            continue;
        }

        lrp = get_lrp_by_lrp_name(ic->nbrec_lrp_by_name, lrp_name);
        if (!lrp) {
            continue;
        }

        struct lport_addresses lrp_networks;
        if (!extract_lrp_networks(lrp, &lrp_networks)) {
            destroy_lport_addresses(&lrp_networks);
            continue;
        }

        if (IN6_IS_ADDR_V4MAPPED(&nexthop)) {
            ovs_be32 nexthop_v4 = in6_addr_get_mapped_ipv4(&nexthop);
            for (size_t i_v4 = 0; i_v4  < lrp_networks.n_ipv4_addrs; i_v4++) {
                struct ipv4_netaddr address = lrp_networks.ipv4_addrs[i_v4];
                if (address.addr == nexthop_v4) {
                    destroy_lport_addresses(&lrp_networks);
                    return lrp;
                }
            }
        } else {
            for (size_t i_v6 = 0; i_v6 < lrp_networks.n_ipv6_addrs; i_v6++) {
                struct ipv6_netaddr address = lrp_networks.ipv6_addrs[i_v6];
                struct in6_addr nexthop_v6 = ipv6_addr_bitand(&nexthop,
                                                              &address.mask);
                if (ipv6_addr_equals(&address.network, &nexthop_v6)) {
                    destroy_lport_addresses(&lrp_networks);
                    return lrp;
                }
            }
        }
        destroy_lport_addresses(&lrp_networks);
    }

    return NULL;
}

static bool
lrp_is_ts_port(struct route_input *ic, struct ic_router_info *ic_lr,
               const char *lrp_name)
{
    const struct icsbrec_port_binding *isb_pb;
    const char *ts_lrp_name;
    VECTOR_FOR_EACH (&ic_lr->isb_pbs, isb_pb) {
        ts_lrp_name = get_lrp_name_by_ts_port_name(ic, isb_pb->logical_port);
        if (!strcmp(ts_lrp_name, lrp_name)) {
            return true;
        }
    }
    return false;
}

static void
sync_learned_routes(const struct engine_context *ctx,
                    struct route_input *ic,
                    struct ic_router_info *ic_lr,
                    const struct nbrec_nb_global_table *nb_global_table)
{
    ovs_assert(ctx->ovnnb_idl_txn);
    const struct icsbrec_route *isb_route, *isb_route_key;

    const struct nbrec_nb_global *nb_global =
        nbrec_nb_global_table_first(nb_global_table);
    ovs_assert(nb_global);

    const char *lrp_name, *ts_route_table, *route_filter_tag;
    const struct icsbrec_port_binding *isb_pb;
    const struct nbrec_logical_router_port *lrp;
    VECTOR_FOR_EACH (&ic_lr->isb_pbs, isb_pb) {
        if (!strcmp(isb_pb->address, "")) {
            continue;
        }
        lrp_name = get_lrp_name_by_ts_port_name(ic, isb_pb->logical_port);
        lrp = get_lrp_by_lrp_name(ic->nbrec_lrp_by_name, lrp_name);
        if (lrp) {
            ts_route_table = smap_get_def(&lrp->options, "route_table", "");
            route_filter_tag = smap_get_def(&lrp->options,
                                            "ic-route-filter-tag", "");
        } else {
            ts_route_table = "";
            route_filter_tag = "";
        }

        isb_route_key = icsbrec_route_index_init_row(ic->icsbrec_route_by_ts);
        icsbrec_route_index_set_transit_switch(isb_route_key,
                                               isb_pb->transit_switch);

        ICSBREC_ROUTE_FOR_EACH_EQUAL (isb_route, isb_route_key,
                                      ic->icsbrec_route_by_ts) {
            /* Filters ICSB routes, skipping those that either belong to
             * current logical router or are legacy routes from the current
             * availability zone (withoud lr-id).
             */
            const char *lr_id = smap_get(&isb_route->external_ids, "lr-id");
            struct uuid lr_uuid;
            if (lr_id) {
                if (!uuid_from_string(&lr_uuid, lr_id)
                    || uuid_equals(&ic_lr->lr->header_.uuid, &lr_uuid)) {
                    continue;
                }
            } else if (isb_route->availability_zone == ic->runned_az) {
                continue;
            }

            const char *isb_route_tag = smap_get(&isb_route->external_ids,
                                                 "ic-route-tag");
            if (isb_route_tag  && !strcmp(isb_route_tag, route_filter_tag)) {
                VLOG_DBG("Skip learning route %s -> %s as its route tag "
                         "[%s] is filtered by the filter tag [%s] of TS LRP ",
                         isb_route->ip_prefix, isb_route->nexthop,
                         isb_route_tag, route_filter_tag);
                continue;
            }

            if (isb_route->route_table[0] &&
                strcmp(isb_route->route_table, ts_route_table)) {
                if (VLOG_IS_DBG_ENABLED()) {
                    VLOG_DBG("Skip learning static route %s -> %s as either "
                             "its route table %s != %s of TS port or ",
                             isb_route->ip_prefix, isb_route->nexthop,
                             isb_route->route_table, ts_route_table);
                }
                continue;
            }

            struct in6_addr prefix, nexthop;
            unsigned int plen;
            if (!parse_route(isb_route->ip_prefix, isb_route->nexthop,
                             &prefix, &plen, &nexthop)) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "Bad route format in IC-SB: %s -> %s. "
                             "Ignored.", isb_route->ip_prefix,
                             isb_route->nexthop);
                continue;
            }
            if (!route_need_learn(ic_lr->lr, isb_route, &prefix, plen,
                                  &nb_global->options, lrp, &nexthop)) {
                continue;
            }

            struct ic_route_info *route_learned
                = ic_route_find(&ic_lr->routes_learned, &prefix, plen,
                                &nexthop, isb_route->origin,
                                isb_route->route_table, 0);
            if (route_learned) {
                /* Sync external-ids */
                struct uuid ext_id;
                smap_get_uuid(&route_learned->nb_route->external_ids,
                              "ic-learned-route", &ext_id);
                if (!uuid_equals(&ext_id, &isb_route->header_.uuid)) {
                    char *uuid_s =
                        xasprintf(UUID_FMT,
                                  UUID_ARGS(&isb_route->header_.uuid));
                    nbrec_logical_router_static_route_update_external_ids_setkey(
                        route_learned->nb_route, "ic-learned-route", uuid_s);
                    free(uuid_s);
                }
                hmap_remove(&ic_lr->routes_learned, &route_learned->node);
                free(route_learned);
            } else {
                /* Create the missing route in NB. */
                const struct nbrec_logical_router_static_route *nb_route =
                    nbrec_logical_router_static_route_insert(
                        ctx->ovnnb_idl_txn);
                nbrec_logical_router_static_route_set_ip_prefix(nb_route,
                    isb_route->ip_prefix);
                nbrec_logical_router_static_route_set_nexthop(nb_route,
                    isb_route->nexthop);
                char *uuid_s = xasprintf(UUID_FMT,
                                         UUID_ARGS(&isb_route->header_.uuid));
                nbrec_logical_router_static_route_set_route_table(nb_route,
                    isb_route->route_table);
                nbrec_logical_router_static_route_update_external_ids_setkey(
                    nb_route, "ic-learned-route", uuid_s);
                nbrec_logical_router_static_route_update_options_setkey(
                    nb_route, "origin", isb_route->origin);
                free(uuid_s);
                nbrec_logical_router_update_static_routes_addvalue(ic_lr->lr,
                    nb_route);
            }
        }
        icsbrec_route_index_destroy_row(isb_route_key);
    }

    /* Delete extra learned routes. */
    struct ic_route_info *route_learned;
    HMAP_FOR_EACH_SAFE (route_learned, node, &ic_lr->routes_learned) {
        VLOG_DBG("Delete route %s -> %s that is not in IC-SB from NB.",
                 route_learned->nb_route->ip_prefix,
                 route_learned->nb_route->nexthop);
        nbrec_logical_router_update_static_routes_delvalue(
            ic_lr->lr, route_learned->nb_route);
        hmap_remove(&ic_lr->routes_learned, &route_learned->node);
        free(route_learned);
    }
}

static void
ad_route_sync_external_ids(const struct ic_route_info *route_adv,
                           const struct icsbrec_route *isb_route)
{
    struct uuid isb_ext_id, nb_id, isb_ext_lr_id, lr_id;
    const char *route_tag;
    smap_get_uuid(&isb_route->external_ids, "nb-id", &isb_ext_id);
    smap_get_uuid(&isb_route->external_ids, "lr-id", &isb_ext_lr_id);
    nb_id = route_adv->nb_lb ? route_adv->nb_lb->header_.uuid :
            route_adv->nb_route ? route_adv->nb_route->header_.uuid :
            route_adv->nb_lrp->header_.uuid;

    lr_id = route_adv->nb_lr->header_.uuid;
    if (!uuid_equals(&isb_ext_id, &nb_id)) {
        char *uuid_s = xasprintf(UUID_FMT, UUID_ARGS(&nb_id));
        icsbrec_route_update_external_ids_setkey(isb_route, "nb-id",
                                                 uuid_s);
        free(uuid_s);
    }
    if (!uuid_equals(&isb_ext_lr_id, &lr_id)) {
        char *uuid_s = xasprintf(UUID_FMT, UUID_ARGS(&lr_id));
        icsbrec_route_update_external_ids_setkey(isb_route, "lr-id",
                                                 uuid_s);
        free(uuid_s);
    }
    if (strcmp(route_adv->route_tag, "")) {
        icsbrec_route_update_external_ids_setkey(isb_route, "ic-route-tag",
                                                 route_adv->route_tag);
    } else {
        route_tag = smap_get(&isb_route->external_ids, "ic-route-tag");
        if (route_tag) {
            icsbrec_route_update_external_ids_delkey(isb_route,
                                                     "ic-route-tag");
        }
    }
}

/* Sync routes from routes_ad to IC-SB. */
static void
advertise_routes(const struct engine_context *ctx,
                 struct route_input *ic,
                 const struct icsbrec_availability_zone *az,
                 const char *ts_name, struct hmap *routes_ad)
{
    ovs_assert(ctx->ovnisb_idl_txn);
    const struct icsbrec_route *isb_route;
    const struct icsbrec_route *isb_route_key =
        icsbrec_route_index_init_row(ic->icsbrec_route_by_ts_az);
    icsbrec_route_index_set_transit_switch(isb_route_key, ts_name);
    icsbrec_route_index_set_availability_zone(isb_route_key, az);

    ICSBREC_ROUTE_FOR_EACH_EQUAL (isb_route, isb_route_key,
                                  ic->icsbrec_route_by_ts_az) {
        struct in6_addr prefix, nexthop;
        unsigned int plen;

        if (!parse_route(isb_route->ip_prefix, isb_route->nexthop,
                         &prefix, &plen, &nexthop)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "Bad route format in IC-SB: %s -> %s. "
                         "Delete it.",
                         isb_route->ip_prefix, isb_route->nexthop);
            icsbrec_route_delete(isb_route);
            continue;
        }
        struct ic_route_info *route_adv =
            ic_route_find(routes_ad, &prefix, plen, &nexthop,
                          isb_route->origin, isb_route->route_table, 0);
        if (!route_adv) {
            /* Delete the extra route from IC-SB. */
            VLOG_DBG("Delete route %s -> %s from IC-SB, which is not found"
                     " in local routes to be advertised.",
                     isb_route->ip_prefix, isb_route->nexthop);
            icsbrec_route_delete(isb_route);
        } else {
            ad_route_sync_external_ids(route_adv, isb_route);

            hmap_remove(routes_ad, &route_adv->node);
            free(route_adv);
        }
    }
    icsbrec_route_index_destroy_row(isb_route_key);

    /* Create the missing routes in IC-SB */
    struct ic_route_info *route_adv;
    HMAP_FOR_EACH_SAFE (route_adv, node, routes_ad) {
        isb_route = icsbrec_route_insert(ctx->ovnisb_idl_txn);
        icsbrec_route_set_transit_switch(isb_route, ts_name);
        icsbrec_route_set_availability_zone(isb_route, az);

        char *prefix_s, *nexthop_s;
        if (IN6_IS_ADDR_V4MAPPED(&route_adv->prefix)) {
            ovs_be32 ipv4 = in6_addr_get_mapped_ipv4(&route_adv->prefix);
            ovs_be32 nh = in6_addr_get_mapped_ipv4(&route_adv->nexthop);
            prefix_s = xasprintf(IP_FMT "/%d", IP_ARGS(ipv4), route_adv->plen);
            nexthop_s = xasprintf(IP_FMT, IP_ARGS(nh));
        } else {
            char network_s[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &route_adv->prefix, network_s,
                      INET6_ADDRSTRLEN);
            prefix_s = xasprintf("%s/%d", network_s, route_adv->plen);
            inet_ntop(AF_INET6, &route_adv->nexthop, network_s,
                      INET6_ADDRSTRLEN);
            nexthop_s = xstrdup(network_s);
        }
        icsbrec_route_set_ip_prefix(isb_route, prefix_s);
        icsbrec_route_set_nexthop(isb_route, nexthop_s);
        icsbrec_route_set_origin(isb_route, route_adv->origin);
        icsbrec_route_set_route_table(isb_route, route_adv->route_table
                                                 ? route_adv->route_table
                                                 : "");
        free(prefix_s);
        free(nexthop_s);

        ad_route_sync_external_ids(route_adv, isb_route);

        hmap_remove(routes_ad, &route_adv->node);
        free(route_adv);
    }
}

static void
build_ts_routes_to_adv(struct route_input *ic,
                       struct ic_router_info *ic_lr,
                       struct hmap *routes_ad,
                       struct lport_addresses *ts_port_addrs,
                       const struct nbrec_nb_global *nb_global,
                       const char *ts_route_table,
                       const char *route_tag,
                       const struct nbrec_logical_router_port *ts_lrp)
{
    const struct nbrec_logical_router *lr = ic_lr->lr;

    /* Check static routes of the LR */
    for (int i = 0; i < lr->n_static_routes; i++) {
        const struct nbrec_logical_router_static_route *nb_route
            = lr->static_routes[i];
        struct uuid isb_uuid;
        if (smap_get_uuid(&nb_route->external_ids, "ic-learned-route",
                          &isb_uuid)) {
            /* It is a learned route */
            if (!add_to_routes_learned(&ic_lr->routes_learned, nb_route, lr)) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "Bad format of learned route in NB: "
                             "%s -> %s. Delete it.", nb_route->ip_prefix,
                             nb_route->nexthop);
                nbrec_logical_router_update_static_routes_delvalue(lr,
                    nb_route);
            }
        } else if (!strcmp(ts_route_table, nb_route->route_table)) {
            /* It may be a route to be advertised */
            add_static_to_routes_ad(routes_ad, nb_route, lr, ts_port_addrs,
                                    &nb_global->options, route_tag, ts_lrp);
        }
    }

    /* Check directly-connected subnets of the LR */
    for (int i = 0; i < lr->n_ports; i++) {
        const struct nbrec_logical_router_port *lrp = lr->ports[i];
        if (!lrp_is_ts_port(ic, ic_lr, lrp->name)) {
            for (int j = 0; j < lrp->n_networks; j++) {
                add_network_to_routes_ad(routes_ad, lrp->networks[j], lrp,
                                         ts_port_addrs,
                                         &nb_global->options,
                                         lr, route_tag, ts_lrp);
            }
        } else {
            /* The router port of the TS port is ignored. */
            VLOG_DBG("Skip advertising direct route of lrp %s (TS port)",
                     lrp->name);
        }
    }

    /* Check loadbalancers associated with the LR */
    if (smap_get_bool(&nb_global->options, "ic-route-adv-lb", false)) {
        for (size_t i = 0; i < lr->n_load_balancer; i++) {
            const struct nbrec_load_balancer *nb_lb = lr->load_balancer[i];
            struct smap_node *node;
            SMAP_FOR_EACH (node, &nb_lb->vips) {
                add_lb_vip_to_routes_ad(routes_ad, node->key, nb_lb,
                                        ts_port_addrs,
                                        &nb_global->options,
                                        lr, route_tag, ts_lrp);
            }
        }

        for (size_t i = 0; i < lr->n_load_balancer_group; i++) {
            const struct nbrec_load_balancer_group *nb_lbg =
                lr->load_balancer_group[i];
            for (size_t j = 0; j < nb_lbg->n_load_balancer; j++) {
                const struct nbrec_load_balancer *nb_lb =
                    nb_lbg->load_balancer[j];
                struct smap_node *node;
                SMAP_FOR_EACH (node, &nb_lb->vips) {
                    add_lb_vip_to_routes_ad(routes_ad, node->key, nb_lb,
                                            ts_port_addrs,
                                            &nb_global->options,
                                            lr, route_tag, ts_lrp);
                }
            }
        }
    }
}

static void
collect_lr_routes(struct route_input *ic,
                  struct ic_router_info *ic_lr,
                  struct shash *routes_ad_by_ts,
                  const struct nbrec_nb_global_table *nb_global_table)
{
    const struct nbrec_nb_global *nb_global =
        nbrec_nb_global_table_first(nb_global_table);

    ovs_assert(nb_global);

    const struct icsbrec_port_binding *isb_pb;
    const char *lrp_name, *ts_name, *route_table, *route_tag;
    struct lport_addresses ts_port_addrs;
    const struct icnbrec_transit_switch *key;
    const struct nbrec_logical_router_port *lrp;

    struct hmap *routes_ad;
    const struct icnbrec_transit_switch *t_sw;
    VECTOR_FOR_EACH (&ic_lr->isb_pbs, isb_pb) {
        key = icnbrec_transit_switch_index_init_row(
            ic->icnbrec_transit_switch_by_name);
        icnbrec_transit_switch_index_set_name(key, isb_pb->transit_switch);
        t_sw = icnbrec_transit_switch_index_find(
             ic->icnbrec_transit_switch_by_name, key);
        icnbrec_transit_switch_index_destroy_row(key);
        if (!t_sw) {
            continue;
        }
        ts_name = t_sw->name;
        routes_ad = shash_find_data(routes_ad_by_ts, ts_name);
        if (!routes_ad) {
            routes_ad = xzalloc(sizeof *routes_ad);
            hmap_init(routes_ad);
            shash_add(routes_ad_by_ts, ts_name, routes_ad);
        }

        if (!extract_lsp_addresses(isb_pb->address, &ts_port_addrs)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(&rl, "Route sync ignores port %s on ts %s for router"
                         " %s because the addresses are invalid.",
                         isb_pb->logical_port, isb_pb->transit_switch,
                         ic_lr->lr->name);
            continue;
        }
        lrp_name = get_lrp_name_by_ts_port_name(ic, isb_pb->logical_port);
        lrp = get_lrp_by_lrp_name(ic->nbrec_lrp_by_name, lrp_name);
        if (lrp) {
            route_table = smap_get_def(&lrp->options, "route_table", "");
            route_tag = smap_get_def(&lrp->options, "ic-route-tag", "");
        } else {
            route_table = "";
            route_tag = "";
        }
        build_ts_routes_to_adv(ic, ic_lr, routes_ad, &ts_port_addrs,
                               nb_global, route_table, route_tag, lrp);
        destroy_lport_addresses(&ts_port_addrs);
    }
}

static void
delete_orphan_ic_routes(struct route_input *ic,
                        const struct icsbrec_availability_zone *az)
{
    const struct icsbrec_route *isb_route, *isb_route_key =
        icsbrec_route_index_init_row(ic->icsbrec_route_by_az);
    icsbrec_route_index_set_availability_zone(isb_route_key, az);

    const struct icnbrec_transit_switch *t_sw, *t_sw_key;

    ICSBREC_ROUTE_FOR_EACH_EQUAL (isb_route, isb_route_key,
                                  ic->icsbrec_route_by_az)
    {
        t_sw_key = icnbrec_transit_switch_index_init_row(
            ic->icnbrec_transit_switch_by_name);
        icnbrec_transit_switch_index_set_name(t_sw_key,
            isb_route->transit_switch);
        t_sw = icnbrec_transit_switch_index_find(
            ic->icnbrec_transit_switch_by_name, t_sw_key);
        icnbrec_transit_switch_index_destroy_row(t_sw_key);

        if (!t_sw || !find_lrp_of_nexthop(ic, isb_route)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(&rl, "Deleting orphan ICDB:Route: %s->%s (%s, rtb:%s,"
                         " transit switch: %s)", isb_route->ip_prefix,
                         isb_route->nexthop, isb_route->origin,
                         isb_route->route_table, isb_route->transit_switch);
            icsbrec_route_delete(isb_route);
        }
    }
    icsbrec_route_index_destroy_row(isb_route_key);
}
