#include "ovn-ic-sb-idl.h"
#ifndef EN_IC_TS_H
#define EN_IC_TS_H 1

#include <config.h>
#include <stdbool.h>
#include "lib/inc-proc-eng.h"
#include "openvswitch/hmap.h"
#include "openvswitch/shash.h"

struct tracked_ts_data {
    struct shash crupdated_ts;
    struct shash deleted_ts;
};

struct ed_type_ts_data {
    /* hmap of datapath tunel ids */
    struct hmap dp_tnlids;
    /* shash of interconnect southbound transit switch datapaths */
    struct shash isb_ts_dps;
    /* shash of northbound transit switches */
    struct shash nb_tses;

    bool tracked;
    struct tracked_ts_data tracked_ts_data;
};

enum engine_node_state en_ts_run(struct engine_node *node, void *data);
void *en_ts_init(struct engine_node *, struct engine_arg *);
void en_ts_cleanup(void *data);
void en_ts_clear_tracked_data(void *data);

enum engine_input_handler_result
    en_ts_handler(struct engine_node *node, void *data);
enum engine_input_handler_result
    en_ts_ic_nb_global_handler(struct engine_node *node, void *data);
#endif
