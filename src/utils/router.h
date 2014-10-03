#include "onep_core_services.h"
#include "onep_policy_bulk.h"
#include "onep_datapath_policy.h"
#include "onep_class.h"
#include "onep_filter.h"
#include "onep_dpss_packet_delivery.h"
#include "onep_types.h"
#include "onep_dpss_actions.h"
#include "onep_dpss_pkt.h"
#include "onep_dpss_flow.h"
#include "onep_dpss_callback_framework.h"

//
//
onep_status_t router_get_table( onep_network_element_t *elem,           // Network element
                                onep_collection_t **tables,             // RETURN | Tables
                                onep_policy_table_cap_t **table_cap );  // RETURN | Datapath table

//
// Display a list of interfaces.
void router_print_intf_list(onep_collection_t *intf_list,   // List of interfaces
                            FILE *op );                     // File to print