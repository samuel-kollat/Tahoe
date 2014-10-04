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
void policy_map_begin(  onep_network_element_t *elem,           // Network element
                        onep_policy_table_cap_t *table_cap,     // Router table
                        onep_policy_op_list_t **pmap_op_list,   // RETURN | Policy map operation list
                        onep_policy_pmap_op_t **pmap_op );      // RETURN | Policy map operation

//
//
void policy_map_finish( onep_policy_pmap_op_t *pmap_op,             // Policy map operation
                        onep_policy_op_list_t *pmap_op_list,        // Policy map operation list
                        onep_policy_pmap_handle_t *pmap_handle );   // RETURN | Policy map handle

//
//
void policy_map_add_entry(  onep_policy_table_cap_t *table_cap,     // Router table
                            onep_policy_pmap_op_t *pmap_op,         // Policy map operation
                            uint32_t sequence,                      // Sequence number
                            onep_policy_entry_op_t **entry_op );    // RETURN | Entry operation

//
//
void policy_map_try_set_persistent( onep_policy_table_cap_t *table_cap,     // Router table
                                    onep_policy_pmap_op_t *pmap_op,         // Policy map operation
                                    char* pmap_name );                      // Name of policy map