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
void class_map_begin(   onep_network_element_t *elem,           // Network element
                        onep_policy_table_cap_t *table_cap,     // Traffic action table
                        onep_policy_cmap_attr_e attribute,      // Logical AND or OR between rules
                        onep_policy_entry_op_t *entry_op,       // Entry operation
                        char* cmap_name,                        // Class map name
                        onep_policy_op_list_t **cmap_op_list,   // RETURN | Operation list
                        onep_policy_cmap_op_t **cmap_op,        // RETURN | Operation
                        onep_policy_match_holder_t **mh );      // RETURN | Match holder

//
//
void class_map_finish(  onep_policy_table_cap_t *table_cap,     // Traffic action table
                        onep_policy_op_list_t *cmap_op_list,    // Operation list
                        onep_policy_cmap_op_t *cmap_op,         // Operation
                        onep_policy_entry_op_t **entry_op );    // RETURN | Entry operation

//
//
void class_map_add_l7_protocol( onep_policy_match_holder_t *mh,     // Match holder
                                char* protocol_name );              // Name of L7 protocol

//
//
void class_map_add_acl( onep_policy_match_holder_t *mh,     // Match holder
                        onep_policy_access_list_t *acl );   // Name of L7 protocol