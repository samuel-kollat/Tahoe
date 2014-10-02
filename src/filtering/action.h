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
void action_add(    onep_policy_entry_op_t *entry_op,       // Entry operation
                    onep_dpss_pkt_action_type_e action,     // DPSS action
                    onep_dpss_pak_callback_t callback );    // Action callback
