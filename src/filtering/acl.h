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
void acl_begin( onep_network_element_t *elem,   // Network element
                onep_acl_t **acl );             // RETURN | ACL

//
//
void acl_finish(onep_acl_t *acl,    // ACL
                onep_ace_t *ace );  // ACE

//
//
void ace_init(  int sequence,       // Sequence number
                onep_ace_t **ace ); // RETURN | ACE

//
//
void ace_add_ip(onep_ace_t *ace,                // ACE  
                struct sockaddr *src_prefix,    // Source IP prefix
                uint16_t src_length,            // Source IP prefix length
                struct sockaddr *dst_prefix,    // Destination IP prefix
                uint16_t dst_length );          // Destination IP prefix length

//
void ace_add_protocol(  onep_ace_t *ace,                // ACE 
                        onep_acl_protocol_e protocol ); // L3 protocol

//
//
void ace_add_port(  onep_ace_t *ace,                    // ACE
                    uint16_t src_port,                  // Source port
                    onep_operator_e src_operator,       // Source match operator
                    uint16_t dst_port,                  // Destination port
                    onep_operator_e dst_operator );     // Destination match operator