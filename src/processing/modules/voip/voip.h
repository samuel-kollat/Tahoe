/* * * * * * * * * * * * * * * * * * * * *
 *              O n e M o n              *
 *                                       *
 * File: voip.h                          *
 * Author: David Antolik                 *
 *                                       *
 * * * * * * * * * * * * * * * * * * * * */

#ifndef __VOIP_H__
#define __VOIP_H__

#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

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

#include <pcap.h>

#include "../../utils/config.h"

#include "../../queues/queues.h"

#include "sip_calls.h"

void Voip(
    TQueueItem* start,
    TQueueItem* stop
);

typedef struct {
	uint8_t dsthw[6];
	uint8_t srchw[6];
	uint8_t proto[2];
} L2_header;

typedef struct {
	//uint8_t version;	
	uint8_t ihl : 4;
	uint8_t version : 4;
	uint8_t ecn : 2;
	uint8_t dscp : 6;	
	uint16_t total_length;
	uint8_t identification;		
	uint16_t fragment_offset : 13;	
	uint8_t flags : 3;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t header_checksum;
	uint32_t source_ip;
	uint32_t destination_ip;
} L3_header;

typedef struct {
	uint16_t source_port;
	uint16_t destination_port;
	uint16_t length;
	uint16_t checksum;
} UDP_header;

typedef struct {
	uint8_t cc : 4;
	uint8_t extension : 1;
	uint8_t padding : 1;
	uint8_t version : 2;	
	uint8_t payload_type : 7;
	uint8_t m : 1; 
	uint16_t sequence_number;
	uint32_t timestamp;
	uint32_t ssrc;
} RTP_header;

typedef enum {

	/* Request methods */
	SIP_UNKNOWN_METHOD,
	SIP_INVITE, 
	SIP_ACK, 
	SIP_BYE, 
	SIP_CANCEL, 
	SIP_OPTIONS, 
	SIP_REGISTER, 
	SIP_PRACK, 
	SIP_SUBSCRIBE, 
	SIP_NOTIFY, 
	SIP_PUBLISH, 
	SIP_INFO, 
	SIP_REFER, 
	SIP_MESSAGE, 
	SIP_UPDATE,
	SIP_REPLY,

	/* Status methods */
	SIP_REPLY_TRYING,
	SIP_REPLY_RINGING,
	SIP_REPLY_SUCCESS,
	SIP_REPLY_OK,
	SIP_REPLY_DIALOG_ESTABLISHEMENT,
	SIP_REPLY_REQUEST_CANCELLED,
	SIP_REPLY_DECLINE,

	SIP_REPLY_400,
	SIP_REPLY_500,
	SIP_REPLY_486,
} Sip_Method;

char * print_sip_method(Sip_Method sip_method);

char * print_sip_call_state(CallState call_state);

void print_hex(uint8_t *mem, int length);

void dump_sip_calls(TList *);

void *info_thread(void *);

uint32_t ip_str_to_uint32(char *);

#endif