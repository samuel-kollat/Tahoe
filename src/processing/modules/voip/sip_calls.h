/* * * * * * * * * * * * * * * * * * * * *
 *              O n e M o n              *
 *                                       *
 * File: sip_calls.h                     *
 * Author: David Antolik                 *
 *                                       *
 * * * * * * * * * * * * * * * * * * * * */

#ifndef __SIP_CALLS_H__
#define __SIP_CALLS_H__

#include <inttypes.h>
#include <stdbool.h>

typedef struct ListItem TListItem;
typedef struct ListItem {
	TListItem * prev;
	TListItem * next;
	void * data;
} TListItem;

typedef struct {
	TListItem * first;	
} TList;

int slist_init(TList * list);
int slist_insert(TList * list, TListItem * item);
int slist_delete(TList * list, TListItem * item);
int slist_count_items(TList * list);

typedef enum {
	CALL_IDLE = 0,
	CALL_CALLING = 1,	
	CALL_ESTABLISHED = 2,
	CALL_TERMINATED_BYE = 3,
	CALL_TERMINATED_CANCEL = 4,
	CALL_TERMINATED_DECLINE = 5,
} CallState;

typedef enum {
	UPFLOW,
	DOWNFLOW
} CallDirection;

typedef struct {
	uint32_t timestamp;
	uint16_t sequence_number;
	double arrival_time;

	double Difference;
	double Jitter;
	double Packet_loss;
	unsigned int Packets_expected;

	bool in_order;	// Says if the packet arrives in right order (based on sequence number)

} TRtpInfo;

typedef struct SipCall TSipCall;
typedef struct RtpFlow {
	unsigned int source_port;
	unsigned int destination_port;

	char * sdp;

	uint8_t payload_type;
	unsigned int codec_freq;

	char * media_info;

	uint32_t source_addr;
	uint32_t destination_addr;

	TSipCall * sip_call;

	double arrival_time_base;
	unsigned int sequence_number_base;
	unsigned int last_sequence_number;
	unsigned int sn_overflow;

	unsigned int packet_counter;

	TList * packets;
} TRtpFlow;

typedef struct SipCall {
	char * call_id;
	CallState call_state;
	char * source;			// Field "From:" from SIP header
	char * destination;		// Field "To:" from SIP header
	TRtpFlow *rtp_upflow;
	TRtpFlow *rtp_downflow;
} TSipCall;

TSipCall * find_sip_call(TList * list, char * call_id);
TRtpFlow * find_rtp_flow(TList * list, CallDirection *direction, TSipCall * sip_call, uint16_t src_port, uint16_t dst_port, uint32_t src_ip, uint32_t dst_ip);
TRtpFlow * rtp_flow_init();

#endif

