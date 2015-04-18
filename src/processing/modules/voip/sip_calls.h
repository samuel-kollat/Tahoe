#ifndef __SIP_CALLS_H__
#define __SIP_CALLS_H__

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

typedef enum {
	CALL_INITIALIZED,
	CALL_INVITED,
	CALL_TRYING,
	CALL_CANCELED,
	CALL_IN_PROGRESS,
	CALL_DROPPED,
} CallState;

typedef enum {
	UPFLOW,
	DOWNFLOW
} CallDirection;

typedef struct RtpFlow {
	unsigned int source_port;
	unsigned int destination_port;
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
TRtpFlow * find_rtp_flow_by_ports(TList * list, CallDirection *direction, TSipCall * sip_call, unsigned int src_port, unsigned int dst_port);

#endif

