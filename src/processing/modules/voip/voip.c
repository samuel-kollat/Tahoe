/* * * * * * * * * * * * * * * * * * * * *
 *              O n e M o n              *
 *                                       *
 * File: voip.c                          *
 * Author: David Antolik                 *
 *                                       *
 * * * * * * * * * * * * * * * * * * * * */

#include "voip.h"
#include "sip_calls.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

// Call-Table
TList *sip_calls = NULL;

//TList *rtp_flows = NULL;

void Voip_initialize()
{
	// initialize list with call informations extracted from SIP
	sip_calls = malloc(sizeof(TList));
	if(sip_calls == NULL)
		return;
	slist_init(sip_calls);
	// initialize list with RTP flows
	//rtp_flows = malloc(sizeof(TList));
	//if(rtp_flows == NULL)
	//	return;
	//slist_init(rtp_flows);

	// create info thread
	pthread_t info_thr;
	while(pthread_create(&info_thr, NULL, info_thread, NULL)!=0)
	{
		fprintf(stderr, "[VoIP DEBUG] Cannot create info thread.\n");
	}

}

/* Extractor functions */

// Extract timestamp field from RTP header
uint32_t get_rtp_timestamp(RTP_header *rtp_header)
{
	return ntohl(rtp_header->timestamp);
}

// Extract CC field from RTP header
uint8_t get_rtp_cc(RTP_header *rtp_header)
{
	return rtp_header->cc;
}

// Extract Extension field from RTP header
uint8_t get_rtp_extension(RTP_header *rtp_header)
{
	return rtp_header->extension;
}

// Extract Padding field from RTP header
uint8_t get_rtp_padding(RTP_header *rtp_header)
{
	return rtp_header->padding;
}

// Extract RTP version from its header
uint8_t get_rtp_version(RTP_header *rtp_header)
{
	return rtp_header->version;
}

// Extract Payload_type from RTP header
uint8_t get_rtp_payload_type(RTP_header *rtp_header)
{
	return rtp_header->payload_type;
}

uint8_t get_rtp_m(RTP_header *rtp_header)
{
	return rtp_header->m;
}

// Extract sequence number from RTP header
uint16_t get_rtp_sequence_number(RTP_header *rtp_header)
{
	return ntohs(rtp_header->sequence_number);
}

// Extract SSRC from RTP header
uint32_t get_rtp_ssrc(RTP_header *rtp_header)
{
	return ntohl(rtp_header->ssrc);
}

// Extract Source IP address from IP header
uint32_t get_ip_src(L3_header *l3_header)
{
	return ntohl(l3_header->source_ip);
}

// Extract Destination IP address from IP header
uint32_t get_ip_dst(L3_header *l3_header)
{
	return ntohl(l3_header->destination_ip);
}

// Extract Source port number from UDP header
uint16_t get_port_src(UDP_header *udp_header)
{
	return ntohs(udp_header->source_port);
}

// Extract Destination port number from UDP header
uint16_t get_port_dst(UDP_header *udp_header)
{
	return ntohs(udp_header->destination_port);
}

// Identifies SIP method (Request / Response) from first line of SIP payload
Sip_Method get_sip_method(uint8_t * sip_payload)
{
	switch(sip_payload[0])
	{
		case 'A':
			// ACK
			return SIP_ACK;
			break;
		case 'B':
			// BYE
			return SIP_BYE;
			break;
		case 'C':
			// CANCEL
			return SIP_CANCEL;
			break;
		case 'O':
			// OPTIONS
			return SIP_OPTIONS;
			break;
		case 'R':
			// REGISTER, REFER
			if(sip_payload[2] == 'G')
				return SIP_REGISTER;
			else
				return SIP_REFER;
			break;
		case 'P':
			// PRACK, PUBLISH
			if(sip_payload[1] == 'R')
				return SIP_PRACK;
			else
				return SIP_PUBLISH;
			break;
		case 'I':
			// INFO, INVITE
			if(sip_payload[2] == 'F')
				return SIP_INFO;
			else
				return SIP_INVITE;
			break;
		case 'S':
			// SUBSCRIBE, SIP
			if(sip_payload[1] == 'I')
			{
				// SIP Response
				if(sip_payload[8] == '4')
				{
					// Response message type 4xx
					// SIP 486 Busy Here
						if(sip_payload[9] == '8' && sip_payload[10] == '6')
						{
							return SIP_REPLY_486;
						}				
				
					return SIP_REPLY_400;
				}
				else if(sip_payload[8] == '5')
				{
					// Response message type 5xx
					return SIP_REPLY_500;
				}
				else if( strstr(sip_payload, "Trying") != NULL)
				{
					// Trying response
					return SIP_REPLY_TRYING;
				} else if( strstr(sip_payload, "Ringing") != NULL)
				{
					// Ringing response
					return SIP_REPLY_RINGING;
				} else if( strstr(sip_payload, "Success") != NULL)
				{
					// Success response
					return SIP_REPLY_SUCCESS;
				} else if( strstr(sip_payload, "OK") != NULL)
				{
					// OK response
					return SIP_REPLY_OK;
				}
				else if( strstr(sip_payload, "Dialog Establishement") != NULL)
				{
					// Dialog establishement response
					return SIP_REPLY_DIALOG_ESTABLISHEMENT;
				}
				else if( strstr(sip_payload, "Request Cancelled") != NULL)
				{
					// Request cancelled response
					return SIP_REPLY_REQUEST_CANCELLED;
				}
				else if( strstr(sip_payload, "Decline") != NULL)
				{
					// Decline response
					return SIP_REPLY_DECLINE;
				}
				//printf("%s\n", sip_payload);
				return SIP_REPLY;
			}
			else
			{
				return SIP_SUBSCRIBE;
			}
			break;
		case 'N':
			// NOTIFY
			return SIP_NOTIFY;
			break;
		case 'M':
			// MESSAGE
			return SIP_MESSAGE;
			break;
		case 'U':
			// UPDATE
			return SIP_UPDATE;
			break;

	}

	return SIP_UNKNOWN_METHOD;
}

// Call-back function of VoIP analyzer
void Voip(TQueueItem* start, TQueueItem* stop)
{

	if(sip_calls == NULL)
	{
		Voip_initialize();		
	}

	TQueueItem *item = start;
	int i;
	while(item != NULL)
	{
		TPacket* packet = (TPacket*)item->packet;

		// match SIP packets

		uint8_t * payload;
		uint32_t payload_size;
		onep_status_t s = onep_dpss_pkt_get_l2_start(item->packet, &payload, &payload_size);
		//printf("onep_dpss_pkt_get_l2_start:%d %d %d\n", s, (s == ONEP_OK), (s == ONEP_ERR_BAD_ARGUMENT));

		// + TCP header
		uint32_t offset_to_siprtp = sizeof(L2_header) + sizeof(L3_header) + sizeof(UDP_header);
		uint8_t *siprtp_payload = payload + offset_to_siprtp;

		Sip_Method find_method = get_sip_method(siprtp_payload);

		if(find_method != SIP_UNKNOWN_METHOD)
		{
			// replace \0 characters with \n characters
			
			for(i = offset_to_siprtp; i < payload_size; i++)
			{
				if(*(payload + i) == '\0')
				{
					*(payload + i) = '\n';
				}				
			}
			// Process packet as SIP
			Process_SIP(siprtp_payload);
		} else {
			// Process packet as RTP
			Process_RTP(item, payload, payload_size, siprtp_payload);
		}
		// packet processing routine - SIP and RTP

		// move to the next item
		item = GetNextItem(item, stop);
	}
}

char * extract_sip_header_field(uint8_t *payload, char *key)
{
	char * occurence = strstr(payload, key);
	if(occurence != NULL)
	{
		occurence += strlen(key);
		// left trim
		while(isspace(*occurence)) occurence++;
		char * field_value = occurence;
		while(isprint(*occurence) && *occurence != ';') occurence++;
		// null terminating the header field value
		char backup_occ_char = *occurence;
		*occurence = '\0';
		char *ret = strdup(field_value);
		*occurence = backup_occ_char;
		return ret;
	}

	return NULL;
}

char * get_sip_call_id(uint8_t *sip_payload)
{
	return extract_sip_header_field(sip_payload, "Call-ID: ");	
}

int Process_SIP(uint8_t * sip_payload)
{
	//printf("Processing SIP\n");	

	// get SIP method
	Sip_Method method = get_sip_method(sip_payload);

	//printf("Method: %s\n", print_sip_method(method));

	// extract SIP Call-ID
	char * current_call_id = get_sip_call_id(sip_payload);
	if(current_call_id == NULL)
	{
		// do not process, we cannot find Call-ID .. maybe incorrect SIP packet
		fprintf(stderr, "[DEBUG VoIP] Cannot find Call-ID.\n");
	} else {	
		//fprintf("[DEBUG VoIP] Call-ID: %s\n", current_call_id);
	}

	// find this SIP call in Call-Table
	TSipCall * sip_call = find_sip_call(sip_calls, current_call_id);
	if(sip_call == NULL)
	{
		// create new SIP Call
		sip_call = malloc(sizeof(TSipCall));
		if(sip_call == NULL)
			return 0;
		sip_call->call_id = extract_sip_header_field(sip_payload, "Call-ID: ");
		sip_call->source = extract_sip_header_field(sip_payload, "From: ");	
		sip_call->destination = extract_sip_header_field(sip_payload, "To: ");
		sip_call->call_state = CALL_IDLE;

		insert_sip_call(sip_calls, sip_call);

		// Initialize structures for RTP UP-FLOW and DOWN-FLOW 
		sip_call->rtp_upflow = rtp_flow_init();
		if(sip_call->rtp_upflow == NULL)
			return;
		sip_call->rtp_downflow = rtp_flow_init();
		if(sip_call->rtp_downflow == NULL)
			return;

	}

	bool has_sdp = false;
	char * sip_content_length = extract_sip_header_field(sip_payload, "Content-Length:");
	if(sip_content_length != NULL)
	{
		//printf("sip_content_length: %s\n", sip_content_length);
		if(atoi(sip_content_length) > 0)
			has_sdp = true;
	}

	char * host_rtp_audio_port = extract_sip_header_field(sip_payload, "m=audio ");
	if(host_rtp_audio_port != NULL)	// SDP processing
	{
		int audio_port = atoi(host_rtp_audio_port);
		char * host_rtp_addr = extract_sip_header_field(sip_payload, "c=IN IP4 ");
		//printf("nasiel soooooooom port\n");
		if(audio_port != 0 && has_sdp)
		{
			char * sdp_begin = strstr(sip_payload, "\r\n\r\n");
			//if(sdp_begin != NULL)
			//	printf("%s\n", sdp_begin);
			printf("method: %s\n", print_sip_method(method));
			if (method == SIP_INVITE)	// UPFLOW
			{
				sip_call->rtp_upflow->sdp = sdp_begin;
				//printf("UPFLOW\n%s\n", sdp_begin);
				sip_call->rtp_upflow->source_port = atoi(host_rtp_audio_port);
				sip_call->rtp_downflow->destination_port = atoi(host_rtp_audio_port);
				sip_call->rtp_upflow->source_addr = ip_str_to_uint32(host_rtp_addr);
				sip_call->rtp_downflow->destination_addr = ip_str_to_uint32(host_rtp_addr);
				printf("source port/addr: %d/%x\n", sip_call->rtp_upflow->source_port, sip_call->rtp_upflow->source_addr);
			} else {	// DOWNFLOW
				sip_call->rtp_downflow->sdp = sdp_begin;
				//printf("DOWNFLOW\n%s\n", sdp_begin);
				sip_call->rtp_upflow->destination_port = atoi(host_rtp_audio_port);
				sip_call->rtp_downflow->source_port = atoi(host_rtp_audio_port);
				sip_call->rtp_upflow->destination_addr = ip_str_to_uint32(host_rtp_addr);
				sip_call->rtp_downflow->source_addr = ip_str_to_uint32(host_rtp_addr);
				printf("destination port/addr: %d/%x\n", sip_call->rtp_upflow->destination_port, sip_call->rtp_upflow->destination_addr);
			}
		}
	}

	// update Call-State
	if(sip_call->call_state == CALL_IDLE && method == SIP_INVITE)
	{
		sip_call->call_state = CALL_CALLING;
	} 
	else if(sip_call->call_state == CALL_CALLING && method == SIP_CANCEL)
	{
		sip_call->call_state = CALL_TERMINATED_CANCEL;
	}
	else if(sip_call->call_state == CALL_CALLING && method == SIP_ACK)
	{
		sip_call->call_state = CALL_ESTABLISHED;
	}
	else if(sip_call->call_state == CALL_CALLING && method == SIP_REPLY_DECLINE)
	{
		sip_call->call_state = CALL_TERMINATED_DECLINE;
	}
	else if(sip_call->call_state == CALL_CALLING && method == SIP_REPLY_486)
	{
		sip_call->call_state = CALL_TERMINATED_DECLINE;
	}
	else if(sip_call->call_state == CALL_CALLING && ( method == SIP_REPLY_400 || method == SIP_REPLY_500))
	{
		sip_call->call_state = CALL_IDLE;
	}
	else if(sip_call->call_state == CALL_ESTABLISHED && method == SIP_BYE)
	{
		sip_call->call_state = CALL_TERMINATED_BYE;
	}
	else if(sip_call->call_state == CALL_CALLING && method == SIP_REPLY_DECLINE)
	{
		sip_call->call_state = CALL_TERMINATED_CANCEL;
	}

	return 1;	
}

// Convert string with IPv4 address (XXX.XXX.XXX.XXX) to uint32_t
uint32_t ip_str_to_uint32(char * x)
{    
   char ip_str[20];
   strcpy(ip_str, x);
   const char s[2] = ".";
   char *token;
   uint32_t num = 0;
   int ctr = 24;

   token = strtok(ip_str, s);
   
   while( token != NULL ) 
   {      
      num |= (uint32_t)atoi(token) << ctr;
      ctr -= 8;
      token = strtok(NULL, s);
   }
   
   return num;
}

// Process RTP packet
int Process_RTP(TQueueItem *queueItem, uint8_t *payload, uint32_t payload_size, uint8_t *rtp_payload)
{
	// extract header from RTP payload

	CallDirection direction;
	TSipCall * sip_call_to_rtp_flow;

	//printf("RTP: src_pn: %d dst_pn: %d src_ip: %x dst_ip: %x\n", get_port_src( payload + sizeof(L2_header) + sizeof(L3_header) ), get_port_dst( payload + sizeof(L2_header) + sizeof(L3_header) ), get_ip_src( payload + sizeof(L2_header) ), get_ip_dst( payload + sizeof(L2_header) ));

	TRtpFlow * rtp_flow = find_rtp_flow(sip_calls, 
		&direction, 
		sip_call_to_rtp_flow, 
		get_port_src( payload + sizeof(L2_header) + sizeof(L3_header) ), 
		get_port_dst( payload + sizeof(L2_header) + sizeof(L3_header) ), 
		get_ip_src( payload + sizeof(L2_header) ), 
		get_ip_dst( payload + sizeof(L2_header) ));

	/*if(rtp_flow)
	{
		printf("rtp_flow was found");
		if(direction == UPFLOW)
			printf("UPFLOW\n");
		else
			printf("DOWNFLOW\n");
	} else {
		printf("rtp_flow wasn't found");
		return 0;
	}*/

	if(rtp_flow == NULL)
	{
		printf("[DEBUG VoIP] rtp_flow wasn't found\n");
		return 0;
	}

	// RTP payload type
	if(get_rtp_payload_type(rtp_payload) != rtp_flow->payload_type)
	{
		// payload type changed or not initialized
		// find sampling frequency in SDP
		char media_search_buffer[32];
		sprintf(media_search_buffer, "a=rtpmap:%d ", (int)get_rtp_payload_type(rtp_payload));
		if(rtp_flow->sdp != NULL)
		{
			char * media_search = extract_sip_header_field(rtp_flow->sdp, media_search_buffer);
			if(media_search != NULL)
			{
				rtp_flow->media_info = strdup(media_search);
				int freq = atoi((strstr(media_search, "/")+sizeof(char)));
				rtp_flow->codec_freq = freq;
				//printf("frekvencia: %d\n", freq);
				rtp_flow->payload_type = get_rtp_payload_type(rtp_payload);
			}
		}
	}

	// initialize RTP flow sequence number
	if(rtp_flow->sequence_number_base == 0)
	{
		rtp_flow->sequence_number_base = get_rtp_sequence_number(rtp_payload);
	}

	rtp_flow->packet_counter++;
	rtp_flow->last_sequence_number = get_rtp_sequence_number(rtp_payload);

	if(rtp_flow->last_sequence_number > get_rtp_sequence_number(rtp_payload))
	{
		//fprintf(stderr, "[DEBUG VoIP] RTP SN overflow++\n");
		rtp_flow->sn_overflow++;
	}

	// Insert informations extracted from RTP packet 
	TListItem *rtp_info_item = malloc(sizeof(TListItem));
	if(rtp_info_item==NULL)
		return 0;

	TRtpInfo * rtp_info = malloc(sizeof(TRtpInfo));
	if(rtp_info == NULL)
		return 0;

	rtp_info->timestamp = get_rtp_timestamp(rtp_payload);
	rtp_info->sequence_number = get_rtp_sequence_number(rtp_payload);
	rtp_info->arrival_time = (double)queueItem->timestamp.tv_nsec/1000000000 + queueItem->timestamp.tv_sec;

	rtp_info_item->data = (void *) rtp_info;
	slist_insert(rtp_flow->packets, rtp_info_item);

	//printf("Count: %d\n", slist_count_items(rtp_flow->packets));

	bool seq_in_order = false;
	int  packets_lossed = 0;	

	if(rtp_info_item->next != NULL)
	{
		TRtpInfo * previous_rtp_info = (TRtpInfo *) rtp_info_item->next->data;

		if(previous_rtp_info->sequence_number+1 == rtp_info->sequence_number)
		{
			seq_in_order = true;
		} else {
			packets_lossed = rtp_info->sequence_number - previous_rtp_info->sequence_number;
			if(packets_lossed < 0)
				return 1;
		}

		double prev_skew = previous_rtp_info->arrival_time-(double)previous_rtp_info->timestamp/rtp_flow->codec_freq;
		double cur_skew = rtp_info->arrival_time-(double)get_rtp_timestamp(rtp_payload)/rtp_flow->codec_freq;

		rtp_info->Difference = prev_skew - cur_skew;

		// Jitter
		// J(i) = J(i-1) + ( |D(i-1,i)| - J(i-1) )/16

		rtp_info->Jitter = previous_rtp_info->Jitter + (rtp_info->Difference * (rtp_info->Difference < 0? -1: 1) - previous_rtp_info->Jitter) / 16;// + packets_lossed * 0.02;

		// Packet loss

		rtp_info->Packets_expected = (65536 - rtp_flow->sequence_number_base) + ((rtp_flow->sn_overflow)-1)*65536 + get_rtp_sequence_number(rtp_payload) + 1;
		if(rtp_info->Packets_expected < rtp_flow->packet_counter)
		{
			rtp_info->Packets_expected = rtp_flow->packet_counter;
		}
		rtp_info->Packet_loss = (double)((double)(rtp_info->Packets_expected-rtp_flow->packet_counter)/(double)rtp_info->Packets_expected);

	} else {
		rtp_info->Difference = 0;
		rtp_info->Jitter = 0;
		rtp_info->Packet_loss = 0;
	}

	//if(direction==UPFLOW && get_rtp_sequence_number(rtp_payload) % 100 == 0)
	//if(get_rtp_sequence_number(rtp_payload) % 100 == 0)
	/*{
		printf("%d Seq: %d, Timestamp: %f, Arrival time: %f, Difference: %f, Jitter: %f, Packet-loss: %f(recv:%d,exp:%d)\n", 
			direction, 
			get_rtp_sequence_number(rtp_payload), 
			(double)get_rtp_timestamp(rtp_payload)/8000, 
			rtp_info->arrival_time, 
			rtp_info->Difference, 
			rtp_info->Jitter*1000,
			rtp_info->Packet_loss, rtp_flow->packet_counter, rtp_info->Packets_expected );
	}*/

	return 1;
}

char * print_sip_method(Sip_Method sip_method)
{
	switch(sip_method)
	{
		case SIP_UNKNOWN_METHOD: return "SIP_UNKNOWN_METHOD"; break;
		case SIP_INVITE: return "SIP_INVITE"; break;
		case SIP_ACK: return "SIP_ACK"; break;
		case SIP_BYE: return "INVITE"; break;
		case SIP_CANCEL: return "SIP_CANCEL"; break;
		case SIP_OPTIONS: return "SIP_OPTIONS"; break;
		case SIP_REGISTER: return "SIP_REGISTER"; break;
		case SIP_PRACK: return "SIP_PRACK"; break;
		case SIP_SUBSCRIBE: return "SIP_SUBSCRIBE"; break;
		case SIP_NOTIFY: return "SIP_NOTIFY"; break;
		case SIP_PUBLISH: return "SIP_PUBLISH"; break;
		case SIP_INFO: return "SIP_INFO"; break;
		case SIP_REFER: return "SIP_REFER"; break;
		case SIP_MESSAGE: return "SIP_MESSAGE"; break;
		case SIP_UPDATE: return "SIP_UPDATE"; break;
		case SIP_REPLY: return "SIP_REPLY"; break;

		case SIP_REPLY_TRYING: return "SIP_REPLY_TRYING"; break;
		case SIP_REPLY_RINGING: return "SIP_REPLY_RINGING"; break;
		case SIP_REPLY_SUCCESS: return "SIP_REPLY_SUCCESS"; break;
		case SIP_REPLY_OK: return "SIP_REPLY_OK"; break;
		case SIP_REPLY_DIALOG_ESTABLISHEMENT: return "SIP_REPLY_DIALOG_ESTABLISHEMENT"; break;
		case SIP_REPLY_REQUEST_CANCELLED: return "SIP_REPLY_REQUEST_CANCELLED"; break;
	}
	return "UNKNOWN_METHOD";
}

char * print_sip_call_state(CallState call_state)
{
	switch(call_state)
	{
		case CALL_IDLE: return "CALL_IDLE"; break;
		case CALL_CALLING: return "CALL_CALLING"; break;
		case CALL_ESTABLISHED: return "CALL_ESTABLISHED"; break;
		case CALL_TERMINATED_BYE: return "CALL_TERMINATED_BYE"; break;
		case CALL_TERMINATED_CANCEL: return "CALL_TERMINATED_CANCEL"; break;
		case CALL_TERMINATED_DECLINE: return "CALL_TERMINATED_DECLINE"; break;
	}
	return "UNKNOWN STATE";
}

void dump_sip_calls(TList * list)
{

	if(list == NULL)
		return NULL;
	printf("\e[1;1H\e[2J");
	printf("Call-Table\n");

	TListItem *item;
	unsigned int call_counter = 0;

	for(item = list->first; item != NULL; item = item->next)
	{
		call_counter++;
		TSipCall *call = (TSipCall*) item->data;

		if(call->call_state >= CALL_CALLING)
		{
			switch(call->call_state)
			{
				case CALL_CALLING:
					printf(ANSI_COLOR_YELLOW);
				break;
				case CALL_ESTABLISHED:
					printf(ANSI_COLOR_GREEN);
				break;
				case CALL_TERMINATED_DECLINE:
				case CALL_TERMINATED_CANCEL:
				case CALL_TERMINATED_BYE:
					printf(ANSI_COLOR_RED);
				break;
				default:
				break;				
			}
			printf("\n""Call-ID: %s (%s -> %s), state: %s\n", call->call_id, call->source, call->destination, print_sip_call_state(call->call_state));
			if(call->rtp_upflow->packets->first != NULL)
			{
				char * media_info = "unknown";
				if((TRtpInfo *)call->rtp_upflow->media_info != NULL)
				{
					media_info = (TRtpInfo *)call->rtp_upflow->media_info;
				}
				printf("---> UPFLOW (media: %s): Jitter: %.2f ms, Packet-loss: %.2f \% (recv: %d, exp: %d)\n", 
					media_info,
					((TRtpInfo *)call->rtp_upflow->packets->first->data)->Jitter*1000,
					((TRtpInfo *)call->rtp_upflow->packets->first->data)->Packet_loss*100,
					call->rtp_upflow->packet_counter,
					((TRtpInfo *)call->rtp_upflow->packets->first->data)->Packets_expected);
			}
			if(call->rtp_downflow->packets->first != NULL)
			{
				char * media_info = "unknown";
				if((TRtpInfo *)call->rtp_downflow->media_info != NULL)
				{
					media_info = (TRtpInfo *)call->rtp_downflow->media_info;
				}
				printf("<--- DOWNFLOW (media: %s): Jitter: %.2f ms, Packet-loss: %.2f \% (recv: %d, exp: %d)\n",
					media_info,
					((TRtpInfo *)call->rtp_downflow->packets->first->data)->Jitter*1000,
					((TRtpInfo *)call->rtp_downflow->packets->first->data)->Packet_loss*100,
					call->rtp_downflow->packet_counter,
					((TRtpInfo *)call->rtp_downflow->packets->first->data)->Packets_expected);
			}
			printf(ANSI_COLOR_RESET);
		}

	}

}

void *info_thread(void *a)
{
	while(1)
	{
		//printf("VoIP INFO():\n");

		dump_sip_calls(sip_calls);
		sleep(1);
	}
}

void print_hex(uint8_t *mem, int length) 
{
  int i;
  uint8_t *p = (uint8_t *)mem;
  //printf("%x\n", mem[0]);
  for (i=1;i<=length;i++) {
  	if ((i-1)%8==0)
      printf("%5.d  ", (i-1));
    printf("0x%02x ", p[i-1]);
    //printf("%d\n", i);
    if (i%8==0)
      printf("\n");
  }
  printf("\n");
}