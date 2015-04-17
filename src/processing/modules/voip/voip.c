#include "voip.h"
#include "sip_calls.h"

TList *sip_calls = NULL;

void Voip_initialize()
{
	// initialize list with call informations extracted from SIP
	sip_calls = malloc(sizeof(TList));
	if(sip_calls == NULL)
		return;
	slist_init(sip_calls);
}

/*


-INVITE, -ACK, -BYE, -CANCEL, -OPTIONS, -REGISTER, -PRACK, -SUBSCRIBE, -NOTIFY, -PUBLISH, -INFO, -REFER, -MESSAGE, -UPDATE
*/

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
				//printf("(%d)%s\n", strlen(sip_payload), sip_payload);
				//getchar();
				//char * reply = strtok( (char *)sip_payload, "\n");

				//printf("%s\n", reply);
				if( strstr(sip_payload, "Trying") != NULL)
				{
					return SIP_REPLY_TRYING;
				} else if( strstr(sip_payload, "Ringing") != NULL)
				{
					return SIP_REPLY_RINGING;
				} else if( strstr(sip_payload, "Success") != NULL)
				{
					return SIP_REPLY_SUCCESS;
				} else if( strstr(sip_payload, "OK") != NULL)
				{
					return SIP_REPLY_OK;
				}
				else if( strstr(sip_payload, "Dialog Establishement") != NULL)
				{
					return SIP_REPLY_DIALOG_ESTABLISHEMENT;
				}
				else if( strstr(sip_payload, "Request Cancelled") != NULL)
				{
					return SIP_REPLY_REQUEST_CANCELLED;
				}
				printf("%s\n", sip_payload);
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

void Voip(TQueueItem* start, TQueueItem* stop)
{

	if(sip_calls == NULL)
	{
		Voip_initialize();		
	}

	printf("voip\n");

	//printf("VoIP processing began!!!\n");

	TQueueItem *item = start;
	int i;
	while(item != NULL)
	{
		TPacket* packet = (TPacket*)item->packet;
		printf("packet!\n");
	

		// match SIP packets

		uint8_t * payload;
		uint32_t payload_size;
		onep_status_t s = onep_dpss_pkt_get_l2_start(item->packet, &payload, &payload_size);
		//printf("onep_dpss_pkt_get_l2_start:%d %d %d\n", s, (s == ONEP_OK), (s == ONEP_ERR_BAD_ARGUMENT));

		// TODO - moze byt aj cez TCP ... !!!
		uint32_t offset_to_siprtp = sizeof(L2_header) + sizeof(L3_header) + sizeof(UDP_header);
		uint8_t *siprtp_payload = payload + offset_to_siprtp;

		//printf("x0:%s\n", sip_payload);
		Sip_Method find_method = get_sip_method(siprtp_payload);
		//printf("x0\n");


		if(find_method != SIP_UNKNOWN_METHOD)
		{
			printf("sip\n");
			// replace \0 characters with \n characters
			//int i;
			
			for(i = offset_to_siprtp; i < payload_size; i++)
			{
				//printf("%c(%d) ", *(payload + i), *(payload + i));
				if(*(payload + i) == '\0')
				{
					*(payload + i) = '\n';
					//printf("menim\n");
				}				
			}

			//printf("payload length: %d\n", strlen(siprtp_payload));
			//printf("%s\n", siprtp_payload);
			/*char a; i = 0;
			while(strlen(siprtp_payload) < 50)
			{
				printf("%c (%d)\n", *(siprtp_payload+(i)), *(siprtp_payload+(i)));
				i++;
				getchar();
			}*/
			//printf("x2: %d\n", strlen(siprtp_payload));
			Process_SIP(siprtp_payload);
			//printf("x2\n");
		} else {
			Process_RTP(siprtp_payload);
		}
		// packet processing routine - SIP and RTP

		// extract SOURCE IP, DESTINATION_IP, SOURCE_PORT, DESTINATION_PORT
		item = GetNextItem(item, stop);
	}
	printf("koncim\n");
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
	printf("Processing SIP\n");
	// get SIP method
	Sip_Method method = get_sip_method(sip_payload);
	//printf("x4: %d\n", strlen(sip_payload));
	//printf("Method: %s\n", print_sip_method(method));

	// extract SIP Call-ID
	//printf("x0: %d\n", strlen(sip_payload));
	char * current_call_id = get_sip_call_id(sip_payload);
	if(current_call_id == NULL)
	{
		// do not process, we cannot find Call-ID .. maybe incorrect SIP packet
		printf("Cannot find Call-ID.\n");
		//return NULL;
	} else {	
		//printf("Call-ID: %s\n", current_call_id);
	}
	//printf("%s\n", sip_payload);
	//getchar();

	// find this sip call

	TSipCall * sip_call = find_sip_call(sip_calls, current_call_id);
	if(sip_call == NULL)
	{
		sip_call = malloc(sizeof(TSipCall));
		if(sip_call == NULL)
			return 0;
		sip_call->call_id = extract_sip_header_field(sip_payload, "Call-ID: ");
		sip_call->source = extract_sip_header_field(sip_payload, "From: ");	
		sip_call->destination = extract_sip_header_field(sip_payload, "To: ");
		sip_call->call_state = CALL_INITIALIZED;

		insert_sip_call(sip_calls, sip_call);

		sip_call->rtp_flow = (TRtpFlow *)malloc(sizeof(TRtpFlow));
		if(sip_call->rtp_flow == NULL)
			return;

		//printf("Vytvoril som\n");

	}

	/* Try to find the RTP port on which host will be waiting for the RTP packets */

	if(method == SIP_INVITE)
	{
		printf("(%d)%s\n", strlen(sip_payload), sip_payload);
		int i;		
		for(i=0; ; i++)
		{
			printf("%c (%d)\n", sip_payload[i], sip_payload[i] );
			if(i%10==0)
			{
				getchar();
			}
		}
	}

	char * host_rtp_audio_port = extract_sip_header_field(sip_payload, "m=audio ");
	if(host_rtp_audio_port != NULL)
	{
		int audio_port = atoi(host_rtp_audio_port);
		printf("nasiel soooooooom port\n");
		if(audio_port != 0)
		{
			if (method == SIP_INVITE)
			{
				sip_call->rtp_flow->source_port = atoi(host_rtp_audio_port);
				printf("source port: %d\n", sip_call->rtp_flow->source_port);
			} else {
				sip_call->rtp_flow->destination_port = atoi(host_rtp_audio_port);
				printf("destination port: %d\n", sip_call->rtp_flow->destination_port);
			}
		}
		getchar();
		
	}

	// stavovy diagram prechodov medzi SIP stavmi

	if(sip_call->call_state == CALL_INITIALIZED && method == SIP_INVITE)
	{
		sip_call->call_state = CALL_INVITED;
		printf("%s : %s\n", sip_call->call_id, print_sip_call_state(sip_call->call_state));
	} 
	else if(sip_call->call_state == CALL_INVITED && method == SIP_REPLY_TRYING)
	{
		sip_call->call_state = CALL_TRYING;
		printf("%s : %s\n", sip_call->call_id, print_sip_call_state(sip_call->call_state));
	}
	else if(sip_call->call_state == CALL_TRYING && method == SIP_REPLY_OK)
	{
		sip_call->call_state = CALL_IN_PROGRESS;
		printf("%s : %s\n", sip_call->call_id, print_sip_call_state(sip_call->call_state));
	}
	else if(sip_call->call_state == CALL_TRYING && method == SIP_CANCEL)
	{
		sip_call->call_state = CALL_DROPPED;
		printf("%s : %s\n", sip_call->call_id, print_sip_call_state(sip_call->call_state));
	}
	else if(sip_call->call_state == CALL_TRYING && method == SIP_REPLY_DECLINE)
	{
		sip_call->call_state = CALL_DROPPED;
		printf("%s : %s\n", sip_call->call_id, print_sip_call_state(sip_call->call_state));
	}
	else if(sip_call->call_state == CALL_IN_PROGRESS && method == SIP_BYE)
	{
		sip_call->call_state = CALL_DROPPED;
		printf("%s : %s\n", sip_call->call_id, print_sip_call_state(sip_call->call_state));
	}

	return 1;	
}

int Process_RTP()
{
	// extract header from RTP payload





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
}

char * print_sip_call_state(CallState call_state)
{
	switch(call_state)
	{ 	case CALL_INITIALIZED: return "CALL_INITIALIZED"; break;
		case CALL_INVITED: return "CALL_INVITED"; break;
		case CALL_TRYING: return "CALL_TRYING"; break;
		case CALL_CANCELED: return "CALL_CANCELED"; break;
		case CALL_IN_PROGRESS: return "CALL_IN_PROGRESS"; break;
		case CALL_DROPPED: return "CALL_DROPPED"; break;
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