/* * * * * * * * * * * * * * * * * * * * *
 *              O n e M o n              *
 *                                       *
 * File: sip_calls.c                     *
 * Author: David Antolik                 *
 *                                       *
 * * * * * * * * * * * * * * * * * * * * */

#include "sip_calls.h"
#include <stdio.h>
#include <stdlib.h>

/*

- implement SIP calls table (hash table), index is Call-ID
- implement functions - search, insert and functions for state management of SIP session

*/

int slist_init(TList * list)
{
	if(list == NULL)
		return 0;

	list->first = NULL;

	return 1;
}

int slist_insert(TList * list, TListItem * item)
{
	if(list == NULL)
		return 0;

	item->next = list->first;
	list->first = item;

	return 1;
}

int slist_delete(TList * list, TListItem * item)
{
	if(list == NULL)
		return 0;

	TListItem *last_item = NULL;
	TListItem *item_it = list->first;
	while(item_it != NULL)
	{
		if(item == item_it)
		{
			if(last_item == NULL)
			{
				list->first = item->next;
			} else {
				last_item->next = item->next;
			}
			free(item);
		}
		last_item = item;
		item_it = item_it->next;
	}

	return 1;
}

int slist_count_items(TList * list)
{
	int count = 0;
	TListItem *item = list->first;
	while(item != NULL)
	{
		count++;
		item = item->next;
	}
	return count;
}

TSipCall * find_sip_call(TList * list, char * call_id)
{
	if(list == NULL)
		return NULL;

	TListItem *item;
	// + optimize
	for(item = list->first; item != NULL; item = item->next)
	{
		if( strcmp( ((TSipCall *) item->data)->call_id, call_id ) == 0)
		{
			return (TSipCall *) (item->data);
		}

		//printf("%d\n", ((TSipCall *) item->data)->call_id );
	}
	return NULL;
}



TRtpFlow * find_rtp_flow(TList * list, CallDirection *direction, TSipCall * sip_call, uint16_t src_port, uint16_t dst_port, uint32_t src_ip, uint32_t dst_ip)
{
	if(list == NULL)
		return NULL;

	TListItem *item;

	for(item = list->first; item != NULL; item = item->next)
	{
		if( ((TSipCall *) item->data)->rtp_upflow == NULL || ((TSipCall *) item->data)->rtp_downflow == NULL)
		{
			continue;
		}
		if( ((TSipCall *) item->data)->call_state != CALL_ESTABLISHED )
		{
			continue;
		}
		/*printf("src: %d/%x, dst: %d/%x, upflow-src: %d/%x, upflow-dst: %d/%x, downflow-src: %d/%x, downflow-dst: %d/%x\n", 
			src_port, 
			src_ip,
			dst_port,
			dst_ip, 
			((TSipCall *) item->data)->rtp_upflow->source_port, 
			((TSipCall *) item->data)->rtp_upflow->source_addr, 
			((TSipCall *) item->data)->rtp_upflow->destination_port, 
			((TSipCall *) item->data)->rtp_upflow->destination_addr, 
			((TSipCall *) item->data)->rtp_downflow->source_port,
			((TSipCall *) item->data)->rtp_downflow->source_addr, 
			((TSipCall *) item->data)->rtp_downflow->destination_port,
			((TSipCall *) item->data)->rtp_downflow->destination_addr
		);*/
		if(  ((TSipCall *) item->data)->rtp_upflow->source_port == src_port && 
			 ((TSipCall *) item->data)->rtp_upflow->destination_port == dst_port &&
			 ((TSipCall *) item->data)->rtp_upflow->source_addr == src_ip &&
			 ((TSipCall *) item->data)->rtp_upflow->destination_addr == dst_ip
		  )
		{
			if(direction != NULL)
			{
				*direction = UPFLOW;
			}
			if(sip_call != NULL)
			{
				sip_call = (TSipCall *) (item->data);
			}
			return (TRtpFlow *) (((TSipCall *) (item->data)) -> rtp_upflow);
		}
		else if(  
			((TSipCall *) item->data)->rtp_downflow->source_port == src_port && 
			((TSipCall *) item->data)->rtp_downflow->destination_port == dst_port &&
			((TSipCall *) item->data)->rtp_downflow->source_addr == src_ip &&
			((TSipCall *) item->data)->rtp_downflow->destination_addr == dst_ip
			)
		{
			if(direction != NULL)
			{
				*direction = DOWNFLOW;
			}
			if(sip_call != NULL)
			{
				sip_call = (TSipCall *) (item->data);
			}
			return (TRtpFlow *) (((TSipCall *) (item->data)) -> rtp_downflow);
		}

		//printf("%d\n", ((TSipCall *) item->data)->call_id );
	}
	printf("find exit\n");
	return NULL;
}

void insert_sip_call(TList * list, TSipCall * sip_call)
{
	if(list == NULL)
		return;

	TListItem * new_list_item = malloc(sizeof(TListItem));
	if(new_list_item == NULL)
		return;

	new_list_item->data = (void *)sip_call;

	slist_insert(list, new_list_item);
}


TRtpFlow * rtp_flow_init()
{
	TRtpFlow * ret;
	ret = (TRtpFlow *)malloc(sizeof(TRtpFlow));
	if(ret == NULL)
		return NULL;
	ret->packets = malloc(sizeof(TList));
	if(ret->packets == NULL)
	{
		free(ret);
		return NULL;
	}
	slist_init(ret->packets);
	ret->arrival_time_base = 0;
	ret->sequence_number_base = 0;
	ret->last_sequence_number = 0;
	ret->sn_overflow = 0;
	ret->sdp = NULL;
	ret->media_info = NULL;
	ret->payload_type = 0;
	ret->codec_freq = 8000;
	return ret;
}

