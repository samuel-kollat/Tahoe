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

TSipCall * find_sip_call(TList * list, char * call_id)
{
	if(list == NULL)
		return NULL;

	TListItem *item;
	// DO DP -> mozna optimalizacia po uspesnom vyhladani presun hovoru na zaciatok zoznamu
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


TRtpFlow * find_rtp_flow_by_ports(TList * list, CallDirection *direction, TSipCall * sip_call, unsigned int src_port, unsigned int dst_port)
{
	if(list == NULL)
		return NULL;

	TListItem *item;

	for(item = list->first; item != NULL; item = item->next)
	{
		//printf("src_port: %d, dst_port: %d, upflow-src: %d, upflow-dst: %d, downflow-src: %d, downflow-dst: %d\n", src_port, dst_port, ((TSipCall *) item->data)->rtp_upflow->source_port, ((TSipCall *) item->data)->rtp_upflow->destination_port, ((TSipCall *) item->data)->rtp_downflow->source_port, ((TSipCall *) item->data)->rtp_downflow->destination_port);
		if(  ((TSipCall *) item->data)->rtp_upflow->source_port == src_port && ((TSipCall *) item->data)->rtp_upflow->destination_port == dst_port )
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
		else if(  ((TSipCall *) item->data)->rtp_downflow->source_port == src_port && ((TSipCall *) item->data)->rtp_downflow->destination_port == dst_port )
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

