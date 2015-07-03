#include "http_statistics.h"

static THttpStats* head = NULL;

uint32_t get_hash(uint8_t src_ip[], uint8_t dst_ip[],
    uint16_t src_port, uint16_t dst_port, THttpMethod method)
{
    char string[37];
    sprintf(string, "%03u%03u%03u%03u%03u%03u%03u%03u%05u%05u%02u",
        src_ip[0],src_ip[1], src_ip[2], src_ip[3],
        dst_ip[0],dst_ip[1], dst_ip[2], dst_ip[3],
        src_port, dst_port, method);

    return FastHash(string, 36);
}

THttpStats* find_record_with_hash(uint32_t hash)
{
    THttpStats* rec = head;
    while(rec != NULL)
    {
        if(rec->hash == hash)
        {
            return rec;
        }
        rec = rec->next;
    }

    return NULL;
}

void store_http_data(l3_header* l3, tcp_header* tcp, THttpData* data)
{
    if(data->genuine != true)
    {
        return;
    }

    uint32_t hash = get_hash(l3->source_ip, l3->destination_ip,
        tcp->source_port, tcp->destination_port, data->method);

    THttpStats* record = find_record_with_hash(hash);

    if(record != NULL)
    {
        // Update
        record->quantity += data->quantity;
    }
    else
    {
        THttpStats* new_stats = (THttpStats*) malloc(sizeof(THttpStats));

        // Data
        new_stats->hash = hash;
        new_stats->source_ip[0] = l3->source_ip[0];
        new_stats->source_ip[1] = l3->source_ip[1];
        new_stats->source_ip[2] = l3->source_ip[2];
        new_stats->source_ip[3] = l3->source_ip[3];
        new_stats->destination_ip[0] = l3->destination_ip[0];
        new_stats->destination_ip[1] = l3->destination_ip[1];
        new_stats->destination_ip[2] = l3->destination_ip[2];
        new_stats->destination_ip[3] = l3->destination_ip[3];
        new_stats->source_port = tcp->source_port;
        new_stats->destination_port = tcp->destination_port;
        new_stats->method = data->method;
        new_stats->quantity = data->quantity;

        new_stats->next = head;
        head = new_stats;
    }

    return;
}

void print_list_item(THttpStats* item)
{
    printf("\nList Item:\n");
    printf("\tSrc Port: %u\n", item->source_port);
    printf("\tDst Port: %u\n", item->destination_port);
    printf("\tMethod: %u\n", item->method);
    printf("\tQuantity: %u\n", item->quantity);
}

void print_list()
{
    THttpStats* item = head;
    while(item != NULL)
    {
        print_list_item(item);
        item = item->next;
    }
}