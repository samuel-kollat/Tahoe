#include "dns.h"

void AnalyzeDns(TQueueItem* start, TQueueItem* stop, TQueueCallbackArgs args)
{
    TQueueItem* item = start;

    while(item != NULL)
    {
        TPacket* packet = (TPacket*)item->packet;
        Analyze(packet);

        item = GetNextItem(item, stop);
    }
}

void Analyze(TPacket* packet)
{
    // Get payload
    uint8_t* payload;
    uint32_t payload_size;
    onep_status_t s = onep_dpss_pkt_get_l2_start((onep_dpss_paktype_t*)packet, &payload, &payload_size);
    if(s != ONEP_OK)
    {
        printf("onep_dpss_pkt_get_l2_start:%d %d %d\n", s, (s == ONEP_OK), (s == ONEP_ERR_BAD_ARGUMENT));
        return;
    }

    // Parse payload
    l2_header l2;
    l3_header l3;
    udp_header udp;
    dns_message query;

    parse_l2_header(payload, &l2);
    parse_l3_header(payload, &l3);
    parse_l4_udp_header(payload, &udp);
    parse_dns_message(payload, payload_size, &query);

    if(query.status == DNS_OK)
    {
        // Store parsed DNS data
        store_dns_message(&l3, &udp, &query);

        // DEBUG
        uint32_t i;
        for(i = 0; i < payload_size; i++)
        {
            printf("| %02x ", payload[i]);
        }
        printf("\nEnd.\n\n");

        // DEBUG
        TResolutionItem* item = get_dns_resolutions_list();
        while(item != NULL)
        {
            print_dns_resolution_data(item);
            item = item->next;
        }
    }

    return;
}