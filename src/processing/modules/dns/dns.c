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
    printf("Analyzing ...\n");

    uint8_t* payload;
    uint32_t payload_size;
    onep_status_t s = onep_dpss_pkt_get_l2_start((onep_dpss_paktype_t*)packet, &payload, &payload_size);
    if(s != ONEP_OK)
    {
        printf("onep_dpss_pkt_get_l2_start:%d %d %d\n", s, (s == ONEP_OK), (s == ONEP_ERR_BAD_ARGUMENT));
        return;
    }

    uint32_t i;
    for(i = 0; i < payload_size; i++)
    {
        printf("| %02x ", payload[i]);
    }
    printf("\nEnd.\n\n");

    l2_header l2;
    l3_header l3;
    udp_header udp;
    dns_message query;

    parse_l2_header(payload, &l2);
    parse_l3_header(payload, &l3);
    parse_l4_udp_header(payload, &udp);
    parse_dns_message(payload, payload_size, &query);

    printf("SRC IP: %u.%u.%u.%u\n", l3.source_ip[0], l3.source_ip[1], l3.source_ip[2], l3.source_ip[3]);
    printf("DST IP: %u.%u.%u.%u\n", l3.destination_ip[0], l3.destination_ip[1], l3.destination_ip[2], l3.destination_ip[3]);

    printf("SRC PORT: %u\n", udp.source_port);
    printf("DST PORT: %u\n", udp.destination_port);

    if(query.query->query_domain_name == NULL)
    {
        fprintf(stderr, "No domain to query.\n");
        return;
    }
    printf("DNS QUERY DOMAIN: ");
    i = 0;
    char c = (char)query.query->query_domain_name[i];
    while(c != '\0')
    {
        if(c < 33)
        {
            printf(".");
        }
        else
        {
            printf("%c", c);
        }
        i++;
        c = (char)query.query->query_domain_name[i];
    }
    printf("\n\n");

    return;
}