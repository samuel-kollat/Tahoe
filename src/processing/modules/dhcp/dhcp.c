#include "dhcp.h"

static bool data_ready_for_storing = false;

void AnalyzeDhcp(TQueueItem* start, TQueueItem* stop, TQueueCallbackArgs args)
{
    TQueueItem* item = start;

    while(item != NULL)
    {
        TPacket* packet = (TPacket*)item->packet;
        DhcpAnalyze(packet);

        item = GetNextItem(item, stop);
    }
}

bool DhcpDataReady()
{
    return data_ready_for_storing;
}

void DhcpDataPrepare()
{
    data_ready_for_storing = false;
}

void DhcpDataCondition()
{
    data_ready_for_storing = true;
}

void DhcpStore()
{
    printf("Store...\n");
    return;
}

void DhcpAnalyze(TPacket* item)
{
    // Get payload
    uint8_t* payload;
    uint32_t payload_size;
    onep_status_t s = onep_dpss_pkt_get_l2_start((onep_dpss_paktype_t*)item, &payload, &payload_size);
    if(s != ONEP_OK)
    {
        printf("onep_dpss_pkt_get_l2_start:%d %d %d\n", s, (s == ONEP_OK), (s == ONEP_ERR_BAD_ARGUMENT));
        return;
    }

    // Parse payload
    l2_header l2;
    l3_header l3;
    udp_header udp;
    dhcp_message message;

    parse_l2_header(payload, &l2);
    parse_l3_header(payload, &l3);
    parse_l4_udp_header(payload, &udp);
    parse_dhcp_message(payload, payload_size, &message);

    printf("\nDHCP:\n");
    printf("\tOp: %u\n", message.op);
    printf("\tXid: %u\n", message.xid);
    printf("\tSname: %s\n", message.sname);
    printf("\tMagic Cookie: %02x %02x %02x %02x\n",
        message.magic_cookie[0], message.magic_cookie[1], message.magic_cookie[2], message.magic_cookie[3]);
    printf("\tOptions:\n");
    printf("\t\tType: %u\n", message.options.dhcp_message_type);
    printf("\t\tHost Name: %s\n", message.options.host_name);

    int i = 0;
    while(message.options.parameter_request_list[i] != PAD)
    {
        printf("\t\tRequest: %u\n", message.options.parameter_request_list[i]);
        i++;
    }

    return;
}