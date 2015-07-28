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

void DhcpAnalyze(TPacket* packet)
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
    dhcp_message message;

    parse_l2_header(payload, &l2);
    parse_l3_header(payload, &l3);
    parse_l4_udp_header(payload, &udp);
    parse_dhcp_message(payload, payload_size, &message);

    // Debug
    DhcpPrint(&message);

    // Create DHCPOFFER
    if(message.options.dhcp_message_type == DHCPDISCOVER)
    {
        onep_dpss_paktype_t* pkt = (onep_dpss_paktype_t*)packet;

        /*

        // Change DHCP values
        uint8_t op[1] = {BOOT_REPLY};
        onep_dpss_modify_packet(pkt, ONEP_DPSS_LAYER_7, 0, 1, op, 1);

        uint8_t yiaddr[4] = {10, 130, 10, 201};
        onep_dpss_modify_packet(pkt, ONEP_DPSS_LAYER_7, 16, 4, yiaddr, 4);

        uint8_t* siaddr= src_ip;
        onep_dpss_modify_packet(pkt, ONEP_DPSS_LAYER_7, 20, 4, siaddr, 4);*/

        // Change source ip
        int l3_offset = L2_HEADER_LENGTH;
        payload[l3_offset + 12] = 10;
        payload[l3_offset + 13] = 130;
        payload[l3_offset + 14] = 10;
        payload[l3_offset + 15] = 101;

        // Change checksum
        payload[l3_offset + 10] = 0;
        payload[l3_offset + 11] = 0;
        uint16_t cksum = ipv4_checksum(&(payload[l3_offset]), L3_HEADER_LENGTH);
        payload[l3_offset + 10] = cksum%256;
        payload[l3_offset + 11] = cksum/256;

        // Change ports
        int l4_offset = L2_HEADER_LENGTH + L3_HEADER_LENGTH;
        payload[l4_offset + 0] = udp.destination_port/256;
        payload[l4_offset + 1] = udp.destination_port%256;
        payload[l4_offset + 2] = udp.source_port/256;
        payload[l4_offset + 3] = udp.source_port%256;

        // Change DHCP values
        int l7_offset = L2_HEADER_LENGTH + L3_HEADER_LENGTH + UDP_HEADER_LENGTH;
        payload[l7_offset + 0] = BOOT_REPLY;

        payload[l7_offset + 16] = 10;
        payload[l7_offset + 17] = 130;
        payload[l7_offset + 18] = 10;
        payload[l7_offset + 19] = 201;

        payload[l7_offset + 20] = 10;
        payload[l7_offset + 21] = 130;
        payload[l7_offset + 22] = 10;
        payload[l7_offset + 23] = 101;

        payload[message.options.dhcp_message_type_l2_offset] = DHCPOFFER;


        // Get input interface
        onep_network_interface_t* intf;
        onep_dpss_pkt_get_input_interface(pkt, &intf);

        onep_status_t s = onep_dpss_inject_raw_packet(GetNetworkElement(), payload, payload_size, 0, intf, ONEP_TARGET_LOCATION_HARDWARE_DEFINED_OUTPUT);

        printf("STATUS: %u\n", s);
    }

    return;
}

void DhcpPrint(dhcp_message* message)
{
    printf("\nDHCP:\n");
    printf("\tOp: %u\n", message->op);
    printf("\tXid: %u\n", message->xid);
    printf("\tSname: %s\n", message->sname);
    printf("\tMagic Cookie: %02x %02x %02x %02x\n",
        message->magic_cookie[0], message->magic_cookie[1], message->magic_cookie[2], message->magic_cookie[3]);
    printf("\tOptions:\n");
    printf("\t\tType: %u\n", message->options.dhcp_message_type);
    printf("\t\tHost Name: %s\n", message->options.host_name);

    int i = 0;
    while(message->options.parameter_request_list[i] != PAD)
    {
        printf("\t\tRequest: %u\n", message->options.parameter_request_list[i]);
        i++;
    }
}