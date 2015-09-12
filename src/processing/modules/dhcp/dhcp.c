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
    // Packet size
    uint32_t response_size = L2_HEADER_LENGTH + L3_HEADER_LENGTH + UDP_HEADER_LENGTH + MINIMAL_DHCP_PACKET_SIZE + 1; // +1 is hotfix for parser

    // Get payload
    uint8_t* payload;
    uint8_t* response = (uint8_t*)malloc(response_size * sizeof(uint8_t));
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

    printf("Payload size: %u\n", payload_size);

    // Debug
    DhcpPrint(&message);

    // Create DHCPOFFER
    if(message.options.dhcp_message_type == DHCPDISCOVER)
    {
        onep_dpss_paktype_t* pkt = (onep_dpss_paktype_t*)packet;

        // Copy payload to response
        int i;
        for(i = 0; i < response_size ; i++)
        {
            response[i] = payload[i];
        }

        /*

        // Change DHCP values
        uint8_t op[1] = {BOOT_REPLY};
        onep_dpss_modify_packet(pkt, ONEP_DPSS_LAYER_7, 0, 1, op, 1);

        uint8_t yiaddr[4] = {10, 130, 10, 201};
        onep_dpss_modify_packet(pkt, ONEP_DPSS_LAYER_7, 16, 4, yiaddr, 4);

        uint8_t* siaddr= src_ip;
        onep_dpss_modify_packet(pkt, ONEP_DPSS_LAYER_7, 20, 4, siaddr, 4);*/

        // Change destination MAC
        int l2_offset = 0;
        response[l2_offset + 0] = payload[l2_offset + 6];
        response[l2_offset + 1] = payload[l2_offset + 7];
        response[l2_offset + 2] = payload[l2_offset + 8];
        response[l2_offset + 3] = payload[l2_offset + 9];
        response[l2_offset + 4] = payload[l2_offset + 10];
        response[l2_offset + 5] = payload[l2_offset + 11];

        // Change source MAC
        response[l2_offset + 6] = 0;
        response[l2_offset + 7] = 0;
        response[l2_offset + 8] = 171;
        response[l2_offset + 9] = 233;
        response[l2_offset + 10] = 218;
        response[l2_offset + 11] = 2;

        // Change source ip
        int l3_offset = L2_HEADER_LENGTH;
        response[l3_offset + 12] = 10;
        response[l3_offset + 13] = 120;
        response[l3_offset + 14] = 10;
        response[l3_offset + 15] = 100;

        // Change destination ip
        /*response[l3_offset + 16] = 10;
        response[l3_offset + 17] = 120;
        response[l3_offset + 18] = 10;
        response[l3_offset + 19] = 1;*/

        // Change checksum
        response[l3_offset + 10] = 0;
        response[l3_offset + 11] = 0;
        uint16_t cksum = ipv4_checksum(&(response[l3_offset]), L3_HEADER_LENGTH);
        response[l3_offset + 10] = cksum%256;
        response[l3_offset + 11] = cksum/256;

        // Change ports
        int l4_offset = L2_HEADER_LENGTH + L3_HEADER_LENGTH;
        response[l4_offset + 0] = udp.destination_port/256;
        response[l4_offset + 1] = udp.destination_port%256;
        response[l4_offset + 2] = udp.source_port/256;
        response[l4_offset + 3] = udp.source_port%256;

        // Change DHCP values
        int l7_offset = L2_HEADER_LENGTH + L3_HEADER_LENGTH + UDP_HEADER_LENGTH;
        response[l7_offset + 0] = BOOT_REPLY;

        // Offered address
        response[l7_offset + 16] = 10;
        response[l7_offset + 17] = 120;
        response[l7_offset + 18] = 10;
        response[l7_offset + 19] = 2;

        // Server address
        response[l7_offset + 20] = 10;
        response[l7_offset + 21] = 120;
        response[l7_offset + 22] = 10;
        response[l7_offset + 23] = 100;

        // Option 53
        response_size += 3;
        response = (uint8_t*)realloc(response, response_size * sizeof(uint8_t)); // NULL check needed
        response[message.options.dhcp_message_type_l2_offset - 2] = 53;
        response[message.options.dhcp_message_type_l2_offset - 1] = 1;
        response[message.options.dhcp_message_type_l2_offset] = DHCPOFFER;

        // Option 1
        response_size += 6;
        response = (uint8_t*)realloc(response, response_size * sizeof(uint8_t)); // NULL check needed
        response[response_size - 6] = 1;    // Type
        response[response_size - 5] = 4;    // Length
        response[response_size - 4] = 255;
        response[response_size - 3] = 255;
        response[response_size - 2] = 255;
        response[response_size - 1] = 0;

        // Option 28
        response_size += 6;
        response = (uint8_t*)realloc(response, response_size * sizeof(uint8_t)); // NULL check needed
        response[response_size - 6] = 28;    // Type
        response[response_size - 5] = 4;    // Length
        response[response_size - 4] = 10;
        response[response_size - 3] = 120;
        response[response_size - 2] = 10;
        response[response_size - 1] = 255;

        // Option 2
        /*response_size += 6;
        response = (uint8_t*)realloc(response, response_size * sizeof(uint8_t)); // NULL check needed
        response[response_size - 6] = 2;    // Type
        response[response_size - 5] = 4;    // Length
        response[response_size - 4] = 0;
        response[response_size - 3] = 0;
        response[response_size - 2] = 0;
        response[response_size - 1] = 0;*/

        // Option 3
        response_size += 6;
        response = (uint8_t*)realloc(response, response_size * sizeof(uint8_t)); // NULL check needed
        response[response_size - 6] = 3;    // Type
        response[response_size - 5] = 4;    // Length
        response[response_size - 4] = 10;
        response[response_size - 3] = 120;
        response[response_size - 2] = 10;
        response[response_size - 1] = 100;

        // Option 15
        response_size += 8;
        response = (uint8_t*)realloc(response, response_size * sizeof(uint8_t)); // NULL check needed
        response[response_size - 8] = 15;    // Type
        response[response_size - 7] = 6;    // Length
        response[response_size - 6] = 'm';
        response[response_size - 5] = 'y';
        response[response_size - 4] = '.';
        response[response_size - 3] = 'c';
        response[response_size - 2] = 'o';
        response[response_size - 1] = 'm';

        // Option 51
        response_size += 6;
        response = (uint8_t*)realloc(response, response_size * sizeof(uint8_t)); // NULL check needed
        response[response_size - 6] = 51;   // Type
        response[response_size - 5] = 4;    // Length
        response[response_size - 4] = 0;    // 1 day
        response[response_size - 3] = 1;
        response[response_size - 2] = 51;
        response[response_size - 1] = 80;


        // Option 54
        response_size += 6;
        response = (uint8_t*)realloc(response, response_size * sizeof(uint8_t)); // NULL check needed
        response[response_size - 6] = 54;   // Type
        response[response_size - 5] = 4;    // Length
        response[response_size - 4] = 10;
        response[response_size - 3] = 120;
        response[response_size - 2] = 10;
        response[response_size - 1] = 100;

        // Option 255
        response_size += 1;
        response = (uint8_t*)realloc(response, response_size * sizeof(uint8_t)); // NULL check needed
        response[response_size - 1] = 255;

        printf("---> %u\n", response_size);

        // Padding
        uint32_t padding_minimum = 308 + L2_HEADER_LENGTH + L3_HEADER_LENGTH;
        if(response_size < padding_minimum) {
            uint32_t padding = padding_minimum - response_size;
            response_size += padding;
            response = (uint8_t*)realloc(response, response_size * sizeof(uint8_t)); // NULL check needed

            printf("\tAddind padding: %u\n", padding);

            for(i = 0; i < padding; i++) {
                response[response_size - 1 - i] = 0;
            }
        }

        // Change length in UDP header
        response[l4_offset + 4] = (response_size - (L2_HEADER_LENGTH + L3_HEADER_LENGTH))/256;
        response[l4_offset + 5] = (response_size - (L2_HEADER_LENGTH + L3_HEADER_LENGTH))%256;

        printf("---> %u\n", response_size);

        // Get input interface
        onep_network_interface_t* intf;
        onep_dpss_pkt_get_input_interface(pkt, &intf);

        onep_status_t s = onep_dpss_inject_raw_packet(GetNetworkElement(), response, response_size, 0, intf, ONEP_TARGET_LOCATION_HARDWARE_DEFINED_OUTPUT);

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