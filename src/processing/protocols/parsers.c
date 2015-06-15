#include "parsers.h"

void parse_l2_header(uint8_t* packet, l2_header* header)
{
    header->dsthw[0] = packet[0];
    header->dsthw[1] = packet[1];
    header->dsthw[2] = packet[2];
    header->dsthw[3] = packet[3];
    header->dsthw[4] = packet[4];
    header->dsthw[5] = packet[5];

    header->srchw[0] = packet[6];
    header->srchw[1] = packet[7];
    header->srchw[2] = packet[8];
    header->srchw[3] = packet[9];
    header->srchw[4] = packet[10];
    header->srchw[5] = packet[11];

    header->proto[0] = packet[12];
    header->proto[1] = packet[13];
}

void parse_l3_header(uint8_t* packet, l3_header* header)
{
    int offset = L2_HEADER_LENGTH;

    header->total_length = packet[offset + 2]*16 + packet[offset + 3];

    header->source_ip[0] = packet[offset + 12];
    header->source_ip[1] = packet[offset + 13];
    header->source_ip[2] = packet[offset + 14];
    header->source_ip[3] = packet[offset + 15];

    header->destination_ip[0] = packet[offset + 16];
    header->destination_ip[1] = packet[offset + 17];
    header->destination_ip[2] = packet[offset + 18];
    header->destination_ip[3] = packet[offset + 19];

    // TODO: rest of fields
}

void parse_l4_udp_header(uint8_t* packet, udp_header* header)
{
    int offset = L2_HEADER_LENGTH + L3_HEADER_LENGTH;

    header->source_port = packet[offset + 0]*16 + packet[offset + 1];

    header->destination_port = packet[offset + 2]*16 + packet[offset + 3];

    header->length = packet[offset + 4]*16 + packet[offset + 5];

    header->checksum = packet[offset + 6]*16 + packet[offset + 7];
}

void parse_dns_message(uint8_t* packet, uint32_t packet_length, dns_message* message)
{
    // Allocation
    message->header = (dns_header*)malloc(sizeof(dns_header));
    if(message->header == NULL)
    {
        fprintf(stderr, "Error: malloc (parse_dns_message / header)\n");
        return;
    }

    message->query = (dns_query*)malloc(sizeof(dns_query));
    if(message->query == NULL)
    {
        fprintf(stderr, "Error: malloc (parse_dns_message / query)\n");
        return;
    }

    message->response = (dns_response*)malloc(sizeof(dns_response));
    if(message->response == NULL)
    {
        fprintf(stderr, "Error: malloc (parse_dns_message / response)\n");
        return;
    }

    // Parsing
    int offset = L2_HEADER_LENGTH + L3_HEADER_LENGTH + UDP_HEADER_LENGTH;

    // *******
    // Header
    // *******
    message->header->identifier[0] = packet[offset + 0];
    message->header->identifier[1] = packet[offset + 1];

    // TODO: params

    message->header->question_count = packet[offset + 4]*16 + packet[offset + 5];
    message->header->answer_count = packet[offset + 6]*16 + packet[offset + 7];
    message->header->authority_record_count = packet[offset + 8]*16 + packet[offset + 9];
    message->header->additional_record_count = packet[offset + 10]*16 + packet[offset + 11];

    // *******
    // Query
    // *******
    int query_domain_name_length = packet_length - offset - DNS_QUERY_KNOWN_FIELDS_LENGTH;  // WARNING: working only for query, response must be processed differently !!!!
    message->query->query_domain_name = (uint8_t*)malloc(query_domain_name_length * sizeof(uint8_t));
    if(message->query->query_domain_name == NULL)
    {
        fprintf(stderr, "Error: malloc (parse_dns_message / query_domain_name)\n");
        return;
    }

    int i;
    for(i = 0; i < query_domain_name_length; i++)
    {
       message->query->query_domain_name[i] = packet[offset + 12 + i];
    }
    offset = offset + i;

    message->query->query_type = packet[offset + 12]*16 + packet[offset + 13];
    message->query->query_class = packet[offset + 14]*16 + packet[offset + 15];

    // *******
    // Response
    // *******

    // TODO

}