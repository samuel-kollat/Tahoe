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

    // Status
    message->status = DNS_FORMAT_ERROR;

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
    // http://maradns.samiam.org/multiple.qdcount.html: for QCOUNT > 1
    // *******
    if(message->header->question_count != 1)
    {
        fprintf(stderr, "QCOUNT: %u\n", message->header->question_count);
        return;
    }

    int query_domain_name_length = 0;
    if(message->header->answer_count + message->header->authority_record_count + message->header->additional_record_count == 0)
    {
        // Query
        query_domain_name_length = packet_length - offset - DNS_QUERY_KNOWN_FIELDS_LENGTH;
    }
    else
    {
        // Response
        query_domain_name_length = dns_fqdn_length(&(packet[offset + 12]));
    }
    message->query->query_domain_name_length = query_domain_name_length;

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

    if(message->query->query_type != DNS_REC_A)
    {
        fprintf(stderr, "[Skip] Query Type: %u\n", message->query->query_type);
        message->status = DNS_NOT_IMPLEMENTED;
        return;
    }

    // *******
    // Response
    // *******

    // Answers
    message->response->answer = NULL;
    offset = offset + 16;
    dns_response_section* previous_section = NULL;
    for(i = 0; i < message->header->answer_count; i++)
    {
        // Allocation
        dns_response_section* rs = (dns_response_section*)malloc(sizeof(dns_response_section));
        if(message->response == NULL)
        {
            fprintf(stderr, "Error: malloc (parse_dns_message / response_section)\n");
            return;
        }

        // Name
        if( (packet[offset + 0] & 0b11000000) == 0)        // label
        {
            // TODO
            fprintf(stderr, "Error: LABEL (parse_dns_message / response_section)\n");
        }
        else if( (packet[offset + 0] & 0b11000000) == 192) // pointer
        {
            // TODO
        }
        else
        {
            fprintf(stderr, "Answer NAME: %u\n", packet[offset + 1]);
            return;
        }

        // Params
        rs->type = packet[offset + 2]*16 + packet[offset + 3];
        rs->inet_class = packet[offset + 4]*16 + packet[offset + 5];
        rs->ttl = packet[offset + 6]*16*16*16 + packet[offset + 7]*16*16 + packet[offset + 8]*16 + packet[offset + 9];

        // Data
        rs->data_length = packet[offset + 10]*16 + packet[offset + 11];
        rs->resource_data = NULL;

        if(rs->type != DNS_REC_A || rs->data_length != 4)
        {
            offset = offset + 12 + rs->data_length;

            free(rs);
            continue;
        }

        rs->resource_data = (uint8_t*)malloc(4 * sizeof(uint8_t));
        if(rs->resource_data == NULL)
        {
            fprintf(stderr, "Error: malloc (parse_dns_message / resource_data)\n");
            return;
        }

        rs->resource_data[0] = packet[offset + 12];
        rs->resource_data[1] = packet[offset + 13];
        rs->resource_data[2] = packet[offset + 14];
        rs->resource_data[3] = packet[offset + 15];

        // List
        rs->next_section = NULL;
        if(previous_section != NULL)
        {
            previous_section->next_section = rs;
        }
        else
        {
            message->response->answer = rs;
        }
        previous_section = rs;

        offset = offset + 12 + rs->data_length;
    }

    // Authority - skip
    message->response->authoritative_name_servers = NULL;

    // Additional - skip
    message->response->additional_records = NULL;

    // Status
    message->status = DNS_OK;
    return;
}

uint16_t dns_fqdn_length(uint8_t* data)
{
    int length = 0;

    while(data[length] != 0)
    {
        if(data[length] <= 31)
        {
            length += data[length] + 1;
        }
        else
        {
            continue;
        }
    }

    return length + 1;
}

void ip_to_str(uint8_t ip[4], char** str)
{
    (*str) = (char*)malloc(16 * sizeof(char));
    if(*str == NULL)
    {
        fprintf(stderr, "Error: Malloc failed [ip_to_str].\n");
        return;
    }
    sprintf((*str), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

void domain_to_str(uint8_t* domain, char** str)
{
    if(domain == NULL)
    {
        fprintf(stderr, "No domain to query.\n");
        return;
    }

    // Count characters
    int i = 0;
    char c = (char)domain[i];
    while(c != '\0')
    {
        i++;
        c = (char)domain[i];
    }

    // Allocation
    (*str) = (char*)malloc((i+1) * sizeof(char));
    if(*str == NULL)
    {
        fprintf(stderr, "Error: Malloc failed [domain_to_str].\n");
        return;
    }

    // To string
    i = 0;
    c = (char)domain[i];
    while(c != '\0')
    {
        if(c < 33)
        {
            (*str)[i] = '.';
        }
        else
        {
            (*str)[i] = c;
        }
        i++;
        c = (char)domain[i];
    }
    (*str)[i] = '\0';
}