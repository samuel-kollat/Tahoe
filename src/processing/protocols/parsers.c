#include "parsers.h"

// TODO: *16 -> *16*16

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

void parse_l4_tcp_header(uint8_t* packet, tcp_header* header)
{
    int offset = L2_HEADER_LENGTH + L3_HEADER_LENGTH;

    header->source_port = packet[offset + 0]*16*16 + packet[offset + 1];

    header->destination_port = packet[offset + 2]*16*16 + packet[offset + 3];

    header->data_offset = packet[offset + 12] >> 4;

    // TODO: rest of fields
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

void parse_dhcp_message(uint8_t* packet,
    uint32_t packet_length,
    dhcp_message* message)
{
    message->valid = false;
    message->options.parameter_request_list[0] = PAD;

    if(packet_length < MINIMAL_DHCP_PACKET_SIZE)
    {
        return;
    }

    int offset = L2_HEADER_LENGTH + L3_HEADER_LENGTH + UDP_HEADER_LENGTH;

    message->op = packet[offset + 0];
    message->htype = packet[offset + 1];
    message->hlen = packet[offset + 2];
    message->hops = packet[offset + 3];
    message->xid = packet[offset + 4]*256*256*256 + packet[offset + 5]*256*256 +packet[offset + 6]*256 +packet[offset + 7];
    message->secs = packet[offset + 8]*256 + packet[offset + 9];

    message->flags[0] = packet[offset + 10];
    message->flags[1] = packet[offset + 11];

    message->ciaddr[0] = packet[offset + 12];
    message->ciaddr[1] = packet[offset + 13];
    message->ciaddr[2] = packet[offset + 14];
    message->ciaddr[3] = packet[offset + 15];

    message->yiaddr[0] = packet[offset + 16];
    message->yiaddr[1] = packet[offset + 17];
    message->yiaddr[2] = packet[offset + 18];
    message->yiaddr[3] = packet[offset + 19];

    message->siaddr[0] = packet[offset + 20];
    message->siaddr[1] = packet[offset + 21];
    message->siaddr[2] = packet[offset + 22];
    message->siaddr[3] = packet[offset + 23];

    message->giaddr[0] = packet[offset + 24];
    message->giaddr[1] = packet[offset + 25];
    message->giaddr[2] = packet[offset + 26];
    message->giaddr[3] = packet[offset + 27];

    int i;
    for(i = 0; i < 16; i++)
    {
        message->chaddr[i] = packet[offset + 28 + i];
    }

    for(i = 0; i < 64; i++)
    {
        message->sname[i] = packet[offset + 44 + i];
        if(message->sname[i] == 0)
        {
            break;
        }
    }

    // 44 + 64 = 108 + 128 (file) = 236
    message->magic_cookie[0] = packet[offset + 236];
    message->magic_cookie[1] = packet[offset + 237];
    message->magic_cookie[2] = packet[offset + 238];
    message->magic_cookie[3] = packet[offset + 239];

    if(packet_length > offset + MINIMAL_DHCP_PACKET_SIZE)
    {
        int option_offset = offset + MINIMAL_DHCP_PACKET_SIZE + 1;
        while(option_offset < packet_length)
        {
            int option_code = packet[option_offset + 0];
            int option_len = packet[option_offset + 1];

            if(option_code == DHCP_MESSAGE_TYPE && option_len == 1)
            {
                message->options.dhcp_message_type_l2_offset = option_offset + 2;
                message->options.dhcp_message_type = packet[option_offset + 2];
            }
            else if(option_code == HOST_NAME && option_len > 1)
            {
                message->options.host_name = (char*) malloc ((option_len+1) * sizeof(char));
                if(message->options.host_name == NULL)
                {
                    fprintf(stderr, "[Error] malloc (parse_dhcp_message)\n");
                    return;
                }
                for(i = 0; i < option_len; i++)
                {
                    message->options.host_name[i] = packet[option_offset + 2 + i];
                }
                message->options.host_name[option_len] = '\0';
            }
            else if(option_code == PARAMETER_REQUEST_LIST && option_len > 1)
            {
                printf("LOL\n");
                for(i = 0; i < option_len; i++)
                {
                    message->options.parameter_request_list[i] = packet[option_offset + 2 + i];
                }
                message->options.parameter_request_list[option_len] = PAD;
            }

            option_offset = option_offset + 1 + 1 + option_len;
        }
    }

    message->valid = true;
    return;
}

uint16_t ipv4_checksum(uint8_t* buf, unsigned size)
{
    unsigned sum = 0;
    int i;

    /* Accumulate checksum */
    for (i = 0; i < size - 1; i += 2)
    {
        uint16_t word16 = *(uint16_t*) &buf[i];
        sum += word16;
    }

    /* Handle odd-sized case */
    if (size & 1)
    {
        uint16_t word16 = (uint8_t) buf[i];
        sum += word16;
    }

    /* Fold to get the ones-complement result */
    while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);

    /* Invert to get the negative in ones-complement arithmetic */
    return ~sum;
}
