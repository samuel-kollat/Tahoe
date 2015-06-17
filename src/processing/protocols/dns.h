#ifndef __MIDDLEND_PROTOCOLS_DNS__
#define __MIDDLEND_PROTOCOLS_DNS__

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#define DNS_QUERY_KNOWN_FIELDS_LENGTH 16

typedef enum {
    DNS_OK,
    DNS_FORMAT_ERROR,
    DNS_NOT_IMPLEMENTED
} dns_status;

typedef enum {
    DNS_REC_A = 1,
    DNS_REC_NS = 2,
    DNS_REC_CNAME = 5,
    DNS_REC_SOA = 6,
    DNS_REC_MX = 15,
    DNS_REC_AAA = 28,
} dns_qtype;

typedef struct {
    uint8_t identifier[2];
    uint8_t query_response_flag : 1;
    uint8_t operation_code : 4;
    uint8_t authoritative_answer_flag : 1;
    uint8_t truncation_flag : 1;
    uint8_t recursion_desired : 1;
    uint8_t recursion_available : 1;
    uint8_t zero : 3;
    uint8_t response_code : 4;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_record_count;
    uint16_t additional_record_count;
} dns_header;

typedef struct
{
    uint16_t query_domain_name_length;
    uint8_t* query_domain_name;
    uint16_t query_type;
    uint16_t query_class;
} dns_query;

typedef struct response_section {
    uint8_t* domain_name;
    uint16_t type;
    uint16_t inet_class;
    uint32_t ttl;
    uint16_t data_length;
    uint8_t* resource_data;
    struct response_section* next_section;
} dns_response_section;

typedef struct {
    dns_response_section* answer;
    dns_response_section* authoritative_name_servers;
    dns_response_section* additional_records;
} dns_response;

typedef struct {
    dns_header* header;
    dns_query* query;
    dns_response* response;
    dns_status status;
} dns_message;

#endif