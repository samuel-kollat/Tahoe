#ifndef __MODULE_DNS_RESOLUTIONS__
#define __MODULE_DNS_RESOLUTIONS__

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "../../protocols/parsers.h"

typedef struct {
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    uint16_t src_port;
    uint16_t dst_port;
    char* domain;
} TDnsQuery;

typedef struct
{
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    uint16_t src_port;
    uint16_t dst_port;
    // TODO
} TDnsResponse;

typedef struct {
    uint8_t transaction_id[2];
    TDnsQuery query;
    TDnsResponse response;
} TResolution;

typedef struct ResolutionItem {
    bool processed;
    TResolution resolution;
    struct ResolutionItem* next;
} TResolutionItem;

TResolutionItem* get_dns_resolutions_list(
);

void store_dns_message(
    l3_header* l3,
    udp_header* l4,
    dns_message* message
);

void print_dns_resolution_data(
    TResolutionItem* item
);

#endif