#ifndef __MIDDLEND_PROTOCOLS_L3__
#define __MIDDLEND_PROTOCOLS_L3__

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#define L3_HEADER_LENGTH 20

typedef struct {
    uint8_t version : 4;
    uint8_t ihl : 4;
    uint8_t dscp : 6;
    uint8_t ecn : 2;
    uint16_t total_length;
    uint16_t identification;
    uint8_t flags : 3;
    uint16_t fragment_offset : 13;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint8_t source_ip[4];
    uint8_t destination_ip[4];
} l3_header;

#endif