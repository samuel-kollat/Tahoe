#ifndef __MIDDLEND_PROTOCOLS_L4__
#define __MIDDLEND_PROTOCOLS_L4__

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#define UDP_HEADER_LENGTH 8

typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
} udp_header;

#endif