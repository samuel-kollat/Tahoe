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

typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t ack_number;
    uint8_t data_offset : 4;
    uint8_t reserved : 6;
    uint8_t control_bits : 6;
    uint16_t window;
    uint16_t checksum;
    uint8_t options[40];
} tcp_header;

#endif