#ifndef __MIDDLEND_PROTOCOLS_PARSERS__
#define __MIDDLEND_PROTOCOLS_PARSERS__

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "l2.h"
#include "l3.h"
#include "l4.h"

#include "dns.h"
#include "dhcp.h"

void parse_l2_header(
    uint8_t* packet,
    l2_header* header
);

void parse_l3_header(
    uint8_t* packet,
    l3_header* header
);

void parse_l4_udp_header(
    uint8_t* packet,
    udp_header* header
);

void parse_l4_tcp_header(
    uint8_t* packet,
    tcp_header* header
);

void parse_dns_message(
    uint8_t* packet,
    uint32_t packet_length,
    dns_message* message
);

void parse_dhcp_message(
    uint8_t* packet,
    uint32_t packet_length,
    dhcp_message* message
);

void ip_to_str(
    uint8_t ip[4],
    char** str
);

void domain_to_str(
    uint8_t* domain,
    char** str
);

uint16_t dns_fqdn_length(
    uint8_t* data
);

uint16_t ipv4_checksum(
    uint8_t* buf,
    unsigned size
);

#endif