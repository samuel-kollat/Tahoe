#ifndef __MIDDLEND_PROTOCOLS_DHCP__
#define __MIDDLEND_PROTOCOLS_DHCP__

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#define MINIMAL_DHCP_PACKET_SIZE 239
#define REQUEST_LIST_SIZE 20

typedef enum {
    DHCPDISCOVER = 1,
    DHCPOFFER,
    DHCPREQUEST,
    DHCPDECLINE,
    DHCPACK,
    DHCPNAK,
    DHCPRELEASE
    // TODO
} TDhcpMessageType;

typedef enum {
    PAD = 0,
    SUBNET_MASK = 1,
    TIME_OFFSET = 2,
    ROUTER = 3,
    DOMAIN_NAME_SERVER = 6,
    HOST_NAME = 12,
    DOMAIN_NAME = 15,
    INTERFACE_MTU = 26,
    BROADCAST_ADDRESS = 28,
    NTP_SERVERS = 42,
    NB_OVET_IP_NAME_SERVER = 44,
    NB_OVER_IP_SCOPE = 47,
    DHCP_MESSAGE_TYPE = 53,
    PARAMETER_REQUEST_LIST = 55,
    DOMAIN_SEARCH = 119,
    CLASSLESS_STATIC_ROUTE = 121
    // TODO
} TDhcpOptions;

typedef struct
{
    TDhcpMessageType dhcp_message_type;
    char* host_name;
    TDhcpOptions parameter_request_list[REQUEST_LIST_SIZE];
} dhcp_options;

typedef struct {
    bool valid;
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint8_t flags[2];
    uint8_t ciaddr[4];
    uint8_t yiaddr[4];
    uint8_t siaddr[4];
    uint8_t giaddr[4];
    uint8_t chaddr[16];
    uint8_t sname[64];
    //uint8_t file[128];
    uint8_t magic_cookie[4];
    //uint8_t options[312];
    dhcp_options options;
} dhcp_message;

#endif