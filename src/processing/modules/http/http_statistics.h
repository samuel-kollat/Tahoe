#ifndef __MODULE_HTTP_STATISTICS__
#define __MODULE_HTTP_STATISTICS__

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "../../protocols/parsers.h"
#include "../../../utils/hash.h"

typedef enum {
    HEAD,
    GET,
    POST,
    PUT,
    DELETE,
    TRACE,
    CONNECT,
    RESPONSE    // not actual method, but needed for recognition
} THttpMethod;

typedef struct HttpStats {
    uint32_t hash;
    uint8_t source_ip[4];
    uint8_t destination_ip[4];
    uint16_t source_port;
    uint16_t destination_port;
    THttpMethod method;
    uint32_t quantity;
    struct HttpStats* next;
} THttpStats;

typedef struct {
    bool genuine;
    THttpMethod method;
    uint32_t quantity;
} THttpData;

void store_http_data(
    l3_header* l3,
    tcp_header* tcp,
    THttpData* data
);

THttpStats* get_list_start();

void print_list(
);

#endif