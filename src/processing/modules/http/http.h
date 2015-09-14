#ifndef __MODULE_HTTP__
#define __MODULE_HTTP__

#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#include "onep_core_services.h"
#include "onep_policy_bulk.h"
#include "onep_datapath_policy.h"
#include "onep_class.h"
#include "onep_filter.h"
#include "onep_dpss_packet_delivery.h"
#include "onep_types.h"
#include "onep_dpss_actions.h"
#include "onep_dpss_pkt.h"
#include "onep_dpss_flow.h"
#include "onep_dpss_callback_framework.h"

#include "../../../queues/queues.h"
#include "../../protocols/parsers.h"
#include "../../storing.h"
#include "http_statistics.h"
#include "../../../database/mysql/analyzers/http_mysql.h"

#define HTTP_PROTO_STRING_SIZE 8

void AnalyzeHttp(
    TQueueItem* start,
    TQueueItem* stop,
    TQueueCallbackArgs args
);

void HttpAnalyze(
    TPacket* packet
);

bool HttpDataReady(
);

void HttpDataPrepare(
);

void HttpDataCondition(
);

void HttpStore(
);

void ParseHttp(
    uint8_t* packet,
    uint32_t packet_size,
    tcp_header* tcp,
    THttpData* http
);

#endif