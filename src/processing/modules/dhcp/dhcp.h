#ifndef __MODULE_DHCP__
#define __MODULE_DHCP__

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

void AnalyzeDhcp(
    TQueueItem* start,
    TQueueItem* stop,
    TQueueCallbackArgs args
);

void DhcpAnalyze(
    TPacket* item
);

bool DhcpDataReady(
);

void DhcpDataPrepare(
);

void DhcpDataCondition(
);

void DhcpStore(
);

#endif