#ifndef __MODULE_PRINT__
#define __MODULE_PRINT__

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

#include "../../queues/queues.h"

void Print(
    TQueueItem* start,
    TQueueItem* stop
);

void print_packet(
    TPacket* packet
);

void proc_pi_get_flow_state(
    struct onep_dpss_paktype_ *pakp,
    onep_dpss_flow_ptr_t fid,
    char *l4_state_char
);

onep_status_t proc_pi_get_ip_port_info(
    struct onep_dpss_paktype_ *pakp,
    char **src_ip,
    char **dest_ip,
    uint16_t *src_port, uint16_t *dest_port,
    char *prot,
    char ip_version
);

onep_status_t proc_pi_get_ip_version(
    struct onep_dpss_paktype_ *pakp,
    char *ip_version
);

#endif