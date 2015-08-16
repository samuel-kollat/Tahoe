/*
 *-----------------------------------------------------------------
 * OneMon
 *-----------------------------------------------------------------
 */

// configuration file
#include "utils/config.h"

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <unistd.h>
// OnePK
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
// Other
#include "session_element_util.h"
#include "include/tahoe_util.h"
// Database
#include "database/db_wrapper.h"
// Utils
#include "utils/router.h"
// Processing

// Backend API
#include "filtering/api.h"
#include "filtering/callback.h"

// TODO: unused
#include "filtering/configuration.h"

#include "processing/connector.h"

#include <pthread.h>

// Global variables
#include "globals.h"

//Modules
#include "processing/modules/modules.h"

#define FAIL false
#define SUCCESS true
#define DPSS_ACTION_MAX_LEN (20)

onep_policy_global_cap_t *global_cap = NULL;
onep_policy_cap_filter_t *filter_cap = NULL;
onep_collection_t *tables = NULL;

static int proto;