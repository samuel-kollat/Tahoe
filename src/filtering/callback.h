#ifndef __FILTERING_CALLBACK__
#define __FILTERING_CALLBACK__

#include <pthread.h>

#include "onep_dpss_callback_framework.h"

#include "../globals.h"
#include "../queues/queues.h"

void packet_enqueue_callback( onep_dpss_traffic_reg_t*,
                            struct onep_dpss_paktype_*, 
                            void*, 
                            bool*); 

#endif