#ifndef __TAHOE_GLOBALS__
#define __TAHOE_GLOBALS__

#include "queues/queues.h"

extern pthread_mutex_t proc_mutex;
extern pthread_cond_t proc_cond;

extern TQueue* Packet_queue;

#endif