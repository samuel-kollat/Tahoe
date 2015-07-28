#ifndef __MIDDLEND_CONNECTOR__
#define __MIDDLEND_CONNECTOR__

#include <stdio.h>
#include <stdlib.h>

#include <pthread.h>

// Global variables
#include "../globals.h"

#include "../queues/queues.h"

#include "onep_dpss_callback_framework.h"

// Status
typedef enum {
    ME_OK,
    ME_FAIL
} TMeStatus;

// Type of callback to process queue
typedef void (*TQueueCallback)(TQueueItem* start, TQueueItem* stop, TQueueCallbackArgs args);

// Set desired queue type
TMeStatus SetTypeOfQueue(TQueueType type, TQueueParam param, TQueue** queue);

// Register callbact to be called on the set queue
TMeStatus RegisterQueueCallback(TQueueCallback callback);

// Register arguments for selected callback function
TMeStatus RegisterQueueCallbackArgs(char* args);

TMeStatus RegisterNetworkElement(onep_network_element_t* ne);
onep_network_element_t* GetNetworkElement();

// Print error
void PrintMeErrorMessage(char* dst, char* msg);

void* processing(void *);

extern TQueueCallback Proc_callback;
extern TQueueCallbackArgs Proc_callback_args;
extern onep_network_element_t* network_element;

#endif