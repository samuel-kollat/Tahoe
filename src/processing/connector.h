#ifndef __MIDDLEND_CONNECTOR__
#define __MIDDLEND_CONNECTOR__

#include <stdio.h>
#include <stdlib.h>

#include "../queues/queues.h"

#include "onep_dpss_callback_framework.h"

// Status
typedef enum {
    ME_OK,
    ME_FAIL
} TMeStatus;

// Type of callback to process queue
typedef TMeStatus (*TQueueCallback)(TQueue* queue);

// Set desired queue type
TMeStatus SetTypeOfQueue(TQueueType type, TQueueParam param, TQueue** queue);

// Register callbact to be called on the set queue
TMeStatus RegisterQueueCallback(TQueueCallback callback);

// Print error
void PrintMeErrorMessage(char* dst, char* msg);

#endif