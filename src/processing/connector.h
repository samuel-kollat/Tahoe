#ifndef __MIDDLEND_CONNECTOR__
#define __MIDDLEND_CONNECTOR__

#include "onep_dpss_callback_framework.h"

// Status
typedef enum {
    ME_OK,
    ME_FAIL
} TMeStatus;

// All types of queues
typedef enum {
    ONLINE,    // Share structures stored in RAM
    OFFLINE    // Files (.pcap) stored on disk
} TQueueType;

// Additional parameter of a queue
typedef int TQueueParam;

// Type of packet
typedef struct onep_dpss_paktype_* TPacket;

// Item on packet queue
typedef struct Packet {
    TPacket packet;
    struct Packet* next;
} TQueueItem;

// Queue
typedef struct {
    TPacket head;    // Pointer to first element
} TQueue;

// Type of callback to process queue
typedef TMeStatus (*TQueueCallback)(TQueue* queue);

// Set desired queue type
TMeStatus SetTypeOfQueue(TQueueType type, TQueueParam param, TQueue** queue);

// Register callbact to be called on the set queue
TMeStatus RegisterQueueCallback(TQueueCallback callback);

#endif