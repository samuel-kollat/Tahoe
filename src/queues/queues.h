#ifndef __SHARED_QUEUES__
#define __SHARED_QUEUES__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

// All types of queues
typedef enum {
    ONLINE     // Share structures stored in RAM
} TQueueType;

// Additional parameter of a queue
typedef int TQueueParam;

// Arguments for callback function
typedef char* TQueueCallbackArgs;

// Type of packet
typedef struct onep_dpss_paktype_* TPacket;

// Type of pcap
typedef FILE* TPcap;

// Item on packet queue
typedef struct Packet {
    TPacket packet;
    struct Packet* next;
    struct Packet* prev;
    bool backstop;                  // True if Backstop
    int param;                      // Additional info about Backstop
    struct timespec timestamp;     // Seconds from 1970 and millisecond since the last second
} TQueueItem;

// Queue
typedef struct {
    TQueueType type;    // Type of the queue
    TQueueItem* tail;   // Pointer to the last element
    TQueueItem* backstop;   // Pointer to the backstop
    TPcap pcap;         // Pointer to a pcap file
    TQueueParam param;  // Queue parameter - number of items in complete chunk
} TQueue;

// Print error
void PrintQueueErrorMessage(
    char* dst,
    char* msg
);

// Public
TQueue* GetQueue(
    TQueueType type,
    TQueueParam param
);

// Public
TQueueItem* InsertPacketToQueue(
    TQueue* queue,
    TPacket packet
);

// Public
bool CompleteChunkInQueue(
    TQueue* queue
);

// Public
TQueueItem* GetNextItem(
    TQueueItem* current,
    TQueueItem* stop
);

// Public
void DisposeQueueItem(
    TQueueItem* item
);

// Public
void GetChunkRange(
    TQueue* queue,
    TQueueItem** start,
    TQueueItem** stop
);

//
TQueueItem* CreateBackstop();

//
TQueue* GetOnlineQueue(
    TQueueParam param
);

//
TQueueItem* InsertPacketToOnlineQueue(
    TQueue* queue,
    TPacket packet
);

bool IsChunkFull(
    TQueue* queue
);

bool IsChunkReady(
    TQueue* queue
);

#endif