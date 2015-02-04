#ifndef __MIDDLEND_CONNECTOR__
#define __MIDDLEND_CONNECTOR__

#include <stdio.h>
#include <stdlib.h>

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

// Type of pcap
typedef FILE* TPcap;

// Item on packet queue
typedef struct Packet {
    TPacket packet;
    struct Packet* next;
    bool backstop;          // True if Backstop
} TQueueItem;

// Queue
typedef struct {
    TQueueType type;    // Type of the queue
    TQueueItem* head;       // Pointer to first element
    TPcap pcap;         // Pointer to pcap file
} TQueue;

// Type of callback to process queue
typedef TMeStatus (*TQueueCallback)(TQueue* queue);

// Set desired queue type
TMeStatus SetTypeOfQueue(TQueueType type, TQueueParam param, TQueue** queue);

// Register callbact to be called on the set queue
TMeStatus RegisterQueueCallback(TQueueCallback callback);

// Print error
void PrintMeErrorMessage(char* dst, char* msg);

//
TQueue* GetOnlineQueue(TQueueParam param);

//
TQueueItem* CreateBackstop();

//
TQueue* GetOfflineQueue(TQueueParam param);

#endif