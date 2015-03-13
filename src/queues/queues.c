#include "queues.h"

void PrintQueueErrorMessage(char* dst, char* msg)
{
    fprintf(stderr, "Error in Queues (%s): %s\n", dst, msg);
    return;
}

TQueue* GetQueue(TQueueType type, TQueueParam param)
{
    TQueue* queue = NULL;

    switch(type)
    {
        case ONLINE:
            queue = GetOnlineQueue(param);
            break;
        default:
            PrintQueueErrorMessage("SetTypeOfQueue", "wrong type of queue");
            break;
    }

    return queue;
}

TQueue* GetOnlineQueue(TQueueParam param)
{
    TQueue* queue = (TQueue*)(malloc(sizeof(TQueue)));
    if(queue == NULL)
    {
        PrintQueueErrorMessage("GetOnlineQueue", "malloc");
        return NULL;
    }

    queue->type = ONLINE;
    queue->backstop = CreateBackstop();
    queue->tail = queue->backstop;
    queue->pcap = NULL;
    queue->param = param;

    return queue;
}

TQueueItem* CreateBackstop()
{
    TQueueItem* item = (TQueueItem*)(malloc(sizeof(TQueueItem)));
    if(item == NULL)
    {
        PrintQueueErrorMessage("CreateBackstop", "malloc");
        return NULL;
    }

    item->packet = NULL;
    item->next = NULL;
    item->prev = NULL;
    item->backstop = true;
    item->param = 0;
    // Timestamp
    clock_gettime(CLOCK_MONOTONIC, &(item->timestamp));

    return item;
}

TQueueItem* InsertPacketToQueue(TQueue* queue,
    TPacket packet)
{
    TQueueItem* item = NULL;
    switch(queue->type)
    {
        case ONLINE:
            item = InsertPacketToOnlineQueue(queue, packet);
            break;
        default:
            PrintQueueErrorMessage("InsertPacketToQueue", "wrong queue type");
            return NULL;
    }

    return item;
}

TQueueItem* InsertPacketToOnlineQueue(TQueue* queue,
    TPacket packet)
{
    TQueueItem* new_item = (TQueueItem*)(malloc(sizeof(TQueueItem)));
    if(new_item == NULL)
    {
        PrintQueueErrorMessage("InsertPacketToQueue", "malloc");
        return NULL;
    }

    new_item->packet = packet;
    new_item->next = NULL;
    new_item->prev = queue->tail;
    new_item->backstop = false;
    new_item->param = -1;

    queue->tail->next = new_item;
    queue->tail = new_item;

    queue->backstop->param++;

    return new_item;
}

bool CompleteChunkInQueue(TQueue* queue)
{
    bool complete = false;

    // check number of new packets
    if(queue->backstop->param >= (int)queue->param)
    {
        complete = true;
    }

    // if complete, move backstop
    if(complete == true)
    {
        // Prev pointer of the first item in queue is NULL
        queue->backstop->next->prev = NULL;

        queue->tail->next = queue->backstop;
        queue->backstop->next = NULL;
        queue->backstop->prev = queue->tail;
        queue->backstop->param = 0;
        queue->tail = queue->backstop;
    }

    return complete;
}

void GetChunkRange(TQueue* queue, TQueueItem** start,TQueueItem** stop)
{
    *stop = queue->backstop->prev;

    TQueueItem* item = *stop;
    while(item != NULL)
    {
        *start = item;
        item = item->prev;
    }

    // Close chunk
    queue->backstop->prev = NULL;

    return;
}

TQueueItem* GetNextItem(TQueueItem* current, TQueueItem* stop)
{
    TQueueItem* item = NULL;

    // No more items
    if(current == stop)
    {
        // Nothing to return
        item = NULL;
    }
    else
    {
        // Next item
        item = current->next;

        // Dispose current
        item->prev = NULL;
        DisposeQueueItem(current);
    }
    return item;
}

void DisposeQueueItem(TQueueItem* item)
{
    //free(item->packet); // TODO
    free(item);

    return;
}

bool IsChunkFull(TQueue* queue)
{
    return (queue->backstop->param >= (int)queue->param);
}

bool IsChunkReady(TQueue* queue)
{
    return (queue->backstop->prev != NULL);
}

