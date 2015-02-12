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
        case OFFLINE:
            queue = GetOfflineQueue(param);
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
    queue->head = CreateBackstop();
    queue->tail = queue->head;
    queue->backstop = queue->head;
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
    item->backstop = true;
    item->param = 0;

    return item;
}


TQueue* GetOfflineQueue(TQueueParam param)
{
    return NULL;
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
        case OFFLINE:
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
    new_item->backstop = false;
    new_item->param = -1;

    queue->tail->next = new_item;
    queue->tail = new_item;

    queue->backstop->param++;

    return new_item;
}

TQueueItem* InsertPacketToOfflineQueue(TQueue* queue,
    TPacket packet)
{
    return NULL;
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
        queue->head = queue->backstop->next;
        queue->tail->next = queue->backstop;
        queue->backstop->next = NULL;
        queue->backstop->param = 0;
    }

    return complete;
}

TQueueItem* GetNextItemInQueue(TQueue* queue)
{
    TQueueItem* item = queue->head;

    // No more items
    if(item->backstop == true)
    {
        item = NULL;
    }
    else
    {
        // Move head
        queue->head = queue->head->next;
        // Remove from queue
        item->next = NULL;
    }

    return item;
}

void DisposeQueueItem(TQueueItem* item)
{
    free(item->packet); // TODO
    free(item);

    return;
}

bool IsChunkFull(TQueue* queue)
{
    return (queue->backstop->param >= (int)queue->param);
}

bool IsChunkReady(TQueue* queue)
{
    return (queue->head->backstop != true);
}

