#include "connector.h"

void PrintMeErrorMessage(char* dst, char* msg)
{
    fprintf(stderr, "Error in Connector (%s): %s\n", dst, msg);
    return;
}

TMeStatus SetTypeOfQueue(TQueueType type,
    TQueueParam param, TQueue** queue)
{
    switch(type)
    {
        case ONLINE:
            *queue = GetOnlineQueue(param);
            break;
        case OFFLINE:
            *queue = GetOfflineQueue(param);
            break;
        default:
            PrintMeErrorMessage("SetTypeOfQueue", "wrong type of queue");
            return ME_FAIL;
    }

    if(*queue == NULL)
    {
        PrintMeErrorMessage("SetTypeOfQueue", "cannot get queue");
        return ME_FAIL;
    }

    return ME_OK;
}

TQueue* GetOnlineQueue(TQueueParam param)
{
    TQueue* queue = (TQueue*)(malloc(sizeof(TQueue)));
    if(queue == NULL)
    {
        PrintMeErrorMessage("GetOnlineQueue", "malloc");
        return NULL;
    }

    queue->type = ONLINE;
    queue->head = CreateBackstop();
    queue->pcap = NULL;

    return queue;
}

TQueueItem* CreateBackstop()
{
    TQueueItem* item = (TQueueItem*)(malloc(sizeof(TQueueItem)));
    if(item == NULL)
    {
        PrintMeErrorMessage("CreateBackstop", "malloc");
        return NULL;
    }

    item->packet = NULL;
    item->next = NULL;
    item->backstop = true;

    return item;
}


TQueue* GetOfflineQueue(TQueueParam param)
{
    return NULL;
}