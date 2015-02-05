#include "connector.h"

void PrintMeErrorMessage(char* dst, char* msg)
{
    fprintf(stderr, "Error in Connector (%s): %s\n", dst, msg);
    return;
}

TMeStatus SetTypeOfQueue(TQueueType type,
    TQueueParam param, TQueue** queue)
{

    *queue = GetQueue(type, param);

    if(*queue == NULL)
    {
        PrintMeErrorMessage("SetTypeOfQueue", "cannot get queue");
        return ME_FAIL;
    }

    return ME_OK;
}