#include "dns.h"

void AnalyzeDns(TQueueItem* start, TQueueItem* stop, TQueueCallbackArgs args)
{
    TQueueItem* item = start;

    while(item != NULL)
    {
        TPacket* packet = (TPacket*)item->packet;
        Analyze(packet);

        item = GetNextItem(item, stop);
    }
}

void Analyze(TPacket* packet)
{
    printf("Analyzing ...\n");
    return;
}