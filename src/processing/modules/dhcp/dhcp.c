#include "dhcp.h"

static bool data_ready_for_storing = false;

void AnalyzeDhcp(TQueueItem* start, TQueueItem* stop, TQueueCallbackArgs args)
{
    TQueueItem* item = start;

    while(item != NULL)
    {
        TPacket* packet = (TPacket*)item->packet;
        DhcpAnalyze(packet);

        item = GetNextItem(item, stop);
    }
}

void DhcpAnalyze(TPacket* item)
{
    printf("Data item\n");

    return;
}

bool DhcpDataReady()
{
    return data_ready_for_storing;
}

void DhcpDataPrepare()
{
    data_ready_for_storing = false;
}

void DhcpDataCondition()
{
    data_ready_for_storing = true;
}

void DhcpStore()
{
    return;
}