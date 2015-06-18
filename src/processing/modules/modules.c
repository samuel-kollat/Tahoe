#include "modules.h"

TQueueCallback SelectModule(char* name)
{
    TQueueCallback callback = NULL;

    if(strcmp(name, "print") == 0)
    {
        callback = Print;
    }
    else if(strcmp(name, "pcap") == 0)
    {
        callback = Pcap;
    }
    else if(strcmp(name, "dns") == 0)
    {
        callback = AnalyzeDns;
    }
    //else if() ...
    else
    {
        fprintf(stderr, "Warning: No callback added!\n");
        callback = NULL;
    }

    return callback;
}

TStoreDataReadyCallback SelectStoreReady(char* name)
{
    TStoreDataReadyCallback callback = NULL;

    if(strcmp(name, "dns") == 0)
    {
        callback = DnsDataReady;
    }
    //else if() ...
    else
    {
        fprintf(stderr, "Warning: No callback added!\n");
        callback = NULL;
    }

    return callback;
}

TStorePrepareDataCallback SelectStorePrepare(char* name)
{
    TStorePrepareDataCallback callback = NULL;

    if(strcmp(name, "dns") == 0)
    {
        callback = DnsDataPrepare;
    }
    //else if() ...
    else
    {
        fprintf(stderr, "Warning: No callback added!\n");
        callback = NULL;
    }

    return callback;
}

TStoreConditionCallback SelectStoreCondition(char* name)
{
    TStoreConditionCallback callback = NULL;

    if(strcmp(name, "dns") == 0)
    {
        callback = DnsDataCondition;
    }
    //else if() ...
    else
    {
        fprintf(stderr, "Warning: No callback added!\n");
        callback = NULL;
    }

    return callback;
}

TStoreCallback SelectStoreModule(char* name)
{
    TStoreCallback callback = NULL;

    if(strcmp(name, "dns") == 0)
    {
        callback = DnsStore;
    }
    //else if() ...
    else
    {
        fprintf(stderr, "Warning: No callback added!\n");
        callback = NULL;
    }

    return callback;
}