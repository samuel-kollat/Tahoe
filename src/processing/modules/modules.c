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
    else if(strcmp(name, "http") == 0)
    {
        callback = AnalyzeHttp;
    }
    else if(strcmp(name, "dhcp") == 0)
    {
        callback = AnalyzeDhcp;
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
    else if(strcmp(name, "http") == 0)
    {
        callback = HttpDataReady;
    }
    else if(strcmp(name, "dhcp") == 0)
    {
        callback = DhcpDataReady;
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
    else if(strcmp(name, "http") == 0)
    {
        callback = HttpDataPrepare;
    }
    else if(strcmp(name, "dhcp") == 0)
    {
        callback = DhcpDataPrepare;
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
    else if(strcmp(name, "http") == 0)
    {
        callback = HttpDataCondition;
    }
    else if(strcmp(name, "dhcp") == 0)
    {
        callback = DhcpDataCondition;
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
    else if(strcmp(name, "http") == 0)
    {
        callback = HttpStore;
    }
    else if(strcmp(name, "dhcp") == 0)
    {
        callback = DhcpStore;
    } 
    else if(strcmp(name, "voip") == 0)
    {
        callback = Voip;

    }
    //else if() ...
    else
    {
        fprintf(stderr, "Warning: No callback added!\n");
        callback = NULL;
    }

    return callback;
}