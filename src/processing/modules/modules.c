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