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
    //else if() ...
    else
    {
        callback = NULL;
    }

    return callback;
}