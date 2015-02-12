#include "modules.h"

TQueueCallback SelectModule(char* name)
{
    TQueueCallback callback = NULL;

    if(strcmp(name, "print") == 0)
    {
        callback = Print;
    }
    //elseif() ...
    else
    {
        callback = NULL;
    }

    return callback;
}