#ifndef __MIDDLEND_MODULES__
#define __MIDDLEND_MODULES__

#include "../connector.h"

// Modules
#include "print/print.h"
#include "pcap/pcap.h"

//
TQueueCallback SelectModule(char* name);

#endif