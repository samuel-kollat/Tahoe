#ifndef __MIDDLEND_MODULES__
#define __MIDDLEND_MODULES__

#include "../connector.h"
#include "../storing.h"

// Modules
#include "print/print.h"
#include "pcap/pcap.h"
#include "dns/dns.h"

//
TQueueCallback SelectModule(char* name);

TStoreDataReadyCallback SelectStoreReady(char* name);

TStorePrepareDataCallback SelectStorePrepare(char* name);

TStoreConditionCallback SelectStoreCondition(char* name);

TStoreCallback SelectStoreModule(char* name);

#endif