#ifndef __MIDDLEND_STORING__
#define __MIDDLEND_STORING__

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "../globals.h"


// Type of callback to check for ready data
typedef bool (*TStoreDataReadyCallback)();

// Type of callback to preapare ready data
typedef void (*TStorePrepareDataCallback)();

// Type of callback to store data
typedef void (*TStoreCallback)();

// Type of callback before condition broadcast
// Type of callback to store data
typedef void (*TStoreConditionCallback)();

void RegisterStoreCallbacks(
    TStoreDataReadyCallback ready,
    TStorePrepareDataCallback prepare,
    TStoreCallback store,
    TStoreConditionCallback condition
);

void* storing(
    void* arg
);

void call_storing(
);

extern TStoreDataReadyCallback DataReady_callback;
extern TStorePrepareDataCallback PrepareData_callback;
extern TStoreCallback Store_callback;
extern TStoreConditionCallback Condition_callback;

#endif