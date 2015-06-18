#include "storing.h"

TStoreDataReadyCallback DataReady_callback = NULL;
TStorePrepareDataCallback PrepareData_callback = NULL;
TStoreCallback Store_callback = NULL;
TStoreConditionCallback Condition_callback = NULL;

void RegisterStoreCallbacks(TStoreDataReadyCallback ready,
            TStorePrepareDataCallback prepare,
            TStoreCallback store,
            TStoreConditionCallback condition)
{
    DataReady_callback = ready;
    PrepareData_callback = prepare;
    Store_callback = store;
    Condition_callback = condition;
}

void* storing(void *arg)
{
    printf("Storing thread started ...\n");

    while(1)
    {
        pthread_mutex_lock(&store_mutex);

        while (!DataReady_callback()) {
            /* ne, zahaj čekání a odemkni mutex */
            pthread_cond_wait(&store_cond, &store_mutex);
            /* čekání přerušeno, mutex je zamčený */
        }

        PrepareData_callback();

        pthread_mutex_unlock(&store_mutex);

        printf("storing(...)\n");
        Store_callback();
    }
}

void call_storing()
{
    // Signal to storing thread
      pthread_mutex_lock(&store_mutex);

      Condition_callback();

      pthread_cond_signal(&store_cond);

      pthread_mutex_unlock(&store_mutex);
}