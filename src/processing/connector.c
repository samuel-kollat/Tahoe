#include "connector.h"

TQueueCallback Proc_callback = NULL;
TQueueCallbackArgs Proc_callback_args = NULL;
onep_network_element_t* network_element = NULL;

void PrintMeErrorMessage(char* dst, char* msg)
{
    fprintf(stderr, "Error in Connector (%s): %s\n", dst, msg);
    return;
}

TMeStatus SetTypeOfQueue(TQueueType type,
    TQueueParam param, TQueue** queue)
{

    *queue = GetQueue(type, param);

    if(*queue == NULL)
    {
        PrintMeErrorMessage("SetTypeOfQueue", "cannot get queue");
        return ME_FAIL;
    }

    return ME_OK;
}

TMeStatus RegisterQueueCallback(TQueueCallback callback)
{
  // Set global variable with analyzer name
  Proc_callback = callback;

  return ME_OK;
}

TMeStatus RegisterQueueCallbackArgs(char *args)
{
  // Set global variable with arguments for selected analyzer
  Proc_callback_args = args;

  return ME_OK;
}

void* processing(void *arg)
{
  printf("Second thread started ...\n");

  TQueue *queue = (TQueue*) arg;

  while(1)
  {
    TQueueItem* start = NULL;
    TQueueItem* stop = NULL;

    pthread_mutex_lock(&proc_mutex);

    while (!IsChunkReady(queue)) {
      /* ne, zahaj čekání a odemkni mutex */
      pthread_cond_wait(&proc_cond, &proc_mutex);
      /* čekání přerušeno, mutex je zamčený */
    }

    GetChunkRange(queue, &start, &stop);

    pthread_mutex_unlock(&proc_mutex);

    printf("callback(...)\n");
    Proc_callback(start, stop, Proc_callback_args);
  }

}

TMeStatus RegisterNetworkElement(onep_network_element_t* ne)
{
  network_element = ne;

  return ME_OK;
}

onep_network_element_t* GetNetworkElement()
{
  return network_element;
}