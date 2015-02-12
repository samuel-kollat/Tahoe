#include "callback.h"

void packet_enqueue_callback( onep_dpss_traffic_reg_t *reg,
                            struct onep_dpss_paktype_ *pak,
                            void *client_context,
                            bool *return_packet )
{
    InsertPacketToQueue(Packet_queue, (TPacket)pak);
    // Chunk is ready
    if(IsChunkFull(Packet_queue))
    {
      // Signal to second thread
      pthread_mutex_lock(&proc_mutex);

      CompleteChunkInQueue(Packet_queue);

      pthread_cond_signal(&proc_cond);

      pthread_mutex_unlock(&proc_mutex);
    }
}