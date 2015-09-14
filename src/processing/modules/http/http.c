#include "http.h"

static bool data_ready_for_storing = false;

void AnalyzeHttp(TQueueItem* start, TQueueItem* stop, TQueueCallbackArgs args)
{
    TQueueItem* item = start;

    while(item != NULL)
    {
        TPacket* packet = (TPacket*)item->packet;
        HttpAnalyze(packet);

        item = GetNextItem(item, stop);
    }
}

void HttpAnalyze(TPacket* packet)
{
    // Get payload
    uint8_t* payload;
    uint32_t payload_size;
    onep_status_t s = onep_dpss_pkt_get_l2_start((onep_dpss_paktype_t*)packet, &payload, &payload_size);
    if(s != ONEP_OK)
    {
        printf("onep_dpss_pkt_get_l2_start:%d %d %d\n", s, (s == ONEP_OK), (s == ONEP_ERR_BAD_ARGUMENT));
        return;
    }

    // Parse payload
    l2_header l2;
    l3_header l3;
    tcp_header tcp;
    THttpData http;

    parse_l2_header(payload, &l2);
    parse_l3_header(payload, &l3);
    parse_l4_tcp_header(payload, &tcp);

    ParseHttp(payload, payload_size, &tcp, &http);

    store_http_data(&l3, &tcp, &http);

    print_list();

    // Store data to permanent place
    // Wakes up storing thread
    call_storing();

    return;
}

bool HttpDataReady()
{
    return data_ready_for_storing;
}

void HttpDataPrepare()
{
    data_ready_for_storing = false;;
}

void HttpDataCondition()
{
    data_ready_for_storing = true;
}

void HttpStore()
{
    printf("Storing ...\n");

    THttpStats* item = get_list_start();
    while(item != NULL)
    {
        mysql_save_http_data(item);
        item = item->next;
    }

    return;
}

void ParseHttp(uint8_t* packet, uint32_t packet_size, tcp_header* tcp, THttpData* http)
{
    uint32_t tcp_length = tcp->data_offset * 4; // number of 32 bit words -> 8(byte)*4 == 32
    uint32_t offset = L2_HEADER_LENGTH + L3_HEADER_LENGTH + tcp_length;
    uint32_t data_size = packet_size - offset;
    http->method = RESPONSE;
    http->genuine = false;

    if(data_size > HTTP_PROTO_STRING_SIZE)
    {
        /*int i;
        for(i = 0; i < data_size; i++)
        {
            if(packet[offset + i] >= 32 && packet[offset + i] <= 126)
            {
                printf(" %c |", packet[offset + i]);
            }
            else
            {
                printf(" %02x |", packet[offset + i]);
            }
        }*/

        // HEAD
        if(packet[offset + 0] == 'H')
        {
            if(packet[offset + 1] == 'E' && packet[offset + 2] == 'A'
                && packet[offset + 3] == 'D')
            {
                http->method = HEAD;
            }
            else
            {
                http->method = RESPONSE;
            }
        }
        // GET
        else if(packet[offset + 0] == 'G')
        {
            if(packet[offset + 1] == 'E' && packet[offset + 2] == 'T')
            {
                http->method = GET;
            }
            else
            {
                http->method = RESPONSE;
            }
        }
        // POST, PUT
        else if(packet[offset + 0] == 'P')
        {
            // POST
            if(packet[offset + 1] == 'O' && packet[offset + 2] == 'S'
                && packet[offset + 3] == 'T')
            {
                http->method = POST;
            }
            // PUT
            else if(packet[offset + 1] == 'U' && packet[offset + 2] == 'T')
            {
                http->method = PUT;
            }
            else
            {
                http->method = RESPONSE;
            }
        }
        // DELETE
        else if(packet[offset + 0] == 'D')
        {
            if(packet[offset + 1] == 'E' && packet[offset + 2] == 'L'
                && packet[offset + 3] == 'E' && packet[offset + 4] == 'T'
                && packet[offset + 5] == 'E')
            {
                http->method = DELETE;
            }
            else
            {
                http->method = RESPONSE;
            }
        }
        // TRACE
        else if(packet[offset + 0] == 'T')
        {
            if(packet[offset + 1] == 'R' && packet[offset + 2] == 'A'
                && packet[offset + 3] == 'C' && packet[offset + 4] == 'E')
            {
                http->method = TRACE;
            }
            else
            {
                http->method = RESPONSE;
            }
        }
        // CONNECT
        else if(packet[offset + 0] == 'C')
        {
            if(packet[offset + 1] == 'O' && packet[offset + 2] == 'N'
                && packet[offset + 3] == 'N' && packet[offset + 4] == 'E'
                && packet[offset + 5] == 'C' && packet[offset + 6] == 'T' )
            {
                http->method = CONNECT;
            }
            else
            {
                http->method = RESPONSE;
            }
        }
        else
        {
            http->method = RESPONSE;
        }

        // Quantity
        http->quantity = data_size;

        // Status
        http->genuine = true;
    }

    return;
}