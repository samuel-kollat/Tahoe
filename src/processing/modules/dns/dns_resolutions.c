#include "dns_resolutions.h"

static TResolutionItem* head = NULL;
static bool dns_resolution_inited = false;

void init_dns_resolutions()
{
    head = NULL;
    dns_resolution_inited = true;
}

TResolutionItem* get_dns_resolutions_list()
{
    return head;
}

void store_dns_message(l3_header* l3,udp_header* l4, dns_message* message)
{
    // Initialization
    if(!dns_resolution_inited)
    {
        init_dns_resolutions();
    }

    // Search for same transaction
    TResolutionItem* iter = head;
    while(iter != NULL)
    {
        if(iter->resolution.transaction_id[0] == message->header->identifier[0] &&
           iter->resolution.transaction_id[1] == message->header->identifier[1] )
        {
            printf("Same ID\n");
            return;
        }

        iter = iter->next;
    }

    // Create and save new item
    TResolutionItem* item = (TResolutionItem*) malloc(sizeof(TResolutionItem));

    item->processed = false;

    item->resolution.transaction_id[0] = message->header->identifier[0];
    item->resolution.transaction_id[1] = message->header->identifier[1];

    item->resolution.query.src_ip[0] = l3->source_ip[0];
    item->resolution.query.src_ip[1] = l3->source_ip[1];
    item->resolution.query.src_ip[2] = l3->source_ip[2];
    item->resolution.query.src_ip[3] = l3->source_ip[3];

    item->resolution.query.dst_ip[0] = l3->destination_ip[0];
    item->resolution.query.dst_ip[1] = l3->destination_ip[1];
    item->resolution.query.dst_ip[2] = l3->destination_ip[2];
    item->resolution.query.dst_ip[3] = l3->destination_ip[3];

    item->resolution.query.src_port = l4->source_port;
    item->resolution.query.dst_port = l4->destination_port;

    char* str;
    domain_to_str(message->query->query_domain_name, &str);
    item->resolution.query.domain = str;

    item->next = head;
    head = item;
}

void print_dns_resolution_data(TResolutionItem* item)
{
    char* str;

    printf("Trans. ID: %02x %02x\n", item->resolution.transaction_id[0], item->resolution.transaction_id[1]);

    ip_to_str(item->resolution.query.src_ip, &str);
    printf("|\tSrc IP: %s\n", str);

    ip_to_str(item->resolution.query.dst_ip, &str);
    printf("|\tDst IP: %s\n", str);

    printf("|\tSrc port: %u\n", item->resolution.query.src_port);
    printf("|\tDst port: %u\n", item->resolution.query.dst_port);
    printf("|\tDomain name: %s\n", item->resolution.query.domain);

    printf("\n");
}