#include "pcap.h"

pcap_t* pcap_handle = NULL;
pcap_dumper_t* pcap_dumpfile = NULL;

typedef struct pcap_pkthdr pcap_pkthdr_t;

void Pcap(TQueueItem* start, TQueueItem* stop, TQueueCallbackArgs args)
{
	//printf("%s\n", args);
	open_pcap(args);
	TQueueItem* item = start;

    while(item != NULL)
    {
        TPacket* packet = item->packet;

        uint8_t* packet_l2_start;
        uint32_t packet_l2_length;
        onep_dpss_pkt_get_l2_start(packet, &packet_l2_start, &packet_l2_length);       

        /*
        struct pcap_pkthdr {
	        struct timeval ts;      // time stamp 
	        bpf_u_int32 caplen;     // length of portion present 
	        bpf_u_int32 len;        // length this packet (off wire) 
		};
		*/

		//printf("%lu\n", item->timestamp.tv_nsec);

		pcap_pkthdr_t x = {{0, 0}, packet_l2_length, packet_l2_length};
		//printf("x:%d, t:%d\n", sizeof(struct pcap_pkthdr), sizeof(struct timeval));

		pcap_dump((u_char*)pcap_dumpfile, &x, packet_l2_start);

        item = GetNextItem(item, stop);
    }
}

void open_pcap(char* filename)
{
	if(pcap_handle==NULL)
	{
		pcap_handle = pcap_open_dead(1, 1500);
        if (pcap_handle == NULL) {
            fprintf(stderr, "Couldn't create PCAP handle.\n");
            exit(EXIT_FAILURE);
        }
	}
	if(pcap_dumpfile==NULL)
	{
		pcap_dumpfile = pcap_dump_open(pcap_handle, filename);
        if (pcap_dumpfile == NULL) {
            fprintf(stderr, "Couldn't create PCAP dumpfile.\n");
            exit(EXIT_FAILURE);
        }
	}	
}

