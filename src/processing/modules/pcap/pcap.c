#include "pcap.h"

pcap_t* pcap_handle = NULL;
pcap_dumper_t* pcap_dumpfile = NULL;

typedef struct pcap_pkthdr pcap_pkthdr_t;

void Pcap(TQueueItem* start, TQueueItem* stop)
{
	open_pcap("/tmp/out.pcap");
	TQueueItem* item = start;

    while(item != NULL)
    {
        TPacket* packet = item->packet;
        //print_packet(packet);
        //pcap_dump((u_char*)dumpfiles[dscp], header, packet);

// onep_dpss_pkt_get_l2_start	(	onep_dpss_paktype_t * 	pak, uint8_t ** 	l2_start, uint32_t * 	l2_length )	

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

		printf("%lu\n", item->timestamp.tv_nsec);

		pcap_pkthdr_t x = {{0, 0}, packet_l2_length, packet_l2_length};
		printf("x:%d, t:%d\n", sizeof(struct pcap_pkthdr), sizeof(struct timeval));

		pcap_dump((u_char*)pcap_dumpfile, &x, packet_l2_start);

        //printf("0x%1x 0x%1x 0x%1x\n", packet_l2_start[0], packet_l2_start[1], packet_l2_start[2]);

        item = GetNextItem(item, stop);
    }
	printf("pcap!\n");
}

/*
if (dumpfiles[dscp] == NULL) {
        // name output file 
        unsigned file_name_size = folder_name_len + 
                                sizeof(PCAP_FILE_PREFIX) + 
                                sizeof(PCAP_FILE_SUFFIX) +
                                2 +  numbers in dscp tag 
                                1;   end of string 
        char file_name[file_name_size];
        sprintf (file_name, "%s/%s%02u%s", folder, PCAP_FILE_PREFIX, dscp, PCAP_FILE_SUFFIX);
        // open output file 
        dumpfiles[dscp] = pcap_dump_open(handle, file_name);
        if (dumpfiles[dscp] == NULL) {
            fprintf(stderr, "Couldn't open output file.\n");
            exit(EXIT_FAILURE);
        }
    }

     save the packet to the file 
    pcap_dump((u_char*)dumpfiles[dscp], header, packet);
*/

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

