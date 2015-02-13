#include "print.h"

void Print(TQueueItem* start, TQueueItem* stop)
{
    TQueueItem* item = start;

    while(item != NULL)
    {
        TPacket* packet = item->packet;
        print_packet(packet);

        item = GetNextItem(item, stop);
    }
}

void print_packet(TPacket* packet)
{
    struct onep_dpss_paktype_* pak = (struct onep_dpss_paktype_*)packet;

    onep_status_t        rc;
    onep_dpss_fid_t      fid;
    char                 ipv = 0;
    uint16_t             src_port = 0;
    uint16_t             dest_port = 0;
    char                 *src_ip = NULL;
    char                 *dest_ip = NULL;
    char                 l4_protocol[5];
    char                 l4_state[30];

    strcpy(l4_protocol,"ERR");
    strcpy(l4_state,"ERR");

    rc = onep_dpss_pkt_get_flow(pak, &fid);
    if( rc == ONEP_OK ) {
        rc = proc_pi_get_ip_version(pak, &ipv);
        if( rc != ONEP_OK ) {
            fprintf(stderr, "Error in get ip version: code[%d], text[%s]\n",
                    rc, onep_strerror(rc));
        }
        rc = proc_pi_get_ip_port_info(pak, &src_ip,
                                            &dest_ip,
                                            &src_port,
                                            &dest_port,
                                            l4_protocol,
                                            ipv);
        if( rc != ONEP_OK ) {
          fprintf(stderr, "Error in get ip port info: code[%d], text[%s]\n",
                  rc, onep_strerror(rc));
        }
        proc_pi_get_flow_state(pak, fid, l4_state);

    } else {
        fprintf(stderr, "Error getting flow ID. code[%d], text[%s]\n",
              rc, onep_strerror(rc));
    }



    printf(
        "\n"
        "\033[22;4;30m"
        "| FID | IPv | Source                  |"
        " Destination             | Prot | Pkt# | State                     |\n"
        "\033[0m");
    printf(
      "| %-3"PRIu64" |  %c  | %-15s : %-5d | %-15s : %-5d | %-4s | %-25s |\n\n",
      fid, ipv, src_ip, src_port, dest_ip, dest_port,
      l4_protocol, l4_state);
    free(src_ip);
    free(dest_ip);
    return;
}

onep_status_t proc_pi_get_ip_version(   struct onep_dpss_paktype_ *pakp,
                                        char *ip_version )
{

    onep_status_t rc;
    uint16_t l3_protocol;
    char l3_prot_sym = 'U';

    /* Get packet L3 protocol. */
    rc = onep_dpss_pkt_get_l3_protocol(pakp, &l3_protocol);
    if( rc == ONEP_OK ) {
        if( l3_protocol == ONEP_DPSS_L3_IPV4 ) {
            l3_prot_sym = '4';
        } else if( l3_protocol == ONEP_DPSS_L3_IPV6 ) {
            l3_prot_sym = '6';
        } else if( l3_protocol == ONEP_DPSS_L3_OTHER ) {
            l3_prot_sym = 'N';
        } else {
            l3_prot_sym = 'U';
        }
    } else {
        fprintf(stderr, "Error getting L3 protocol. code[%d], text[%s]\n",
              rc, onep_strerror(rc));
        return (rc);
    }
    *ip_version = l3_prot_sym;
    return (ONEP_OK);
}

onep_status_t proc_pi_get_ip_port_info( struct onep_dpss_paktype_ *pakp,
                                        char **src_ip,
                                        char **dest_ip,
                                        uint16_t *src_port, uint16_t *dest_port,
                                        char *prot,
                                        char ip_version )
{

    onep_status_t   rc;
    uint8_t         l4_protocol;
    uint8_t         *l3_start;
    struct iphdr    *l3hdr;
    uint8_t         *l4_start;
    struct tcphdr   *l4tcp;
    struct udphdr   *l4udp;

    if( ip_version == '4' ) {
        /* get IPv4 header */
        rc = onep_dpss_pkt_get_l3_start(pakp, &l3_start);
        if( rc==ONEP_OK ) {
            l3hdr = (struct iphdr *)l3_start; // convert to iphdr
            *src_ip = strdup(inet_ntoa( *(struct in_addr *)&(l3hdr->saddr) ));
            *dest_ip = strdup(inet_ntoa( *(struct in_addr *)&(l3hdr->daddr) ));
        } else {
            fprintf(stderr,"Error getting IPv4 header. code[%d], text[%s]\n",
                  rc, onep_strerror(rc));
            return (ONEP_ERR_SYSTEM);
        }
    } else if( ip_version == '6' ) {
        fprintf(stderr, "Cannot get IPv6 traffic at this time.\n");
        return (ONEP_ERR_SYSTEM);
    } else if( ip_version == 'N' ) {
        fprintf(stderr, "IP address is neither IPv4 nor IPv6.\n");
        return (ONEP_ERR_SYSTEM);
    } else {
        fprintf(stderr, "Unknown IP version.\n");
        return (ONEP_ERR_SYSTEM);
    }

    /* get L4 header */
    rc = onep_dpss_pkt_get_l4_start(pakp, &l4_start);
    if( rc != ONEP_OK ) {
        fprintf(stderr, "Error getting L4 header. code[%d], text[%s]\n",
              rc, onep_strerror(rc));
        return (rc);
    }

    /* get packet L4 protocol */
    rc = onep_dpss_pkt_get_l4_protocol(pakp, &l4_protocol);
    if( rc == ONEP_OK ) {
        if( l4_protocol == ONEP_DPSS_TCP_PROT ) {
            /* TCP */
            strcpy(prot,"TCP");
            l4tcp = (struct tcphdr *)l4_start;
            *src_port = ntohs( l4tcp->source );
            *dest_port = ntohs( l4tcp->dest );
        }
        else if( l4_protocol == ONEP_DPSS_UDP_PROT ) {
            /* UDP */
            strcpy(prot,"UDP");
            l4udp = (struct udphdr *)l4_start;
            *src_port = ntohs( l4udp->source );
            *dest_port = ntohs( l4udp->dest );
        }
        else if( l4_protocol == ONEP_DPSS_ICMP_PROT ) {
            strcpy(prot,"ICMP");
        }
        else if( l4_protocol == ONEP_DPSS_IPV6_ENCAPSULATION_PROT ) {
            // sends IPV6 packet as payload of IPV4
            strcpy(prot,"ENCP"); // IPV6 encapsulated on IPV4
        }
        else {
            strcpy(prot,"UNK!"); // Unknown!
        }
    }
    else {
        fprintf(stderr, "Error getting L4 protocol. code[%d], text[%s]\n",
              rc, onep_strerror(rc));
    }
    return (ONEP_OK);
}

void proc_pi_get_flow_state(struct onep_dpss_paktype_ *pakp,
                            onep_dpss_flow_ptr_t fid,
                            char *l4_state_char )
{

    onep_status_t             rc;
    onep_dpss_l4_flow_state_e l4_state;

    rc = onep_dpss_flow_get_l4_flow_state(pakp,&l4_state);
    if( rc==ONEP_OK ) {
        if( l4_state == ONEP_DPSS_L4_CLOSED ) {
            strcpy(l4_state_char,"CLOSED");
        } else if( l4_state == ONEP_DPSS_L4_OPENING ) {
            strcpy(l4_state_char,"OPENING");
        } else if( l4_state == ONEP_DPSS_L4_UNI_ESTABLISHED ) {
            strcpy(l4_state_char,"UNI-ESTABLISHED");
        } else if( l4_state == ONEP_DPSS_L4_UNI_ESTABLISHED_INCORRECT ) {
            strcpy(l4_state_char,"UNI-ESTABLISHED INCORRECT");
        } else if( l4_state == ONEP_DPSS_L4_BI_ESTABLISHED ) {
            strcpy(l4_state_char,"BI-ESTABLISHED");
        } else if( l4_state == ONEP_DPSS_L4_BI_ESTABLISHED_INCORRECT ) {
            strcpy(l4_state_char,"BI-ESTABLISHED INCORRECT");
        } else if( l4_state == ONEP_DPSS_L4_CLOSING ) {
            strcpy(l4_state_char,"CLOSING");
        } else {
            strcpy(l4_state_char,"!UNKNOWN!");
        }
    } else {
        fprintf(stderr, "Error getting L4 state of flow. code[%d], text[%s]\n",
              rc, onep_strerror(rc));
    }
    return;
}