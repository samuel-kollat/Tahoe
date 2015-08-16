/*
 *-----------------------------------------------------------------
 * OneMon
 *-----------------------------------------------------------------
 */

#include "tahoe.h"

// Define global variables
pthread_mutex_t proc_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t proc_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t store_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t store_cond = PTHREAD_COND_INITIALIZER;
TQueue* Packet_queue = NULL;


/* Main application  */
int main (int argc, char* argv[]) {

   uint64_t pak_count, last_pak_count = 0;
   int timeout = 60;
   int loop_count = 1;
   onep_status_t       rc;
   //onep_status_t destroy_rc;

    /* configuration file parser */

  if(argc!=2)
  {
    fprintf(stderr, "Invalid command line parameters. \nUsage: ./tahoe <configuration_file>\n");
    exit(EXIT_FAILURE);
  }

  char* config_filename = argv[1];
  printf("-- Config filename: %s\n", config_filename);
  parse_config(config_filename);

  // select an application from database and fill it into internal structures
  TMApplication* application = get_application(config->application_id);
  set_appl(application);

  // set root certificate
  set_root_cert_path(application->certificate->root_cert_path);

  printf("-- Application name: %s\n", application->name);

  print_db_version();

  /*
   *
   * START: API CALLS
   *
   */

  printf("-- Filters: Creating\n");

  // Initialization, status should be checked after every operation
  TApiStatus s;
  s = InitializeFilters();

  // get application filters
  application->filter = get_application_filters(application->id);

  // get application routers
  application->router = get_application_routers(application->id);

  TMFilter* application_filter = application->filter;

  while(application_filter!=NULL)
  {
    printf("  -- filter %s: creating\n", application_filter->name);
    TFilterData* filter;

    s = GetEmptyFilter(&filter);

    application_filter->access_list = get_filter_access_lists(application_filter->id);
    application_filter->nbar_protocol = get_filter_nbar_protocols(application_filter->id);


    TMAccess_list* facl = application_filter->access_list;
    while(facl!=NULL)
    {

      /* SOURCE IP ADDRESS */
      if(facl->ip_source!=NULL)
      {
        s = AddIPv4ToFilter(filter, SRC, facl->ip_source->address, facl->ip_source->mask);
        if(strcmp(facl->ip_source->address, "0.0.0.0") == 0)
          printf("    -- added SRC IP to filter: ANY\n");
        else
          printf("    -- added SRC IP to filter: %s\n", facl->ip_source->address);
      }
      /* DESTINATION IP ADDRESS */
      if(facl->ip_destination!=NULL)
      {
        s = AddIPv4ToFilter(filter, DST, facl->ip_destination->address, facl->ip_destination->mask);
        if(strcmp(facl->ip_destination->address, "0.0.0.0") == 0)
          printf("    -- added DST IP to filter: ANY\n");
        else
          printf("    -- added DST IP to filter: %s\n", facl->ip_destination->address);
      }

      /* SOURCE PORTS */
      if(facl->pn_source!=NULL)
      {
        if(facl->pn_source->greater_or_equal==facl->pn_source->less_or_equal)
        {
          s = AddPortToFilter(filter, SRC, facl->pn_source->greater_or_equal);
          printf("    -- added %d as SRC port to filter\n", facl->pn_source->greater_or_equal);
        }
      }

      /* DESTINATION PORTS */
      if(facl->pn_destination!=NULL)
      {
        if(facl->pn_destination->greater_or_equal==facl->pn_destination->less_or_equal)
        {
          s = AddPortToFilter(filter, DST, facl->pn_destination->greater_or_equal);
          printf("    -- added %d as DST port to filter\n", facl->pn_destination->greater_or_equal);
        }
      }

      /* L3 PROTOCOLS from ACL */
      if(facl->protocol!=NULL)
      {
        char* l3_protocol = strtok(facl->protocol, ",");
        while(l3_protocol != NULL)
        {
          if(strcmp(l3_protocol, "TCP")==0)
          {
            s = AddL3ProtocolToFilter(filter, TCP);
          }
          else if(strcmp(l3_protocol, "UDP")==0)
          {
            s = AddL3ProtocolToFilter(filter, UDP);
          }
          else if(strcmp(l3_protocol, "ICMP")==0)
          {
            s = AddL3ProtocolToFilter(filter, TCP);
          }
          else if(strcmp(l3_protocol, "IGMP")==0)
          {
            s = AddL3ProtocolToFilter(filter, TCP);
          }
          else if(strcmp(l3_protocol, "ALL")==0)
          {
            ;
          } else {
            printf("    -- UNKNOWN L3 protocol %s\n", l3_protocol);
          }
          printf("    -- added L3 protocol %s\n", l3_protocol);
          l3_protocol = strtok(NULL, ",");
        }
      }

      facl=facl->next;
    }

     /* NBAR protocols - L7 */
    TMNbar_protocol* filter_nbar = application_filter->nbar_protocol;
    while(filter_nbar!=NULL)
    {
      char* l7_protocol = filter_nbar->protocol_id;
      if(strcmp(l7_protocol, "NONE")==0)
      {
        ;
      }
      else if(strcmp(l7_protocol, "HTTP")==0)
      {
        s = AddL7ProtocolToFilter(filter, HTTP);
      }
      else if(strcmp(l7_protocol, "DNS")==0)
      {
        s = AddL7ProtocolToFilter(filter, DNS);
      }
      else if(strcmp(l7_protocol, "DHCP")==0)
      {
        s = AddL7ProtocolToFilter(filter, DHCP);
      }
      else if(strcmp(l7_protocol, "CIFS")==0)
      {
        s = AddL7ProtocolToFilter(filter, CIFS);
      }
      else if(strcmp(l7_protocol, "RTP")==0)
      {
        s = AddL7ProtocolToFilter(filter, RTP);
      }
      else if(strcmp(l7_protocol, "RTCP")==0)
      {
        s = AddL7ProtocolToFilter(filter, RTCP);
      }
      else if(strcmp(l7_protocol, "SIP")==0)
      {
        s = AddL7ProtocolToFilter(filter, SIP);
      }
      else {
        printf("    -- UNKNOWN L7 protocol %s\n", l7_protocol);
      }
      printf("    -- added L7 protocol %s\n", l7_protocol);
      filter_nbar = filter_nbar->next;
    }

    application_filter = application_filter->next;
  }

  // if there are no filters for the application
  if(application->filter==NULL)
  {
    printf("    -- application->filter IS NULL\n");
    // Create new filter
    TFilterData* filter;
    s = GetEmptyFilter(&filter);

    // Filter for any data
    s = AddDefaultFilter(filter);
  }

  printf("-- Filters: Successfully created\n");

  // Set callback for packet processing
  TApiCallback callback = packet_enqueue_callback;
  s = SetCallbackToFilters(callback);

  // Initialize all network elements - routers
  TMRouter* router = application->router;
  while(router!=NULL)
  {
    printf("  -- configuring router %s - %s\n", router->name, router->interfaces);
    TNetworkElement* element;
    char app_name[32];
    sprintf(app_name, "com.tahoe.application.%d", application->id);
    s = InitializeNetworkElement(
       router->management_ip,
       router->username,
       router->password,
       app_name, // TODO
       "tls",  // TODO
       &(element)
    );

    // Connect to the network element
    s = ConnectToNetworkElement(element);

    // Set all interfaces to monitor
    char* interface = strtok(router->interfaces, ",");
    while(interface != NULL)
    {
      printf("    -- setting interface %s\n", interface);
      s = SetInterfaceOnNetworkElement(element, interface);
      interface = strtok(NULL, ",");
    }
    // Deploy to the network element
    s = DeployFiltersToElement(element);

    // get next router
    router = router->next;
  }

  printf ("-- Filters: Done\n");

  /*
   *
   * END: API CALLS
   *
   */

  TMeStatus me_s;

  me_s = SetTypeOfQueue(ONLINE, 1, &Packet_queue);
  me_s = RegisterQueueCallback(SelectModule(application->analyzer->src));
  me_s = RegisterQueueCallbackArgs(application->analyzer->args);

  // Middlend Thread
  pthread_t proc_thread;
  while(pthread_create(&proc_thread, NULL, processing, (void*)Packet_queue)!=0)
  {
    if (errno == EAGAIN) continue;
    fprintf(stderr, "Cannot create new thread. Exiting...\n");
    exit(EXIT_FAILURE);
  }

  // Set callback for data storing
  RegisterStoreCallbacks(
    SelectStoreReady(application->analyzer->src),
    SelectStorePrepare(application->analyzer->src),
    SelectStoreModule(application->analyzer->src),
    SelectStoreCondition(application->analyzer->src)
  );

  // Storing Thread
  pthread_t store_thread;
  while(pthread_create(&store_thread, NULL, storing, NULL)!=0)
  {
    if (errno == EAGAIN) continue;
    fprintf(stderr, "Cannot create new thread. Exiting...\n");
    exit(EXIT_FAILURE);
  }


  last_pak_count = 0;
  /* wait to query the packet loop for the number
  * of packets received and processed. */
  printf ("\n\nWaiting for packets...\n");
  while (1) {
    sleep(timeout);
    (void) onep_dpss_packet_callback_rx_count(&pak_count);
    fprintf(stderr, "Current Packet Count: %"PRIu64"\n", pak_count);
    if (pak_count == last_pak_count) {
      break;
    } else {
      last_pak_count = pak_count;
      loop_count++;
    }
  }

   printf("\n\n******* DISCONNECT AND CLEAN UP *******\n\n");

   /////////////////////
   // TODO:
   //   Refactoring
   /////////////////////

   /*Remove the policies applied to network element */   

   return rc;
}


