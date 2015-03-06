/*
 *-----------------------------------------------------------------
 * Nevada - Tahoe
 *-----------------------------------------------------------------
 */

#include "tahoe.h"

// Define global variables
pthread_mutex_t proc_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t proc_cond = PTHREAD_COND_INITIALIZER;
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
        printf("    -- added SRC to filter: %s\n", facl->ip_source->address);
      }
      /* DESTINATION IP ADDRESS */
      if(facl->ip_destination!=NULL)
      {
        s = AddIPv4ToFilter(filter, DST, facl->ip_destination->address, facl->ip_destination->mask);
        printf("    -- added DSTIP to filter: %s\n", facl->ip_destination->address);
      }

      /* SOURCE PORTS */
      if(facl->pn_source!=NULL)
      {
        if(facl->pn_source->greater_or_equal==facl->pn_source->less_or_equal)
        {
          s = AddPortToFilter(filter, SRC, facl->pn_source->greater_or_equal);
        }
        printf("    -- added %d as SRC port to filter\n", facl->pn_source->greater_or_equal);
      }

      /* DESTINATION PORTS */
      if(facl->pn_destination!=NULL)
      {
        if(facl->pn_destination->greater_or_equal==facl->pn_destination->less_or_equal)
        {
          s = AddPortToFilter(filter, DST, facl->pn_destination->greater_or_equal);
        }
        printf("    -- added %d as DST port to filter\n", facl->pn_destination->greater_or_equal);
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

  me_s = SetTypeOfQueue(ONLINE, 10, &Packet_queue);
  me_s = RegisterQueueCallback(SelectModule("print"));

  pthread_t proc_thread;
  while(pthread_create(&proc_thread, NULL, processing, (void*)Packet_queue)!=0)
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

   printf("\nDone. Goodbye!");
   printf("\n\n******* DISCONNECT AND CLEAN UP *******\n\n");

   /////////////////////
   // TODO:
   //   Refactoring
   /////////////////////

   /*Remove the policies applied to network element */

   /*
   if(target_op_list) {
           rc = onep_policy_op_list_destroy(&target_op_list);
           if (ONEP_OK != rc) {
                fprintf(stderr, "\nError in destroying target op list : %d, %s", rc, onep_strerror(rc));
                goto cleanup;
           }
    }

    rc = onep_policy_target_op_list_new(&target_op_list);
       if(rc != ONEP_OK) {
            fprintf(stderr, "\nError in creating target op list : %d, %s", rc, onep_strerror(rc));
            goto cleanup;
    }

    //deactivate target
    rc = onep_policy_target_op_deactivate(target_op_list, &target_op);
    if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in deactivating target op : %d, %s", rc, onep_strerror(rc));
          goto cleanup;
    }

    rc = onep_policy_target_op_set_direction(target_op, ONEP_DIRECTION_IN);
    if(rc != ONEP_OK) {
           fprintf(stderr, "\nError in onep_policy_target_op_set_direction: %d, %s",
                 rc, onep_strerror(rc));
           goto cleanup;
    }

    //add interface group to the target
    rc = onep_policy_target_op_add_interface(target_op, intf);
    if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in adding interface to target : %d, %s", rc, onep_strerror(rc));
          goto cleanup;
    }

    rc = onep_policy_target_op_add_pmap(target_op, pmap_handle);
    if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in adding pmap handle to target : %d, %s", rc, onep_strerror(rc));
          goto cleanup;
    }

    rc = onep_policy_op_add_network_element(target_op_list, ne);
    if(rc != ONEP_OK) {
         fprintf(stderr, "\nError in sending target op list to network element : %d, %s", rc, onep_strerror(rc));

    }

    rc = onep_policy_op_update(target_op_list);
    if(rc != ONEP_OK) {
         fprintf(stderr, "\nError in updating target op list : %d, %s", rc, onep_strerror(rc));

    }
	 // removing policy map
	 if(pmap_op_list) {
		 rc = onep_policy_op_list_destroy(&pmap_op_list);
		 if (ONEP_OK != rc) {
			 fprintf(stderr, "\nError in destroying pmap Op List : %d, %s", rc, onep_strerror(rc));
		 }
	 }

	 rc = onep_policy_pmap_op_list_new(&pmap_op_list);
	 if(rc != ONEP_OK) {
		 fprintf(stderr, "\nError in getting Network Application : %d, %s", rc, onep_strerror(rc));
	 }

	 rc = onep_policy_pmap_op_delete(pmap_op_list, pmap_handle, &pmap_op);
	 if(rc != ONEP_OK) {
		fprintf(stderr, "\nError in deleting pmap : %d, %s", rc, onep_strerror(rc));

	 }

	 rc = onep_policy_op_add_network_element(pmap_op_list, ne);
	 if(rc != ONEP_OK) {
		 fprintf(stderr, "\nError in sending pmap op list to network element : %d, %s", rc, onep_strerror(rc));

	 }

	 rc = onep_policy_op_update(pmap_op_list);
	 if(rc != ONEP_OK) {
		 fprintf(stderr, "\nError in updating pmap op list : %d, %s", rc, onep_strerror(rc));

	 }
	 //Removing class map
	 if(cmap_op_list) {
		 rc = onep_policy_op_list_destroy(&cmap_op_list);
		 if (ONEP_OK != rc) {
			fprintf(stderr, "\nError in destroying cmap Op List : %d, %s", rc, onep_strerror(rc));
		 }
	 }

	 rc = onep_policy_cmap_op_list_new(&cmap_op_list);
	 if(rc != ONEP_OK) {
		 fprintf(stderr, "\nError in getting cmap op list : %d, %s", rc, onep_strerror(rc));

	 }

	 rc = onep_policy_cmap_op_delete(cmap_op_list, cmap_handle, &cmap_op);
	 if(rc != ONEP_OK) {
		 fprintf(stderr, "\nError in deleting cmap : %d, %s", rc, onep_strerror(rc));

	 }

	 rc = onep_policy_op_add_network_element(cmap_op_list, ne);
	 if(rc != ONEP_OK) {
		 fprintf(stderr, "\nError in sending op list to network element : %d, %s", rc, onep_strerror(rc));

	 }

	 rc = onep_policy_op_update(cmap_op_list);
	 if(rc != ONEP_OK) {
		 fprintf(stderr, "\nError in updating cmap op list : %d, %s", rc, onep_strerror(rc));

	 }

   cleanup:

      if(target_op_list) {
    	  destroy_rc = onep_policy_op_list_destroy(&target_op_list);
          if(destroy_rc != ONEP_OK) {
        	  fprintf(stderr, "\nError in onep_policy_op_list_destroy: %d, %s",
              destroy_rc, onep_strerror(destroy_rc));
          }
      }

      if(acl) {
         destroy_rc = onep_acl_delete_acl(&acl);
         if(destroy_rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_acl_delete_acl: %d, %s",
                destroy_rc, onep_strerror(destroy_rc));
         }
      }
      if(global_cap) {
         destroy_rc = onep_policy_global_cap_destroy(&global_cap);
         if(destroy_rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_policy_global_cap_destroy: %d, %s",
                destroy_rc, onep_strerror(destroy_rc));
         }
      }
      if(filter_cap) {
         destroy_rc = onep_policy_cap_filter_destroy(&filter_cap);
         if(destroy_rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_policy_cap_filter_destroy: %d, %s",
               destroy_rc, onep_strerror(destroy_rc));
         }
      }
      if(tables) {
         destroy_rc = onep_collection_destroy(&tables);
         if(destroy_rc != ONEP_OK) {
            fprintf(stderr, "\nError in destroy tables : %d, %s",
               destroy_rc, onep_strerror(destroy_rc));
         }
      }
      if(intfs) {
         destroy_rc = onep_collection_destroy(&intfs);
         if(destroy_rc != ONEP_OK) {
             fprintf(stderr, "\nError in destroy intfs : %d, %s",
                 destroy_rc, onep_strerror(destroy_rc));
         }
      }
      if(intf_filter) {
         destroy_rc = onep_interface_filter_destroy(&intf_filter);
         if(destroy_rc != ONEP_OK) {
             fprintf(stderr, "\nError in destroy intf_filter : %d, %s",
                 destroy_rc, onep_strerror(destroy_rc));
         }
      }

    */

   return rc;
}


