/*
 *-----------------------------------------------------------------
 * Nevada - Tahoe
 *-----------------------------------------------------------------
 */

#include "tahoe.h"

/* Main application  */
int main (int argc, char* argv[]) {

  /* configuration file parser */

  /*char* config_filename = "config.dat";

  parse_config(config_filename);

  TMApplication* app = get_application(config->application_id);
  app->filter = get_application_filters(config->application_id);

  printf("%s\n", app->filter->name);


   exit(0);*/

   uint64_t pak_count, last_pak_count = 0;
   int timeout = 60;
   int loop_count = 1;
   onep_status_t       rc;
   //onep_status_t destroy_rc;

   //
   print_db_version();
   //

   /* validate and parse the input. */
   if (parse_options_datapath(argc, argv) == 1) {
      fprintf(stderr, "Usage: %s %s %s %s %s\n",
         argv[0],
         get_usage_required_options(),
         get_usage_required_options_datapath(),
         get_usage_optional_options_datapath(),
         get_usage_optional_options());
      return EXIT_FAILURE;
   }

   if (strcasecmp(get_transport_type(), "tipc") != 0
      || strcmp(get_transport_type(), "2") != 0) {
      prompt_authentication();
      prompt_client_key_passphrase();
   }

  /*
   *
   * START: API CALLS
   *
   */

  printf("-- Filters: Creating\n");

  // Initialization, status should be checked after every operation
  TApiStatus s;
  s = InitializeFilters();

  // Create new filter
  TFilterData* filter;
  s = GetEmptyFilter(&filter);

  // Filter for any data
  //s = AddDefaultFilter(filter);

  // Fill it with data. No need to fill every item
  //s = AddIPv4ToFilter(filter, SRC, "192.168.0.1", 0);
  s = AddPortToFilter(filter, DST, 53);
  s = AddL3ProtocolToFilter(filter, UDP);
  s = AddL7ProtocolToFilter(filter, DNS);

  // Create another new filter and fill it
  // ...

  // Set callback for packet processing
  TApiCallback callback = proc_pi_callback;
  s = SetCallbackToFilters(callback);

  // Initialize a network element
  TNetworkElement* element;
  s = InitializeNetworkElement(
     "10.100.10.101",
     "cisco",
     "cisco",
     "com.tahoe", // TODO
     "tls",  // TODO
     &(element)
  );

  // Connect to the network element
  s = ConnectToNetworkElement(element);

  // Set interface to monitor
  s = SetInterfaceOnNetworkElement(element, "GigabitEthernet0/2");
  s = SetInterfaceOnNetworkElement(element, "GigabitEthernet0/3");

  // Set another interface
  // ...

  printf("-- Filters: Deploying\n");

  // Deploy to the network element
  s = DeployFiltersToElement(element);

  printf ("-- Filters: Done\n");

  /*
   *
   * END: API CALLS
   *
   */

   last_pak_count = 0;
   /* wait to query the packet loop for the number
    * of packets received and processed. */
   printf ("\n\nWaiting for packets...\n");
   while (loop_count < 3) {
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


