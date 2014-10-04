/*
 *-----------------------------------------------------------------
 * Nevada - Tahoe
 *-----------------------------------------------------------------
 */

#include "tahoe.h"

// START SNIPPET: get_class
/*
 * Example function to create a simple ACL and Policy Map
 */
onep_status_t dpss_create_filtering_rules(  onep_network_element_t *elem,               // Network element
                                            onep_dpss_pak_callback_t callback,          // Calback for received packets
                                            onep_policy_pmap_handle_t *pmap_handle )    // Policy map handle
{
    // **********
    // Local variables
    onep_policy_table_cap_t *table_cap = 0;
    onep_status_t rc = ONEP_OK;
    onep_status_t destroy_rc = ONEP_OK;
    onep_policy_entry_op_t *entry_op_1;
    onep_policy_entry_op_t *entry_op_2;

    onep_policy_pmap_op_t *pmap_op = NULL;
    onep_policy_op_list_t *pmap_op_list = NULL;
    onep_policy_op_list_t *cmap_op_list = NULL;

    // **********
    // Create ACL
    onep_ace_t *ace = 0;
    onep_acl_t *onep_acl = 0;

    ace_init(40, &ace);
    ace_add_ip(ace, NULL, 0, NULL, 0);
    ace_add_protocol(ace, proto);
    ace_add_port(ace, 0, ONEP_COMPARE_ANY, 0, ONEP_COMPARE_ANY);

    acl_begin(elem, &onep_acl);
    acl_finish(onep_acl, ace);

    // **********
    // Get traffic action table
    rc = router_get_table(elem, &tables, &table_cap);
    if(rc != ONEP_OK) {
      goto cleanup;
    }
    
    // **********
    // Create a policy
    policy_map_begin(
        elem,
        table_cap,
        &pmap_op_list,
        &pmap_op
    );

    // Add entry for class map
    policy_map_add_entry(
        table_cap,
        pmap_op,
        200,
        &entry_op_1
    );

    // Add entry for class map
    policy_map_add_entry(
        table_cap,
        pmap_op,
        300,
        &entry_op_2
    );

    // Try to set policy map persistent with name
    policy_map_try_set_persistent(
        table_cap,
        pmap_op,
        "onep-tahoe-pmap"
    );

    // **********
    // Create class maps

    // Class : 1
    onep_policy_op_list_t *cmap_op_list_1 = NULL;
    onep_policy_cmap_op_t *cmap_op_1 = NULL;
    onep_policy_match_holder_t *mh_1 = NULL;

    class_map_begin(
        elem,
        table_cap,
        ONEP_POLICY_CMAP_ATTR_MATCH_ALL,
        entry_op_1,
        "onep-tahoe-cmap-1",
        &cmap_op_list_1,
        &cmap_op_1,
        &mh_1
    );

    class_map_add_acl(
        mh_1,
        (onep_policy_access_list_t *)onep_acl
    );

    class_map_add_l7_protocol(
        mh_1,
        "dns"
    );

    class_map_finish(
        table_cap,
        cmap_op_list_1,
        cmap_op_1,
        &entry_op_1
    );

    // Class : 2
    onep_policy_op_list_t *cmap_op_list_2 = NULL;
    onep_policy_cmap_op_t *cmap_op_2 = NULL;
    onep_policy_match_holder_t *mh_2 = NULL;

    class_map_begin(
        elem,
        table_cap,
        ONEP_POLICY_CMAP_ATTR_MATCH_ALL,
        entry_op_2,
        "onep-tahoe-cmap-2",
        &cmap_op_list_2,
        &cmap_op_2,
        &mh_2
    );

    class_map_add_l7_protocol(  
        mh_2,
        "http"
    );

    class_map_finish(
        table_cap,
        cmap_op_list_2,
        cmap_op_2,
        &entry_op_2
    );

    // **********
    // Add callbacks to actions
    action_add( 
        entry_op_1,
        ONEP_DPSS_ACTION_COPY,
        callback
    );

    action_add(
        entry_op_2,
        ONEP_DPSS_ACTION_COPY,
        callback
    );

    // **********
    // Finish policy map creation
    policy_map_finish(
        pmap_op,
        pmap_op_list,
        pmap_handle
    );


    // TODO: refactor

   /* Return the acl we created */
   //*acl = onep_acl;

   printf("Successfully created acl.\n");
   printf("Done creating policy handle.\n");
   
   cleanup:
   
   if(cmap_op_list) {
	   destroy_rc = onep_policy_op_list_destroy(&cmap_op_list);
	   if(destroy_rc != ONEP_OK) {
		 fprintf(stderr, "\nError in onep_policy_op_list_destroy: %d, %s\n",
			 destroy_rc, onep_strerror(destroy_rc));
	   }
    }
   if(pmap_op_list) {
	   destroy_rc = onep_policy_op_list_destroy(&pmap_op_list);
	   if(destroy_rc != ONEP_OK) {
	       fprintf(stderr, "\nError in onep_policy_op_list_destroy: %d, %s\n",
		       destroy_rc, onep_strerror(destroy_rc));
	    }
   }
   return rc;
}
// END SNIPPET: get_class

/* Main application  */
int main (int argc, char* argv[]) {
   onep_session_handle_t* sh;
   uint64_t pak_count, last_pak_count = 0;
   int timeout = 60;
   int loop_count = 1;
   unsigned int count = 0;
   onep_status_t       rc;
   //onep_status_t destroy_rc;

   // START SNIPPET: c_variables
   onep_interface_filter_t* intf_filter = NULL;
   onep_collection_t*  intfs = NULL;
   onep_if_name intf_name;
   //onep_policy_op_list_t *cmap_op_list = NULL;
   //onep_policy_op_list_t *pmap_op_list = NULL;
   onep_policy_pmap_handle_t pmap_handle = 0;
   //onep_policy_pmap_op_t *pmap_op = NULL;
   onep_policy_op_list_t *target_op_list = NULL;
   //onep_policy_cmap_handle_t cmap_handle;
   //onep_policy_cmap_op_t *cmap_op = NULL;
   onep_policy_target_op_t *target_op = NULL;
   onep_policy_target_op_t *target_op2 = NULL;  // My
   onep_dpss_pkt_action_type_e the_action;
   //onep_acl_t * acl = NULL;
   onep_dpss_pak_callback_t the_callback_handler;
   // END SNIPPET: c_variables

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
   
   proto = atoi(get_protocol());
   strncpy(intf_name, get_interface(), ONEP_IF_NAME_SIZE - 1);

   /* Connect to the Network Element */
   sh = connect_network_element(
               get_element_hostname(),
               get_login_username(),
               get_login_password(),
               "com.cisco.onepapp.datapath",
               get_transport_type(),
               &ne);

   if (!sh) {
      fprintf(stderr, "\n*** create_network_connection fails ***\n");
      return ONEP_FAIL;
   }
    printf("\n Network Element CONNECT SUCCESS \n");

     // START SNIPPET: get_interface
     /*
      * Get list of interfaces on device, then find the interface we want.
      */
     rc = onep_interface_filter_new(&intf_filter);
     if (rc != ONEP_OK) {
         fprintf(stderr, "\nError creating intf filter. code[%d], text[%s]\n",
                 rc, onep_strerror(rc));
         goto cleanup;
     }
     rc = onep_element_get_interface_list(ne, intf_filter, &intfs);
     if (rc != ONEP_OK) {
        fprintf(stderr, "\nError getting interface. code[%d], text[%s]\n",
                rc, onep_strerror(rc));
        goto cleanup;
     }
     rc = onep_collection_get_size(intfs, &count);
     if (rc != ONEP_OK) {
         fprintf(stderr, "\nError getting interface. code[%d], text[%s]\n",
                 rc, onep_strerror(rc));
         goto cleanup;
     }
     if (count <= 0 ) {
        fprintf(stderr, "\nNo interfaces available");
        goto cleanup;
     }
    // END SNIPPET: get_interface

    /*
     * Display the interfaces we retrieved
     */
    router_print_intf_list(intfs, stderr);

    /*
     * Register some packet handlers.
     */
   onep_network_interface_t *intf;
   onep_network_interface_t *intf2; // My
   printf("\n Name of interface expecting packets: %s\n", intf_name);
   rc = onep_element_get_interface_by_name(ne, intf_name, &intf);
   if (rc != ONEP_OK) {
      fprintf(stderr, "Error in getting interface: %s\n", onep_strerror(rc));
      goto cleanup;
   }

   // My
   rc = onep_element_get_interface_by_name(ne, "GigabitEthernet0/2", &intf2);
   if (rc != ONEP_OK) {
      fprintf(stderr, "Error in getting interface: %s\n", onep_strerror(rc));
      goto cleanup;
   }

   //START SNIPPET: register_packets
   /*
   * Policy action copy - copy packet to DPSS and forward the original.
   * Application is not allowed to modify the packet or return the packet.
   * 
   * Policy action punt/divert - packet sent to DPSS app and does not continue on 
   * it's original path
   * 
   * This tutorial applies COPY action to selected packets.
   */

   the_action = ONEP_DPSS_ACTION_COPY;
   /* Callback function for processing packets.*/
   the_callback_handler = proc_pi_callback;

   /* create a simple ACL and onep Policy map */
   rc = dpss_create_filtering_rules(
        ne,
        the_callback_handler,
        &pmap_handle
    );

    if(rc != ONEP_OK) {
      goto cleanup;
    }

   /*
    * Now we have a policy, we're going to activate it on one
    * interface
    *
    * So, first create a target operation list and set the network
    * element on it.
    */
   printf ("Applying policy on interface %s\n", intf_name);
   rc = onep_policy_target_op_list_new(&target_op_list);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_list_new: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   rc = onep_policy_op_add_network_element(target_op_list, ne);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_op_add_network_element: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   /* Add request to bind policy to interface */
   rc = onep_policy_target_op_activate(target_op_list, &target_op);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_activate: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }
   rc = onep_policy_target_op_add_pmap(target_op, pmap_handle);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_add_pmap: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   rc = onep_policy_target_op_add_interface(target_op, intf);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_add_interface: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   rc = onep_policy_target_op_set_direction(target_op, ONEP_DIRECTION_IN);        // direction of packets
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_set_direction: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   // My
   rc = onep_policy_target_op_activate(target_op_list, &target_op2);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_activate: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }
   rc = onep_policy_target_op_add_pmap(target_op2, pmap_handle);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_add_pmap: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   rc = onep_policy_target_op_add_interface(target_op2, intf2);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_add_interface: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   rc = onep_policy_target_op_set_direction(target_op2, ONEP_DIRECTION_IN);        // direction of packets
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_set_direction: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }
   
   //END SNIPPET: register_packets

   rc = onep_policy_op_update(target_op_list);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_op_update: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }
   printf ("Finished applying policy on interface\n");
   
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

    cleanup:

   return rc;
}


