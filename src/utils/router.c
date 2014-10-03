#include "router.h"


//
onep_status_t router_get_table( onep_network_element_t *elem,           // Network element
                                onep_collection_t **tables,             // RETURN | Tables
                                onep_policy_table_cap_t **table_cap )   // RETURN | Datapath table
{
    // 0. Local variables
    onep_status_t rc = ONEP_OK;
    uint32_t table_count = 0;
    onep_collection_t  *matches = NULL, *actions = NULL;
    onep_iterator_t *table_iter, *match_iter, *action_iter;
    bool found = false;
    onep_policy_table_cap_t *table;
    onep_policy_global_cap_t *global_cap;
    onep_policy_cap_filter_t *filter_cap;
    onep_policy_match_cap_t *match_cap;
    onep_policy_match_type_e match_type;
    onep_policy_action_cap_t *action_cap;
    onep_policy_action_type_e action_type;
    onep_status_t destroy_rc = ONEP_OK;
    onep_collection_t *tables_tmp = NULL;

    // 1. Get traffic action table
    rc = onep_policy_get_global_capabilities(elem, &global_cap);
   if (rc != ONEP_OK) {
      fprintf(stderr, "Error in get global cap: %s\n\n", onep_strerror(rc));
      return rc;
   }

   rc = onep_policy_cap_filter_new(&filter_cap);
   if (rc != ONEP_OK) {
      fprintf(stderr, "Error in cap filter: %s\n", onep_strerror(rc));
      return rc;
   }

   rc = onep_policy_global_cap_get_table_list(global_cap, filter_cap, &tables_tmp);
   if (rc != ONEP_OK) {
      fprintf(stderr, "Error in getting table list: %s\n", onep_strerror(rc));
      goto cleanup;
   }

   rc = onep_collection_get_size(tables_tmp, &table_count);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in get cap table size : %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

    // 2. Need to have >0 datapath tables
    if (table_count==0) {
      printf("table count = 0\n");
      return ONEP_FAIL;
    }

    rc = onep_collection_get_iterator(tables_tmp, &table_iter);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in get cap table iterator: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

    rc = onep_policy_cap_filter_set_supported(filter_cap);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in set filter supported: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }
    
    // 3. Query all tables to determine table that supports Datapath actions and ACL matches
    while ((table = (onep_policy_table_cap_t *)onep_iterator_next(table_iter)) && !found) {
        rc = onep_policy_table_cap_get_match_list(table, filter_cap, &matches);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in get match list: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }

        rc = onep_collection_get_iterator(matches, &match_iter);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in get cap table iterator: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }

        while ((match_cap = (onep_policy_match_cap_t *)onep_iterator_next(match_iter)) && !found) {
            rc = onep_policy_match_cap_get_type(match_cap, &match_type);
            if(rc != ONEP_OK) {
              fprintf(stderr, "\nError in get match type: %d, %s\n",
                    rc, onep_strerror(rc));
              goto cleanup;
            }

            if(match_type == ONEP_POLICY_MATCH_TYPE_ACL) {
                rc = onep_policy_table_cap_get_action_list(table, filter_cap, &actions);
                if(rc != ONEP_OK) {
                  fprintf(stderr, "\nError in get match list: %d, %s\n",
                        rc, onep_strerror(rc));
                  goto cleanup;
                }
                rc = onep_collection_get_iterator(actions, &action_iter);
                if(rc != ONEP_OK) {
                  fprintf(stderr, "\nError in get cap table iterator: %d, %s\n",
                        rc, onep_strerror(rc));
                  goto cleanup;
                }

                while ((action_cap = (onep_policy_action_cap_t *)onep_iterator_next(action_iter)) && !found) {
                    rc = onep_policy_action_cap_get_type(action_cap, &action_type);
                    if(rc != ONEP_OK) {
                      fprintf(stderr, "\nError in get match type: %d, %s\n",
                            rc, onep_strerror(rc));
                      goto cleanup;
                    }

                    if(action_type == ONEP_POLICY_ACTION_TYPE_COPY) {
                        *table_cap = table;
                        found = true;
                    }
                }
                rc = onep_collection_destroy(&actions);
                if(rc != ONEP_OK) {
                  fprintf(stderr, "\nError in destroy collection: %d, %s\n",
                        rc, onep_strerror(rc));
                  goto cleanup;
                }

                rc =  onep_iterator_destroy(&action_iter);
                if(rc != ONEP_OK) {
                  fprintf(stderr, "\nError in destroy iterator: %d, %s\n",
                        rc, onep_strerror(rc));
                  goto cleanup;
                }
            }
        }
        rc = onep_collection_destroy(&matches);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in destroy collection: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }

        rc =  onep_iterator_destroy(&match_iter);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in destroy iterator: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }
    }

    rc =  onep_iterator_destroy(&table_iter);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in destroy iterator: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    // 4. Prepare out values
    *tables = tables_tmp;
    
    return rc;
    
    cleanup:
        
        if(matches){
            destroy_rc = onep_collection_destroy(&matches);
            if(destroy_rc != ONEP_OK) {
                     fprintf(stderr, "\nError in destroy matches : %d, %s",
                            destroy_rc, onep_strerror(destroy_rc));
            }
        }
    
    if(actions){
        destroy_rc = onep_collection_destroy(&actions);
        if(destroy_rc != ONEP_OK) {
                 fprintf(stderr, "\nError in destroy actions : %d, %s",
                        destroy_rc, onep_strerror(destroy_rc));
         }
    }
        
    if(table_iter){
        destroy_rc = onep_iterator_destroy(&table_iter);
        if(destroy_rc != ONEP_OK) {
                    fprintf(stderr, "\nError in destroy table_iter : %d, %s",
                                    destroy_rc, onep_strerror(destroy_rc));
                }
     }
        
    if(match_iter){
            destroy_rc = onep_iterator_destroy(&match_iter);
            if(destroy_rc != ONEP_OK) {
                    fprintf(stderr, "\nError in destroy match_iter : %d, %s",
                            destroy_rc, onep_strerror(destroy_rc));
            }
            }
        
    if(action_iter){
            destroy_rc = onep_iterator_destroy(&action_iter);
        if(destroy_rc != ONEP_OK) {
                    fprintf(stderr, "\nError in destroy action_iter : %d, %s",
                            destroy_rc, onep_strerror(destroy_rc));
            }
         }
        
    return rc;
}