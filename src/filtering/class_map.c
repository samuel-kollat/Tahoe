#include "class_map.h"

//
void class_map_begin(   onep_network_element_t *elem,           // Network element
                        onep_policy_table_cap_t *table_cap,     // Traffic action table
                        onep_policy_cmap_attr_e attribute,      // Logical AND or OR between rules
                        onep_policy_entry_op_t *entry_op,       // Entry operation
                        char* cmap_name,                        // Class map name
                        onep_policy_op_list_t **cmap_op_list,   // RETURN | Operation list
                        onep_policy_cmap_op_t **cmap_op,        // RETURN | Operation
                        onep_policy_match_holder_t **mh )       // RETURN | Match holder
{
    // 0. Local variables
    onep_policy_op_list_t *cmap_op_list_tmp = NULL;
    onep_policy_cmap_op_t *cmap_op_tmp = NULL;
    onep_policy_match_holder_t *mh_tmp = NULL;
    onep_status_t rc = ONEP_OK;

    if (onep_policy_table_cap_supports_cmap(table_cap))
    {
        // 1. Create the op_list
        rc = onep_policy_cmap_op_list_new(&cmap_op_list_tmp);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in onep_policy_cmap_op_list_new: %d, %s\n",
                   rc, onep_strerror(rc));
          goto cleanup;
        }

        // 2. Add the network element
        rc = onep_policy_op_add_network_element(cmap_op_list_tmp, elem);
        if(rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_policy_op_add_network_element: %d, %s\n",
               rc, onep_strerror(rc));
            goto cleanup;
        }

        // 3. Create a specific operation on the list
        rc = onep_policy_cmap_op_create(cmap_op_list_tmp, table_cap, &cmap_op_tmp);
        if(rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_policy_cmap_op_create: %d, %s\n",
               rc, onep_strerror(rc));
            goto cleanup;
        }

        // 4. Logical ANR or OR
        rc = onep_policy_cmap_op_set_attribute(cmap_op_tmp, attribute);
        if(rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_policy_cmap_op_set_attribute: %d, %s\n",
               rc, onep_strerror(rc));
            goto cleanup;
        }

        // 5.
        if (onep_policy_table_cap_supports_persistent(table_cap)) {
            rc =  onep_policy_cmap_op_set_persistent(cmap_op_tmp, cmap_name);
            if(rc != ONEP_OK) {
                fprintf(stderr, "\nError in onep_policy_cmap_op_set_persistent: %d, %s\n",
                    rc, onep_strerror(rc));
                goto cleanup;
            }
        } 

        // 6. Get the match holder for the operation instance
        rc = onep_policy_cmap_op_get_match_holder(cmap_op_tmp, &mh_tmp);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in onep_policy_cmap_op_get_match_holder: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }

        // 7. Prepare out values
        *cmap_op_list = cmap_op_list_tmp;
        *cmap_op = cmap_op_tmp;
        *mh = mh_tmp;
    }
    else
    {
        // 1. Create match holder
        rc = onep_policy_entry_op_get_match_holder(entry_op, &mh_tmp);
        if(rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_policy_entry_op_get_match_holder: %d, %s\n",
                rc, onep_strerror(rc));
            goto cleanup;
        }

        // 2. Prepare out values
        *mh = mh_tmp;
    }

    cleanup:

    return;
}

//
void class_map_finish(  onep_policy_table_cap_t *table_cap,     // Traffic action table
                        onep_policy_op_list_t *cmap_op_list,    // Operation list
                        onep_policy_cmap_op_t *cmap_op,         // Operation
                        onep_policy_entry_op_t **entry_op )     // RETURN | Entry operation
{
    // 0. Local variables
    onep_collection_t *result_list = 0;
    onep_iterator_t *iter = 0;
    onep_policy_cmap_handle_t cmap_handle;
    onep_policy_entry_op_t *entry_op_tmp = *entry_op;
    onep_status_t rc = ONEP_OK;

    // 1. Only for class map support
    if (! onep_policy_table_cap_supports_cmap(table_cap))
    {
        return;
    }

    // 2. Update class map
    rc = onep_policy_op_update(cmap_op_list);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_op_update 1: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    // 3. Find the cmap_handle we just created
    rc = onep_policy_op_list_get_list(cmap_op_list, &result_list);
    if(rc != ONEP_OK) {
        fprintf(stderr, "\nError in onep_policy_op_list_get_list: %d, %s\n",
           rc, onep_strerror(rc));
        goto cleanup;
    }

    rc = onep_collection_get_iterator(result_list, &iter);
    if(rc != ONEP_OK) {
        fprintf(stderr, "\nError in onep_collection_get_iterator: %d, %s\n",
           rc, onep_strerror(rc));
        goto cleanup;
    }
    
    cmap_op = (onep_policy_cmap_op_t *)onep_iterator_next(iter);
        if (!cmap_op) {
            fprintf(stderr, "\nError in getting policy op\n");
            goto cleanup;
     }

     rc = onep_policy_cmap_op_get_handle(cmap_op, &cmap_handle);
        if(rc != ONEP_OK) {
            fprintf(stderr, "\nError in creating class map : %d, %s\n",
                rc, onep_strerror(rc));
            goto cleanup;
    }


    // 4. Set the cmap on the entry
    rc = onep_policy_entry_op_add_cmap(entry_op_tmp, cmap_handle);
    if(rc != ONEP_OK) {
        fprintf(stderr, "\nError in onep_policy_entry_op_add_cmap: %d, %s\n",
            rc, onep_strerror(rc));
        goto cleanup;
    }

    // 5. Prepare out values
    *entry_op = entry_op_tmp;

    cleanup:

    return;
}

//
void class_map_add_l7_protocol( onep_policy_match_holder_t *mh,     // Match holder
                                char* protocol_name )               // Name of L7 protocol
{   
    // 0. Local variables
    onep_policy_match_t *match = 0;
    onep_status_t rc = ONEP_OK;

    // 1. Set NBAR rule
    rc = onep_policy_match_add_application(mh, protocol_name, NULL, NULL, &match);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_match_add_application: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    cleanup:

    return;
}

//
void class_map_add_acl( onep_policy_match_holder_t *mh,     // Match holder
                        onep_policy_access_list_t *acl )    // Name of L7 protocol
{
    // 0. Local variables
    onep_policy_match_t *match = 0;
    onep_status_t rc = ONEP_OK;

    // 1. Set ACL
    rc = onep_policy_match_add_access_list( mh, acl, &match);
    if(rc != ONEP_OK) {
        fprintf(stderr, "\nError in onep_policy_match_add_access_list: %d, %s\n",
            rc, onep_strerror(rc));
        goto cleanup;
    }

    cleanup:

    return;
}