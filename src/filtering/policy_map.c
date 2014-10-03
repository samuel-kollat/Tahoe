#include "policy_map.h"

//
void policy_map_begin(  onep_network_element_t *elem,           // Network element
                        onep_policy_table_cap_t *table_cap,     // Router table
                        onep_policy_op_list_t **pmap_op_list,   // RETURN | Policy map operation list
                        onep_policy_pmap_op_t **pmap_op )       // RETURN | Policy map operation
{
    // 0. Local variables
    onep_policy_op_list_t *pmap_op_list_tmp = NULL;
    onep_policy_pmap_op_t *pmap_op_tmp = NULL;
    onep_status_t rc = ONEP_OK;

    // 1. Create the op_list
    rc = onep_policy_pmap_op_list_new(&pmap_op_list_tmp);
    if(rc != ONEP_OK) {
        fprintf(stderr, "\nError in onep_policy_pmap_op_list_new: %d, %s\n",
            rc, onep_strerror(rc));
        goto cleanup;
    }

    // 2. Add the network element
    rc = onep_policy_op_add_network_element(pmap_op_list_tmp, elem);
    if(rc != ONEP_OK) {
        fprintf(stderr, "\nError in onep_policy_op_add_network_element: %d, %s\n",
            rc, onep_strerror(rc));
        goto cleanup;
    }

    // 3. Add pmap create operation to list
    rc = onep_policy_pmap_op_create(pmap_op_list_tmp, table_cap, &pmap_op_tmp);
    if(rc != ONEP_OK) {
        fprintf(stderr, "\nError in onep_policy_pmap_op_create: %d, %s\n",
            rc, onep_strerror(rc));
        goto cleanup;
    }

    // 4. Prepare out values
    *pmap_op_list = pmap_op_list_tmp;
    *pmap_op = pmap_op_tmp;

    cleanup:

    return;
}

//
void policy_map_finish( onep_policy_pmap_op_t *pmap_op,             // Policy map operation
                        onep_policy_op_list_t *pmap_op_list,        // Policy map operation list
                        onep_policy_pmap_handle_t *pmap_handle )    // RETURN | Policy map handle
{
    // 0. Local variables
    onep_iterator_t *iter = 0;
    onep_collection_t *result_list = 0;
    onep_status_t rc = ONEP_OK;

    // 1. Submit the operation.
    rc = onep_policy_op_update(pmap_op_list);
   
    if(rc != ONEP_OK) {
        fprintf(stderr, "\nError in onep_policy_op_update: %d, %s\n",
            rc, onep_strerror(rc));
        goto cleanup;
    }

    // 2. Find the pmap_handle we just created
    rc = onep_policy_op_list_get_list(pmap_op_list, &result_list);
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
    
   
    pmap_op = (onep_policy_pmap_op_t *)onep_iterator_next(iter);
        if (!pmap_op) {
            fprintf(stderr, "Error in getting pmap_op\n");
            rc = ONEP_FAIL;
            goto cleanup;
        }

    rc = onep_policy_pmap_op_get_handle(pmap_op, pmap_handle);
    if(rc != ONEP_OK) {
        fprintf(stderr, "\nError in onep_policy_pmap_op_get_handle: %d, %s\n",
            rc, onep_strerror(rc));
        goto cleanup;
    }

    cleanup:

    return;
}