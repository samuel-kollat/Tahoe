#include "action.h"

//
void action_add(    onep_policy_entry_op_t *entry_op,   // Entry operation
                    onep_dpss_pkt_action_type_e action,     // DPSS action
                    onep_dpss_pak_callback_t callback ) // Action callback
{
    // 0. Local variables
    onep_policy_action_t *dp_action = 0;
    onep_policy_action_holder_t *ah = 0;
    onep_status_t rc = ONEP_OK;

    rc = onep_policy_entry_op_get_action_holder(entry_op, &ah);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_entry_op_get_action_holder: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    if (action == ONEP_DPSS_ACTION_COPY) {
        printf ("Adding ONEP DPSS Action Copy\n");
        rc = onep_policy_action_add_copy(ah, callback, NULL, &dp_action);
        if(rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_policy_action_add_copy: %d, %s\n",
                rc, onep_strerror(rc));
            goto cleanup;
        }
    }
    else {
       printf ("TODO: Other than ONEP DPSS Action Copy\n");
       goto cleanup;
    }

    cleanup:

    return;
}