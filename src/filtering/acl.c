#include "acl.h"

//
void acl_begin( onep_network_element_t *elem,   // Network element
                onep_acl_t **acl )              // RETURN | ACL
{
    // 0. Local variables
    onep_acl_t *acl_tmp;
    onep_status_t rc = ONEP_OK;

    // 1. Create ACL structure
    rc = onep_acl_create_l3_acl(AF_INET, elem, &acl_tmp);
    if(rc != ONEP_OK) {
        fprintf(stderr, "\nError in onep_acl_create_l3_acl: %d, %s\n",
            rc, onep_strerror(rc));
        goto cleanup;
    }

    // 2. Prepare out value
    *acl = acl_tmp;

    cleanup:

    return;
}

//
void acl_finish(onep_acl_t *acl,    // ACL
                onep_ace_t *ace )   // ACE
{
    // 0. Local variables
    onep_status_t rc = ONEP_OK;

    // 1. Add Ace to ACL
    rc = onep_acl_add_ace(acl, ace);
    if(rc != ONEP_OK) {
        fprintf(stderr, "\nError in onep_acl_add_ace: %d, %s\n",
            rc, onep_strerror(rc));
        goto cleanup;
    }

    cleanup:

    return;
}

//
void ace_init(  int sequence,       // Sequence number
                onep_ace_t **ace )  // RETURN | ACE
{
    // 0. Local variables
    onep_ace_t *ace_tmp;
    onep_status_t rc = ONEP_OK;

    // 1. Create ACE structure
    rc = onep_acl_create_l3_ace(sequence, TRUE, &ace_tmp);
    if(rc != ONEP_OK) {
        fprintf(stderr, "\nError in onep_acl_create_l3_ace: %d, %s\n",
            rc, onep_strerror(rc));
        goto cleanup;
    }

    // 2. Prepare out value
    *ace = ace_tmp;

    cleanup:

    return;
}

//
void ace_add_ip(onep_ace_t *ace,                // ACE
                char* src_prefix,               // Source IP prefix
                uint16_t src_length,            // Source IP prefix length
                char* dst_prefix,               // Destination IP prefix
                uint16_t dst_length )           // Destination IP prefix length

{
    // 0. Local variables
    onep_status_t rc = ONEP_OK;
    struct sockaddr_in ip4addr_src;
    struct sockaddr_in ip4addr_dst;
    struct sockaddr* sock_src;
    struct sockaddr* sock_dst;

    // 1. Set src prefix
    if(src_prefix != NULL)
    {
        ip4addr_src.sin_family = AF_INET;
        sock_src = (struct sockaddr*)&ip4addr_src;
        inet_pton(AF_INET, src_prefix, &ip4addr_src.sin_addr);

        rc = onep_acl_set_l3_ace_src_prefix(ace, sock_src, src_length);
        if(rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_acl_set_l3_ace_src_prefix : %d, %s\n",
                rc, onep_strerror(rc));
            goto cleanup;
        }
    }

    // 2. Set dest prefix
    if(dst_prefix != NULL)
    {
        ip4addr_dst.sin_family = AF_INET;
        sock_dst = (struct sockaddr *)&ip4addr_dst;
        inet_pton(AF_INET, dst_prefix, &ip4addr_dst.sin_addr);

        rc = onep_acl_set_l3_ace_dst_prefix(ace, sock_dst, dst_length);
        if(rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_acl_set_l3_ace_dst_prefix: %d, %s\n",
                rc, onep_strerror(rc));
            goto cleanup;
        }
    }

    cleanup:

    return;
}

//
void ace_add_protocol(  onep_ace_t *ace,                // ACE
                        onep_acl_protocol_e protocol )  // L3 protocol
{
    // 0. Local variables
    onep_status_t rc = ONEP_OK;

    // 1. Set protocol
    rc = onep_acl_set_l3_ace_protocol(ace, protocol);
    if(rc != ONEP_OK) {
        fprintf(stderr, "\nError in onep_acl_set_l3_ace_protocol: %d, %s\n",
            rc, onep_strerror(rc));
        goto cleanup;
    }

    cleanup:

    return;
}

//
void ace_add_port(  onep_ace_t *ace,                    // ACE
                    uint16_t src_port,                  // Source port
                    onep_operator_e src_operator,       // Source match operator
                    uint16_t dst_port,                  // Destination port
                    onep_operator_e dst_operator )      // Destination match operator
{
    // 0. Local variables
    onep_status_t rc = ONEP_OK;

    // 1. Set src port
    rc = onep_acl_set_l3_ace_src_port(ace, src_port, src_operator);
    if(rc != ONEP_OK) {
        fprintf(stderr, "\nError in onep_acl_set_l3_ace_src_port: %d, %s\n",
            rc, onep_strerror(rc));
        goto cleanup;
    }

    // 2. Set dst port
    rc = onep_acl_set_l3_ace_dst_port(ace, dst_port, dst_operator);
    if(rc != ONEP_OK) {
        fprintf(stderr, "\nError in onep_acl_set_l3_ace_dst_port: %d, %s\n",
            rc, onep_strerror(rc));
        goto cleanup;
    }

    cleanup:

    return;
}