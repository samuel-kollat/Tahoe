/**
 * session_element.c
 *
 * @author The onePK Team (onepk-feedback@cisco.com)
 *
 *
 * Copyright (c) 2012-2013, Cisco Systems, Inc.
 *
 * THIS SAMPLE CODE IS PROVIDED "AS IS" WITHOUT ANY EXPRESS OR IMPLIED WARRANTY
 * BY CISCO SOLELY FOR THE PURPOSE OF PROVIDING PROGRAMMING EXAMPLES.
 * CISCO SHALL NOT BE HELD LIABLE FOR ANY USE OF THE SAMPLE CODE IN ANY
 * APPLICATION.
 *
 * Redistribution and use of the sample code, with or without modification, is
 * subject to the terms and conditions of the Cisco onePK Software Development
 * Kit License Agreement (onePK SDK Internal User License).
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "onep_core_services.h"

#include "session_element_util.h"

/* main function */
int
main (int argc, char* argv[])
{
    onep_network_element_t*     ne = NULL;
    onep_session_handle_t*      session_handle = NULL;

    if (parse_options(argc, argv) == 1) {
        fprintf(stderr, "Usage: %s %s %s\n",
                argv[0],
                get_usage_required_options(),
                get_usage_optional_options());
        return EXIT_FAILURE;
    }
    if (strcasecmp(get_transport_type(), "tipc") != 0
            || strcmp(get_transport_type(), "2") != 0) {
        prompt_authentication();
        prompt_client_key_passphrase();
    }

    fprintf(stderr, "\n********* CONNECT *******\n\n");

    session_handle = connect_network_element(
            get_element_hostname(),
            get_login_username(),
            get_login_password(),
            "Session Element Tutorial",
            get_transport_type(),
            &ne);
    if (session_handle == NULL) {
        fprintf(stderr,
                "\n********* connect_network_element fails *******\n\n");
        return EXIT_FAILURE;
    }

    fprintf(stderr, "\n********* READ PROPERTIES *******\n\n");
    read_properties(ne);

    fprintf(stderr, "\n********* DISCONNECT *******\n\n");
    disconnect_network_element(&ne, &session_handle);

    return EXIT_SUCCESS;
}
