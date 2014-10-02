/*
 * Copyright (c) 2010-2013 by Cisco Systems, Inc.
 * 
 * session_element_util.h
 *
 * THIS SAMPLE CODE IS PROVIDED "AS IS" WITHOUT ANY EXPRESS OR IMPLIED WARRANTY
 * BY CISCO SOLELY FOR THE PURPOSE of PROVIDING PROGRAMMING EXAMPLES.
 * CISCO SHALL NOT BE HELD LIABLE FOR ANY USE OF THE SAMPLE CODE IN ANY
 * APPLICATION.
 *
 * Redistribution and use of the sample code, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * Redistributions of source code must retain the above disclaimer.
 */
#include "onep_core_services.h"
#include "onep_constants.h"

void 
disconnect_network_element (onep_network_element_t **ne,
                            onep_session_handle_t **session_handle);

onep_session_handle_t * 
connect_network_element (char *ipaddr, char *username, char *password, 
                         char *app_name, char *transport_type, 
                         onep_network_element_t **ne); 

void
read_properties (onep_network_element_t *ne); 

char *
get_element_hostname (void);

char *
get_login_username (void);

char *
get_login_password (void);

char *
get_transport_type (void);

char *
get_client_cert_path (void);

char *
get_client_key_path (void);

char *
get_key_passphrase (void);

char *
get_root_cert_path (void);

char *
get_tls_pinning_path(void);

int
parse_options (int argc, char *argv[]);

char *
get_usage_required_options (void);

char *
get_usage_optional_options (void);

void
read_file (const char *arg0, const char *filename,
           int *arg_count, char ***file_args);

void
prompt_authentication (void);

void
prompt_client_key_passphrase (void);

onep_tls_pinning_cb_t
accept_handler (const unsigned char *server_name,	
		const unsigned char *hash_type,
		const unsigned char *fingerprint,
		bool changed);
