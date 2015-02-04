/**
 * session_element_util.c
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
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

#include "onep_core_services.h"

#include "include/session_element_util.h"

// Size of buffer for authentication prompt
#define LINE_SIZE (ONEP_USERNAME_SIZE > ONEP_PASSWORD_SIZE ? \
                   ONEP_USERNAME_SIZE : ONEP_PASSWORD_SIZE)

// Size of buffer for client key passphrase prompt
#define CLIENT_KEY_PASSPHRASE_SIZE 256

#define FILEV_SIZE      42      // Maximum number of file arguments
#define FILE_ARG_SIZE   1024    // Size of file argument buffer

static int filec = 0;
static char *filev[FILEV_SIZE];

// START SNIPPET: c_global
/* The following variables are required to connect to the network element: */
static char *ne_hostname = NULL;
static onep_username username;
static onep_password password;
static char *transport_type = "tls";
// END SNIPPET: c_global
static char *client_cert_path   = NULL;
static char *client_key_path    = NULL;
static char *key_passphrase     = NULL;
static char *root_cert_path     = NULL;
static char *pin_file = NULL;

/**
 * Get the network element's hostname.
 *
 * @return char*  network element hostname
 */
char *
get_element_hostname ()
{
    return ne_hostname;
}

/**
 * Get the username used to log in to the network element.
 *
 * @return char*  username
 */
char *
get_login_username ()
{
    return username;
}

/**
 * Get the password used to log in to the network element.
 *
 * @return char*  password
 */
char *
get_login_password ()
{
    return password;
}

/**
 * Get the transport type for the connection to the network element.
 *
 * @return char*  transport type
 */
char *
get_transport_type ()
{
    return transport_type;
}

/**
 * Get the path to the client certificate file.
 *
 * @return char*  client certificate path
 */
char *
get_client_cert_path ()
{
    return client_cert_path;
}

/**
 * Get the path to the client private key file.
 *
 * @return char*  client private key path
 */
char *
get_client_key_path ()
{
    return client_key_path;
}

/**
 * Get the passphrase the client private key file.
 *
 * @return char*  client private key passphrase
 */
char *
get_key_passphrase ()
{
    return key_passphrase;
}

/**
 * Get the path to the root certificates file.
 *
 * @return char*  root certificates path
 */
char *
get_root_cert_path ()
{
    return root_cert_path;
}

void 
set_root_cert_path (char* _root_cert_path)
{
    root_cert_path = _root_cert_path;
}

/**
 * Get the path to the tls pinning file.
 *
 * @return char*  tls pinning file path
 */
char *
get_tls_pinning_path ()
{
    return pin_file;
}

/**
 * Parses options from the command line, or, if none are supplied, from a
 * properties file. Parsed options will be referenced in static variables.
 *
 * @param [in] argc  The number of arguments
 * @param [in] argv  The argument vector
 * @return -1  An error occurred while parsing.
 *          0  Parsing completed successfully.
 *          1  One or more required options were missing.
 */
int
parse_options (int argc, char *argv[])
{
    static const struct option options[] = {
        {"hostname",    required_argument,  0,  'a'},
        {"transport",   required_argument,  0,  't'},
        {"clientcert",  required_argument,  0,  'C'},
        {"clientkey",   required_argument,  0,  'K'},
        {"rootcert",    required_argument,  0,  'R'},
        {"tlspinning",    required_argument,  0,  'P'},
        {0}
    };

    int c;
    int option_index;
    
    if (argc <= 1) {    /* No additional command-line arguments were given. */
        read_file(argv[0], "./tutorial.properties", &argc, &argv);
    }

    opterr = 0;
    optind = 0;

    /*
     * options:
     *       -a, --hostname <network element hostname or address>
     *       -t, --transport <transport type>
     *       -C, --clientcert <client certificate file>
     *       -K, --clientkey <client private key file>
     *       -R, --rootcert <root certificates file>
     *       -P, --pinfile <tls pinning file>
     */
    while (1) {
        c = getopt_long(argc, argv, "-a:t:C:K:R:P:", options, &option_index);
        if (c == -1) break;

        switch (c) {
            case 'a': ne_hostname = optarg;
                      break;
            case 't': transport_type = optarg;
                      break;
            case 'C': client_cert_path = optarg;
                      break;
            case 'K': client_key_path = optarg;
                      break;
            case 'R': root_cert_path = optarg;
                      break;
            case 'P': pin_file = optarg;
                      break;
            default: break;
        }
    }

    if (!ne_hostname) {
        return 1;
    }
    return 0;
}

/**
 * Gets the required options for running this application.
 *
 * @return The required options
 */
char *
get_usage_required_options (void)
{
    return
        "-a <element hostname or address>";
}

/**
 * Gets the optional options for running this application.
 *
 * @return The optional options
 */
char *
get_usage_optional_options (void)
{
    return 
        "[-t <transport type>] [-C <client cert file>] "
        "[-K <client private key file>] [-R <root certificates file>] "
        "[-P <tls pinning file>]";
}

/**
 * Reads pairs of arguments from a file and stores in the filev string array
 * and the number of arguments read in filec.
 *
 * @param [in]  arg0        The null-terminated program name, i.e., argv[0].
 * @param [in]  filename    The path to the file to be read.
 * @param [out] arg_count   The variable that will get the number of arguments
 *                          read from file.
 * @param [out] file_args   The variable that will get the arguments read from
 *                          file.
 */
void read_file(const char *arg0, const char *filename,
               int *arg_count, char ***file_args)
{
    FILE *fp;
    int c;
    int n = 0;
    char arg_buffer[FILE_ARG_SIZE];
    
    /*
     * If no file arguments have been stored, read the file and scan it for
     * arguments.
     */
    if (filec == 0) {
        fp = fopen(filename, "r");
        if (!fp) {
            fprintf(stderr,
                    "The file '%s' could not be read.\n",
                    filename);
            exit(EXIT_FAILURE);
        }

        if (arg0) {
            filev[0] = strdup(arg0);
            if (filev[0]) {
                filec = 1;
            } else {
                fprintf(stderr,
                        "Error in 'strdup()'. "
                        "Error code: %d\n", errno);
                exit(EXIT_FAILURE);
            }
        }

        while (1) {
            c = fgetc(fp);
            if (c != ' ' && c != '\n' && c != EOF) {
                if (filec >= FILEV_SIZE - 1) {
                    fprintf(stderr,
                            "Error: The number of file arguments exceeded the "
                            "allowed limit.\n");
                    exit(EXIT_FAILURE);
                }
                if (n >= FILE_ARG_SIZE) {
                    fprintf(stderr,
                            "Error: One or more file arguments exceeded the "
                            "maximum allowed length.\n");
                    exit(EXIT_FAILURE);
                }
                arg_buffer[n++] = c;
            } else {
                if (n > 0) {
                    arg_buffer[n] = '\0';
                    filev[filec] = strdup(arg_buffer);
                    if (filev[filec]) {
                        filec++;
                    } else {
                        fprintf(stderr,
                                "Error in 'strdup()'. "
                                "Error code: %d\n", errno);
                        exit(EXIT_FAILURE);
                    }
                    n = 0;
                }
                if (c == EOF) {
                    break;
                }
            }
        }

        if (fclose(fp) == EOF) {
            fprintf(stderr,
                    "Error in closing file '%s'. "
                    "Error code: %d\n", filename, errno);
        }
    }

    if (arg_count) {
        *arg_count = filec;
    }
    if (file_args) {
        *file_args = filev;
    }
}

/**
 * Prompts the user to enter a username and password which will be used to
 * authenticate to the network element.
 */
void
prompt_authentication (void)
{
    int n;
    int c;
    char line_buffer[LINE_SIZE];
    struct termios old_term;
    struct termios new_term;
    int should_fail = 0;
    int should_restore_terminal = 0;

    printf("Enter username: ");
    fflush(stdout);
    n = 0;
    while (1) {
        c = fgetc(stdin);
        if (c != '\n' && c != EOF) {
            if (n < ONEP_USERNAME_SIZE - 1) {
                line_buffer[n++] = c;
            } else {
                fprintf(stderr,
                        "\nError: The username entered exceeded the "
                        "maximum allowed length.\n");
                should_fail = 1;
                goto cleanup;
            }
        } else {
            line_buffer[n] = '\0';
            if (!strncpy(username, line_buffer, ONEP_USERNAME_SIZE - 1)) {
                fprintf(stderr,
                        "\nError in 'strncpy()'.\n");
                should_fail = 1;
                goto cleanup;
            }
            if (c == EOF) {
                putc('\n', stdout);
            }
            break;
        }
    }

    /* Turn echoing off or fail. */
    if (tcgetattr(fileno(stdin), &old_term) != 0) {
        fprintf(stderr,
                "Could not get terminal parameters.\n"
                "Error code: %d\n", errno);
        should_fail = 1;
        goto cleanup;
    }
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    if (tcsetattr(fileno(stdin), TCSAFLUSH, &new_term) != 0) {
        fprintf(stderr,
                "Could not set terminal parameters.\n"
                "Error code: %d\n", errno);
        should_fail = 1;
        goto cleanup;
    }
    should_restore_terminal = 1;

    printf("Enter password: ");
    fflush(stdout);
    n = 0;
    while (1) {
        c = fgetc(stdin);
        if (c != '\n' && c != EOF) {
            if (n < ONEP_PASSWORD_SIZE - 1) {
                line_buffer[n++] = c;
            } else {
                fprintf(stderr,
                        "\nError: The password entered exceeded the "
                        "maximum allowed length.\n");
                should_fail = 1;
                goto cleanup;
            }
        } else {
            line_buffer[n] = '\0';
            if (!strncpy(password, line_buffer, ONEP_PASSWORD_SIZE - 1)) {
                fprintf(stderr,
                        "\nError in 'strncpy()'.\n");
                should_fail = 1;
                goto cleanup;
            }
            break;
        }
    }
    putc('\n', stdout);

cleanup:
    /* Zero the line buffer as it holds sensitive information. */
    memset(line_buffer, 0, LINE_SIZE);

    if (should_restore_terminal
        && tcsetattr(fileno(stdin), TCSAFLUSH, &old_term) != 0) {
        fprintf(stderr,
                "Could not restore terminal parameters.\n"
                "Error code: %d\n", errno);
    }

    if (should_fail) {
        exit(EXIT_FAILURE);
    }
}

/**
 * Prompts the user to enter the passphrase to decrypt the client private key
 * for TLS.
 */
void prompt_client_key_passphrase (void)
{
    int n;
    int c;
    char line_buffer[CLIENT_KEY_PASSPHRASE_SIZE];
    struct termios old_term;
    struct termios new_term;
    int should_fail = 0;
    int should_restore_terminal = 0;

    if (!client_key_path) {
        /* No client key was provided.  No need for passphrase. */
        return;
    }

    /* Turn echoing off or fail. */
    if (tcgetattr(fileno(stdin), &old_term) != 0) {
        fprintf(stderr,
                "Could not get terminal parameters.\n"
                "Error code: %d\n", errno);
        should_fail = 1;
        goto cleanup;
    }
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    if (tcsetattr(fileno(stdin), TCSAFLUSH, &new_term) != 0) {
        fprintf(stderr,
                "Could not set terminal parameters.\n"
                "Error code: %d\n", errno);
        should_fail = 1;
        goto cleanup;
    }
    should_restore_terminal = 1;

    printf("Enter client private key passphrase for TLS [none]: ");
    fflush(stdout);
    n = 0;
    while (1) {
        c = fgetc(stdin);
        if (c != '\n' && c != EOF) {
            if (n < CLIENT_KEY_PASSPHRASE_SIZE - 1) {
                line_buffer[n++] = c;
            } else {
                fprintf(stderr,
                        "\nError: The passphrase entered exceeded the "
                        "maximum allowed length.\n");
                should_fail = 1;
                goto cleanup;
            }
        } else {
            line_buffer[n] = '\0';
            if (line_buffer[0] == '\0') {
                free(key_passphrase);
                key_passphrase = NULL;
            } else {
                if (!(key_passphrase = strdup(line_buffer))) {
                    fprintf(stderr,
                            "\nInsufficient memory for 'strdup()'.\n");
                    should_fail = 1;
                    goto cleanup;
                }
            }
            break;
        }
    }
    putc('\n', stdout);

cleanup:
    /* Zero the line buffer as it holds sensitive information. */
    memset(line_buffer, 0, CLIENT_KEY_PASSPHRASE_SIZE);

    if (should_restore_terminal
        && tcsetattr(fileno(stdin), TCSAFLUSH, &old_term) != 0) {
        fprintf(stderr,
                "Could not restore terminal parameters.\n"
                "Error code: %d\n", errno);
    }

    if (should_fail) {
        exit(EXIT_FAILURE);
    }
}

/**
 * Disconnects the application from the network element.
 *
 * @param [in,out] ne  Address to the onep_network_element_t pointer to be destroyed.
 * @param [in,out] session_handle  Address to the onep_session_handle_t pointer
 *                                 to be destroyed as returned from
 *                                 onep_element_connect().
 */
void
disconnect_network_element (onep_network_element_t **ne,
                            onep_session_handle_t **session_handle)
{
    onep_network_application_t* myapp = NULL;
    onep_status_t rc;

    if ((ne) && (*ne)) {
        /* Done with Network Element, disconnect it. */
        rc = onep_element_disconnect(*ne);
        if (rc != ONEP_OK) {
            fprintf(stderr, "\nFailed to disconnect network element:"
                    " errocode = %d, errormsg = %s",
                     rc, onep_strerror(rc));
        }
        /* Free the network element resource on presentation. */
        rc = onep_element_destroy(ne);
        if (rc != ONEP_OK) {
            fprintf(stderr, "\nFailed to destroy network element:"
                    " errocode = %d, errormsg = %s",
                     rc, onep_strerror(rc));
        }
    }
    /* Free the onePK resource on presentation. */
    if (session_handle && *session_handle) {
        rc = onep_session_handle_destroy(session_handle);
        if (rc != ONEP_OK) {
            fprintf(stderr, "\nFailed to destroy session handle:"
                    " errocode = %d, errormsg = %s",
                     rc, onep_strerror(rc));
        }
    }
    /* Gets the singleton instance of onep_network_application_t. */
    rc = onep_application_get_instance(&myapp);
    if (rc != ONEP_OK) {
        fprintf(stderr, "\nFailed to get the instance of the application:"
                " errocode = %d, errormsg = %s",
                 rc, onep_strerror(rc));
    }
    if (myapp) {
        /* Destroys the onep_network_application_t and frees its memory resource. */
        rc = onep_application_destroy(&myapp);
        if (rc != ONEP_OK) {
            fprintf(stderr, "\nFailed to destroy application:"
                    " errocode = %d, errormsg = %s",
                     rc, onep_strerror(rc));
        }
    }
}


/*
 * @brief Callback to the app to determine whether to add a server to the DB
 *
 * @usage
 *
 * Upon receipt of a certificate which could not be verified,
 * this callback asks the application whether to accept the
 * connection and/or whether to add the server to the pinning database. 
 * By default, the connection will be terminated and the pinning db will
 * remain unchanged.
 *
 * @param [in] server_name is a byte string containing either the FQDN or a
 *             text version of the IP address.
 * @param [in] hash_type is a pointer the hash type. If there was a server
 *             name with a non-matching certificate, this will be the hash-type
 *             from that entry. If there was no entry, this will be created
 *             as "SHA-1".
 * @param [in] fingerprint pointer to the text fingerprint created from the 
 *          certificate. This will be a series of hex bytes separated by
 *          colons of the form "A1:B2:C3:..."
 * @param [in] changed is TRUE if there was an existing entry in the database
 *          but the certificate does not match. FALSE indicates that there was
 *          no entry in the database for this server.
 *
 * @retval: ONEP_TLS_PINNING_CB_ACCEPT_AND_PIN if onep should both accept
 *          the connection and add the entry to the pinning database.
 *          ONEP_TLS_PINNING_CB_ACCEPT_ONCE if onep should only accept
 *          the connection but not add the entry to the pinning database.
 *          ONEP_TLS_PINNING_CB_REJECT if onep should neither accept
 *          the connection nor add the entry to the pinning database.
 */
// START SNIPPET: onep_session_pin_handler
onep_tls_pinning_cb_t
accept_handler (const unsigned char *server_name,	
		const unsigned char *hash_type,
		const unsigned char *fingerprint,
		bool changed) {
	
	char decision[10];
	if (changed) {
		printf("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
		printf(" WARNING: THE CERTIFICATE PRESENTED BY REMOTE HOST '%s'\n "
				"IS DIFFERENT FROM THE ONE PREVIOUSLY ACCEPTED ",server_name);
		printf("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	} else {
        printf("WARNING: The certificate presented by the remote host '%s' was not verified.",server_name);
	}
	printf("\n\nThe %s fingerprint sent by the remote host(%s) is:\n%s",
			hash_type, server_name, fingerprint);
	printf("\n\nYou MUST verify the certificate on remote host before proceeding! \n");
	printf("\nChoose from following options:");
	printf("\nAccept and Pin (p), Accept once (o), Reject (r) (default) :");
	while (fgets(decision, sizeof(decision)-1, stdin) > 0) {
	    	if (decision[0] == 'p' || decision[0] == 'P') {
	    	    return ONEP_TLS_PINNING_CB_ACCEPT_AND_PIN;
	    	}
	    	if (decision[0] == 'o' || decision[0] == 'O') {
	    	    return ONEP_TLS_PINNING_CB_ACCEPT_ONCE;
	    	}
	    	if (decision[0] == 'r' || decision[0] == 'r' ||
	    	    decision[0] == '\n' || decision[0] == '\0') {
	    	    return ONEP_TLS_PINNING_CB_REJECT;
	    	}
	    	printf("\nAccept and Pin (p), Accept Once (o), Reject (r) (default) :");
	 }
	 return ONEP_TLS_PINNING_CB_REJECT;
}
// END SNIPPET: onep_session_pin_handler
/**
 * Creates an instance of onep_session_config_t with the given transport mode.
 *
 * @param [in]  mode    Transport type to use for the session.
 * @param [out] config  Address of the pointer to the onep_session_config_t
 *                      to be created.
 *
 * @retval ONEP_OK  In the case of success. Otherwise, a onep_status_t error
 *                  value is returned. Calling onep_strerror() on the return
 *                  value will convert the error number into an error message.
 */
onep_status_t
create_session_config (onep_transport_mode_e mode, onep_session_config_t **config)
{
    onep_status_t rc;
    onep_status_t destroy_rc;
    onep_session_config_t *local_config = NULL;

    /* Create a new onep_session_config_t with the given transport mode. */
    rc = onep_session_config_new(mode, &local_config);
    if (rc != ONEP_OK) {
        fprintf(stderr, "\nFailed to construct session local_config: "
                "errorcode = %d, errormsg = %s",
                rc, onep_strerror(rc));
        return rc;
    }

    /* Set the port to connect to on the network element.
     * The default ports are: ONEP_SESSION_TLS      15002
     *                        ONEP_SESSION_LOCAL    15003
     *
     */
    switch (mode) {
        case ONEP_SESSION_TLS:
            rc = onep_session_config_set_port(local_config, 15002);
            if (rc != ONEP_OK) {
                fprintf(stderr, "\nFailed to set port: "
                        "errorcode = %d, errormsg = %s",
                        rc, onep_strerror(rc));
                goto error_cleanup;
            }
            break;
        case ONEP_SESSION_LOCAL:
        	rc = onep_session_config_set_port(local_config, 15003);
        	if (rc != ONEP_OK) {
        	   fprintf(stderr, "\nFailed to set port: "
        	           "errorcode = %d, errormsg = %s",
        	            rc, onep_strerror(rc));
        	   goto error_cleanup;
        	}
            break;
        default:
            fprintf(stderr, "\nUnknown transport mode: %d", mode);
            break;
    }
    
    

    /* Set the TLS attributes of the session. */
    if (mode == ONEP_SESSION_TLS) {
    	
        rc = onep_session_config_set_tls(
            local_config,       /* Pointer to onep_session_config_t   */
            client_cert_path,   /* Client certificate file path  */
            client_key_path,    /* Client private key file path  */
            key_passphrase,     /* Client private key passphrase */
            root_cert_path);    /* Root certificates file path   */
        if (rc != ONEP_OK) {
            fprintf(stderr, "\nFailed to set TLS: "
                    "errorcode = %d, errormsg = %s",
                    rc, onep_strerror(rc));
            goto error_cleanup;
        }
        
        /* Enable pinning */
         if (pin_file) {
        	 rc = onep_session_config_set_tls_pinning(local_config, pin_file,
            	       								&accept_handler);
            if (rc != ONEP_OK) {
            	fprintf(stderr, "\nFailed to enable TLS pinning: "
            	       	         "errorcode = %d, errormsg = %s",
            	       	                rc, onep_strerror(rc));
            	goto error_cleanup;
            }
         }
            	
    }

    *config = local_config;
    return ONEP_OK;

error_cleanup:
    destroy_rc = onep_session_config_destroy(&local_config);
    if (destroy_rc != ONEP_OK) {
        fprintf(stderr, "\nFailed to destroy session config: "
                "errorcode = %d, errormsg = %s",
                destroy_rc, onep_strerror(destroy_rc));
    }
    return rc;
}

/**
 * Connects the application to a network element.
 *
 * @param [in]  hostname  This is the hostname of the network element.
 * @param [in]  username  Username
 * @param [in]  password  Password
 * @param [in]  app_name  Application Name
 * @param [out] ne        Address to the onep_network_element_t pointer
 *
 * @retval NULL if a connection could not be established. Otherwise, a
 *              onep_session_handle_t pointer is returned.
 */
onep_session_handle_t *
connect_network_element (char* hostname, char *username, char* password,
                         char* app_name, char *transport,
                         onep_network_element_t **ne)
{
    // START SNIPPET: c_variables
    onep_network_application_t* myapp = NULL;
    onep_network_element_t*     local_ne = NULL;
    onep_session_handle_t*      session_handle = NULL;
    onep_status_t          rc;
    onep_transport_mode_e  mode;
    onep_session_config_t*      config = NULL;
    // END SNIPPET: c_variables

    // START SNIPPET: get_instance
    /* Obtain a onep_network_application_t instance. */
    rc = onep_application_get_instance(&myapp);
    if (rc != ONEP_OK) {
       fprintf(stderr, "\nFailed to get network instance:"
                        " errocode = %d, errormsg = %s",
                        rc, onep_strerror(rc));
       return NULL;
    }
    // END SNIPPET: get_instance

    // START SNIPPET: set_app_name
    /* Set the name of the network application. */
    rc = onep_application_set_name(myapp, app_name);
    if (rc != ONEP_OK) {
       fprintf(stderr, "\nFailed to get network application name:"
                        " errocode = %d, errormsg = %s",
                        rc, onep_strerror(rc));
        disconnect_network_element(NULL, NULL);
        return NULL;
    }
    // END SNIPPET: set_app_name

    // START SNIPPET: get_network_element
    /* Get the network element at the given hostname. */
    rc = onep_application_get_network_element_by_name(myapp,
            hostname,
            &local_ne);
    if (rc != ONEP_OK) {
        fprintf(stderr, "\nFailed to get network element:"
                        " errocode = %d, errormsg = %s",
                        rc, onep_strerror(rc));
        disconnect_network_element(NULL, NULL);
        return NULL;
    }
    // END SNIPPET: get_network_element

    // START SNIPPET: connect
    /* Create a session configuration. */
    if (strcasecmp(transport, "tipc") == 0
    	|| strcmp(transport, "2") == 0) { 
        mode = ONEP_SESSION_LOCAL;
    } else {
    	mode = ONEP_SESSION_TLS;
    }
    rc = create_session_config(mode, &config);
    if (rc != ONEP_OK) {
        fprintf(stderr,
            "\ncreate_session_config failed\n\n");
        disconnect_network_element(&local_ne, NULL);
        return NULL;
    }

    /* Connect to the network element. */
    rc = onep_element_connect(
            local_ne, username, password, config, &session_handle);
    if (rc != ONEP_OK) {
        /**
         * Failed to connect to network element.
         */
        fprintf(stderr, "\nFailed to connect to network element:"
                " errocode = %d, errormsg = %s",
                rc, onep_strerror(rc));
        disconnect_network_element(&local_ne, NULL);
        return NULL;
    }
    *ne = local_ne;
    return session_handle;
    // END SNIPPET: connect
}

/**
 * Reads properties from the network element.
 *
 * @param[in] ne  A pointer to the network element structure
 */
void
read_properties (onep_network_element_t* ne)
{
    onep_status_t rc;
    char *description = NULL;
    char *product_id = NULL;
    char *serial_number = NULL;
    onep_element_property_t *property = NULL;

    /*
     * Get network element properties
    */
    rc = onep_element_get_property(ne, &property);
    if (rc != ONEP_OK) {
        fprintf(stderr, "\nFailed to get property of network element:"
                " errocode = %d, errormsg = %s",
                rc, onep_strerror(rc));
        return;
    }

    rc = onep_element_property_get_sys_descr(property, &description);
    if (rc != ONEP_OK) {
        fprintf(stderr, "\nFailed to get property system description:"
                " errorcode = %d, errormsg = %s",
                rc, onep_strerror(rc));
        goto cleanup;
    }

    rc = onep_element_property_get_product_id(property, &product_id);
    if (rc != ONEP_OK) {
        fprintf(stderr, "\nFailed to get property product ID:"
                " errorcode = %d, errormsg = %s",
                rc, onep_strerror(rc));
        goto cleanup;
    }

    rc = onep_element_property_get_serial_no(property, &serial_number);
    if (rc != ONEP_OK) {
        fprintf(stderr, "\nFailed to get property serial no.:"
                " errorcode = %d, errormsg = %s",
                rc, onep_strerror(rc));
        goto cleanup;
    }

    fprintf(stderr, "\n----- SysDescr  %s -----"
                    "\n----- ProductId %s -----"
                    "\n----- Serial No %s -----",
                    description, product_id, serial_number);

cleanup:
    rc = onep_element_property_destroy(&property);
    if (rc != ONEP_OK) {
        fprintf(stderr, "\nFailed to destroy element property:"
                " errorcode = %d, errormsg = %s",
                rc, onep_strerror(rc));
    }
    free(description);
    free(product_id);
    free(serial_number);
}
