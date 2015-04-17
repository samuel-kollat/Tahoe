#ifndef __TAHOE_BACKEND_API__
#define __TAHOE_BACKEND_API__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "acl.h"
#include "action.h"
#include "class_map.h"
#include "policy_map.h"

#include "onep_core_services.h"

#include "../utils/router.h"
#include "session_element_util.h"

#define NONDEF (-1)

typedef onep_dpss_pak_callback_t TApiCallback;

// Return codes of API
typedef enum {
    API_OK,
    API_ERROR
} TApiStatus;

typedef enum {
    SRC,
    DST
} TIPAddressType;

// Indentifier of L7 protocol for NBAR configuration
typedef enum {
    NONE,
    HTTP,
    DNS,
    DHCP,
    CIFS,
    RTP,
    RTCP,
    SIP
} TL7Protocol;

// Indentifier of L3 protocol
typedef enum {
    ALL,
    ICMP,
    IGMP,
    TCP,
    UDP
} TL3Protocol;

// Data for class map entry
typedef struct {
    char* src_ip;               // Source IP address
    int src_mask;               // Source IP address mask
    char* dst_ip;               // Destination IP address
    int dst_mask;               // Destination IP address mask
    int src_port;               // Source port
    int dst_port;               // Destination port
    onep_acl_protocol_e l3_protocol;    // L3 protocol
    TL7Protocol protocol;       // Protocol
    bool default_filter;        // Default filter settings
} TFilterData;

// Item in list of filtering rules
typedef struct FilterItem {
    TFilterData* data;
    struct FilterItem* next;
} TFilterItem;

// List of filtering rules
// Rules are bound by logical OR
typedef struct {
    TFilterItem* head;
    int count;
    onep_policy_pmap_handle_t pmap_handle;
    onep_dpss_pak_callback_t callback;
} TFilterList;

// Item in list of interfaces
typedef struct InterfaceItem {
    onep_network_interface_t* interface;
    struct InterfaceItem* next;
} TInterfaceItem;

// Network element structure
typedef struct
{
    onep_session_handle_t* sh;
    char* hostname;
    char* login;
    char* password;
    char* url;
    char* transport_type;
    onep_network_element_t* ne;
    onep_collection_t* interfaces;
    TInterfaceItem* interface_list;     // Head of list
    onep_policy_op_list_t* target_op_list;
} TNetworkElement;

// Global list of filters
TFilterList FilterList;

// Global ACE number
extern int ACEIdNumber;

//
void PrintErrorMessage(
        char* dst,              // Identifier of procedure
        char* msg               // Error message for user
    );

// Public
TApiStatus InitializeFilters(
    );

// Public
TApiStatus GetEmptyFilter(
        TFilterData** filter    // Placeholder for filter reference
    );

//
TApiStatus InsertToList(
        TFilterData* filter     // Filter to insert
    );

// Public
TApiStatus AddIPv4ToFilter(
        TFilterData* filter,        // Target filter
        TIPAddressType addr_type,   // Type of address in flow
        char* ip_addr,              // IP address
        int ip_mask                 // IP mask (0-32)
    );

// Public
TApiStatus AddPortToFilter(
        TFilterData* filter,        // Target filter
        TIPAddressType addr_type,   // Type of port in flow
        int port                    // Port (0-65535)
    );

// Public
TApiStatus AddL7ProtocolToFilter(
        TFilterData* filter,        // Target filter
        TL7Protocol protocol        // Type of protocol
    );

// Public
TApiStatus AddL3ProtocolToFilter(
        TFilterData* filter,        // Target filter
        TL3Protocol protocol        // Type of protocol
    );

// Public
TApiStatus AddDefaultFilter(
        TFilterData* filter         // Target filter
    );

// Public
TApiStatus SetCallbackToFilters(
        TApiCallback callback
    );

// Public
TApiStatus DeployFiltersToElement(
        TNetworkElement* element
    );

// Public
TApiStatus InitializeNetworkElement(
        char* hostname,
        char* login,
        char* password,
        char* url,
        char* transport_type,
        TNetworkElement** element
    );

// Public
TApiStatus ConnectToNetworkElement(
        TNetworkElement* element
    );

// Public
TApiStatus SetInterfaceOnNetworkElement(
        TNetworkElement* element,
        char* interface
    );

TApiStatus GetInterfacesOnNetworkElement(
        TNetworkElement* element
    );

//
TApiStatus GenerateFilters(
        TNetworkElement* element
    );

//
TApiStatus GenerateALC(
        TNetworkElement* element,
        TFilterData* data,
        onep_acl_t** acl
    );

//
TApiStatus L7ProtocolToString(
        TL7Protocol protocol,
        char** value
    );

#endif