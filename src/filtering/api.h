#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "acl.h"
#include "action.h"
#include "class_map.h"
#include "policy_map.h"

#define NONDEF -1;

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
    RTCP
} TL7Protocol;

// Data for class map entry
typedef struct {
    struct sockaddr* src_ip;    // Source IP address
    int src_mask;               // Source IP address mask
    struct sockaddr* dst_ip;    // Destination IP address
    int dst_mask;               // Destination IP address mask
    int src_port;               // Source port
    int dst_port;               // Destination port
    TL7Protocol protocol;       // Protocol
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
} TFilterList;

// Global list of filters
TFilterList FilterList;

void PrintErrorMessage(
        char* dst,              // Identifier of procedure
        char* msg               // Error message for user
    );

//
TApiStatus InitializeFilters(
    );

//
TApiStatus GetEmptyFilter(
        TFilterData** filter    // Placeholder for filter reference
    );

//
TApiStatus InsertToList(
        TFilterData* filter     // Filter to insert
    );

//
TApiStatus AddIPv4ToFilter(
        TFilterData* filter,        // Target filter
        TIPAddressType addr_type,   // Type of address in flow
        char* ip_addr,              // IP address
        int ip_mask                 // IP mask (0-32)
    );

//
TApiStatus AddPortToFilter(
        TFilterData* filter,        // Target filter
        TIPAddressType addr_type,   // Type of port in flow
        int port                    // Port (0-65535)
    );

//
TApiStatus AddL7ProtocolToFilter(
        TFilterData* filter,        // Target filter
        TL7Protocol protocol        // Type of protocol
    );

TApiStatus DeployFiltersToElement(
        // TODO
    );