#include "api.h"

void PrintErrorMessage(char* dst, char* msg)
{
    fprintf(stderr, "Error in API (%s): %s", dst, msg);
}

//
TApiStatus InitializeFilters()
{
    FilterList.head = NULL;
    FilterList.count = 0;
    FilterList.pmap_handle = 0;
    FilterList.callback = NULL;
    return API_OK;
}

//
TApiStatus GetEmptyFilter(TFilterData** filter)
{
    *filter = (TFilterData*)(malloc(sizeof(TFilterData)));
    if(*filter == NULL)
    {
        PrintErrorMessage("GetEmptyFilter", "malloc");
        return API_ERROR;
    }

    (*filter)->src_ip = NULL;
    (*filter)->src_mask = NONDEF;
    (*filter)->dst_ip = NULL;
    (*filter)->dst_mask = NONDEF;
    (*filter)->src_port = NONDEF;
    (*filter)->dst_port = NONDEF;
    (*filter)->protocol = NONE;

    return InsertToList(*filter);
}

TApiStatus InsertToList(TFilterData* filter)
{
    TFilterItem* item = (TFilterItem*)(malloc(sizeof(TFilterItem)));
    if(item == NULL)
    {
        PrintErrorMessage("InsertToList", "malloc");
        return API_ERROR;
    }

    TFilterItem* old_head = FilterList.head;

    item->data = filter;
    item->next = old_head;

    FilterList.head = item;
    return API_OK;
}

TApiStatus AddIPv4ToFilter(TFilterData* filter,
    TIPAddressType addr_type, char* ip_addr, int mask)
{
    // Convert IPv4 string address to struct
    if(strlen(ip_addr) >= INET_ADDRSTRLEN)
    {
       PrintErrorMessage("AddIPv4ToFilter", "IP address is too long");
       return API_ERROR;
    }
    struct sockaddr_in* sa = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
    if(sa == NULL)
    {
        PrintErrorMessage("AddIPv4ToFilter", "malloc");
        return API_ERROR;
    }
    inet_pton(AF_INET, ip_addr, &(sa->sin_addr));

    // Check mask
    if(mask < 0 || mask > 32)
    {
       PrintErrorMessage("AddIPv4ToFilter", "Mask is out of {0,1,...,32}");
       return API_ERROR;
    }

    // Save to data structure
    switch(addr_type)
    {
        case SRC:
           filter->src_ip = (struct sockaddr*)sa;
           filter->src_mask = mask;
           break;
        case DST:
           filter->dst_ip = (struct sockaddr*)sa;
           filter->dst_mask = mask;
           break;
        default:
            PrintErrorMessage("AddIPv4ToFilter", "Wrong address type");
            return API_ERROR;
    }

    return API_OK;
}

TApiStatus AddPortToFilter(TFilterData* filter,
    TIPAddressType addr_type, int port)
{
    // Check port
    if(port < 0 || port > 65535)
    {
       PrintErrorMessage("AddPortToFilter", "Port is out of {0,1,...,65535}");
       return API_ERROR;
    }

    // Save to data structure
    switch(addr_type)
    {
        case SRC:
           filter->src_port = port;
           break;
        case DST:
           filter->dst_port = port;
           break;
        default:
            PrintErrorMessage("AddPortToFilter", "Wrong port type");
            return API_ERROR;
    }

    return API_OK;
}

TApiStatus AddL7ProtocolToFilter(TFilterData* filter,
    TL7Protocol protocol)
{
    filter->protocol = protocol;
    return API_OK;
}

TApiStatus SetCallbackToFilters(onep_dpss_pak_callback_t callback)
{
    FilterList.callback = callback;
    return API_OK;
}

TApiStatus DeployFiltersToElement(TNetworkElement* element)
{
    onep_status_t rc;

    // Create filtering rules
    // TODO

    // Create operation list and set it to interface
    rc = onep_policy_target_op_list_new(&(element->target_op_list));
    if(rc != ONEP_OK) {
        PrintErrorMessage("DeployFiltersToElement", onep_strerror(rc));
        return API_ERROR;
    }

    rc = onep_policy_op_add_network_element(element->target_op_list, element->ne);
    if(rc != ONEP_OK) {
        PrintErrorMessage("DeployFiltersToElement", onep_strerror(rc));
        return API_ERROR;
    }

    // Bind policy to interfaces
    TInterfaceItem* next = element->interface_list;
    while(next != NULL)
    {
        onep_policy_target_op_t *target_op = NULL;

        rc = onep_policy_target_op_activate(element->target_op_list, &target_op);
        if(rc != ONEP_OK) {
            PrintErrorMessage("DeployFiltersToElement", onep_strerror(rc));
            return API_ERROR;
        }
        rc = onep_policy_target_op_add_pmap(target_op, FilterList.pmap_handle);
        if(rc != ONEP_OK) {
            PrintErrorMessage("DeployFiltersToElement", onep_strerror(rc));
            return API_ERROR;
        }

        rc = onep_policy_target_op_add_interface(target_op, next->interface);
        if(rc != ONEP_OK) {
            PrintErrorMessage("DeployFiltersToElement", onep_strerror(rc));
            return API_ERROR;
        }

        // direction of packets
        rc = onep_policy_target_op_set_direction(target_op, ONEP_DIRECTION_IN);
        if(rc != ONEP_OK) {
            PrintErrorMessage("DeployFiltersToElement", onep_strerror(rc));
            return API_ERROR;
        }
    }

    // Update policy on router
    rc = onep_policy_op_update(element->target_op_list);
    if(rc != ONEP_OK) {
        PrintErrorMessage("DeployFiltersToElement", onep_strerror(rc));
        return API_ERROR;
    }

    return API_OK;
}

TApiStatus InitializeNetworkElement(char* hostname, char* login,
    char* password, char* url, char* transport_type,
    TNetworkElement** element)
{
    *element = (TNetworkElement*)(malloc(sizeof(TNetworkElement)));
    if(*element == NULL)
    {
        PrintErrorMessage("InitializeNetworkElement", "malloc");
        return API_ERROR;
    }

    (*element)->sh = NULL;
    (*element)->hostname = hostname;
    (*element)->login = login;
    (*element)->password = password;
    (*element)->url = url;              // TODO: if NULL generate unique
    (*element)->transport_type = transport_type;
    (*element)->ne = NULL;
    (*element)->interfaces = NULL;
    (*element)->interface_list = NULL;
    (*element)->target_op_list = NULL;

    return API_OK;
}

TApiStatus ConnectToNetworkElement(TNetworkElement* element)
{
    element->sh = connect_network_element(
               element->hostname,
               element->login,
               element->password,
               element->url,
               element->transport_type,
               &(element->ne)
               );

    if(!element->sh)
    {
        PrintErrorMessage("ConnectToNetworkElement", "connect");
        return API_ERROR;
    }

    return API_OK;
}

TApiStatus SetInterfaceOnNetworkElement(TNetworkElement* element,
    char* interface)
{
    onep_status_t rc;

    // Discover active interfaces if needed
    if(element->interfaces == NULL)
    {
        TApiStatus s = GetInterfacesOnNetworkElement(element);
        if(s != API_OK)
        {
            PrintErrorMessage("SetInterfaceOnNetworkElement", "get interfaces");
            return API_ERROR;
        }
    }

    // Set interface
    TInterfaceItem* intf_item = (TInterfaceItem*)(malloc(sizeof(TInterfaceItem)));
    rc = onep_element_get_interface_by_name(element->ne, interface, &(intf_item->interface));
    if (rc != ONEP_OK) {
        PrintErrorMessage("SetInterfaceOnNetworkElement", onep_strerror(rc));
        return API_ERROR;
    }

    // Add it to list
    intf_item->next = element->interface_list;
    element->interface_list = intf_item;

    return API_OK;
}

TApiStatus GetInterfacesOnNetworkElement(TNetworkElement* element)
{
    onep_status_t rc;
    unsigned count = 0;
    onep_interface_filter_t* intf_filter = NULL;

    rc = onep_interface_filter_new(&intf_filter);
    if (rc != ONEP_OK)
    {
        PrintErrorMessage("GetInterfacesOnNetworkElement", onep_strerror(rc));
        return API_ERROR;
    }
    rc = onep_element_get_interface_list(element->ne, intf_filter, &(element->interfaces));
    if (rc != ONEP_OK)
    {
        PrintErrorMessage("GetInterfacesOnNetworkElement", onep_strerror(rc));
        return API_ERROR;
    }
    rc = onep_collection_get_size(element->interfaces, &count);
    if (rc != ONEP_OK)
    {
        PrintErrorMessage("GetInterfacesOnNetworkElement", onep_strerror(rc));
        return API_ERROR;
    }
    if (count <= 0)
    {
        PrintErrorMessage("GetInterfacesOnNetworkElement", "no interfaces available");
        return API_ERROR;
    }

    if(intf_filter)
    {
        rc = onep_interface_filter_destroy(&intf_filter);
        if(rc != ONEP_OK)
        {
            // Only warning
            PrintErrorMessage("GetInterfacesOnNetworkElement", "Destroy: interface filter");
        }
    }

    return API_OK;
}