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
    FilterList.count++;
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

TApiStatus SetCallbackToFilters(TApiCallback callback)
{
    FilterList.callback = (onep_dpss_pak_callback_t)callback;
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

TApiStatus GenerateFilters(TNetworkElement* element)
{
    TApiStatus s;
    onep_status_t rc;
    onep_collection_t* tables = NULL;
    onep_policy_table_cap_t* table_cap = 0;
    onep_policy_pmap_op_t* pmap_op = NULL;
    onep_policy_op_list_t* pmap_op_list = NULL;
    onep_policy_op_list_t* cmap_op_list = NULL;

    // Get traffic action table
    rc = router_get_table(element->ne, &tables, &table_cap);
    if(rc != ONEP_OK) {
        PrintErrorMessage("GenerateFilters", "action table");
        return API_ERROR;
    }

    // Init policy map
    policy_map_begin(
        element->ne,
        table_cap,
        &pmap_op_list,
        &pmap_op
    );

    // Create class map for every filter item
    unsigned entry_number = 100;
    TFilterItem* filter = FilterList.head;
    while(filter != NULL)
    {
        TFilterData* data = filter->data;

        onep_policy_entry_op_t *entry_op;

        // Add entry to policy map
        policy_map_add_entry(
            table_cap,
            pmap_op,
            entry_number,
            &entry_op
        );
        entry_number++;

        // Add rules
        onep_policy_op_list_t *cmap_op_list = NULL;
        onep_policy_cmap_op_t *cmap_op = NULL;
        onep_policy_match_holder_t *mh = NULL;

        // Begin class map
        class_map_begin(
            element->ne,
            table_cap,
            ONEP_POLICY_CMAP_ATTR_MATCH_ALL,
            entry_op,
            "onep-tahoe-cmap-1",                        // TODO
            &cmap_op_list,
            &cmap_op,
            &mh
        );

        // Add ACL
        onep_acl_t* acl = NULL;
        s = GenerateALC(data, &acl);
        if(s != API_OK)
        {
            PrintErrorMessage("GenerateFilters", "ACL");
            return API_ERROR;
        }

        class_map_add_acl(
            mh,
            (onep_policy_access_list_t *)acl
        );

        // L7 protocol
        char* proto_str = NULL;
        s = L7ProtocolToString(data->protocol, &proto_str);
        if(s != API_OK)
        {
            PrintErrorMessage("GenerateFilters", "protocol string");
            return API_ERROR;
        }

        class_map_add_l7_protocol(
            mh,
            proto_str
        );

        // Class map finish
        class_map_finish(
            table_cap,
            cmap_op_list,
            cmap_op,
            &entry_op
        );

        // Add action
        action_add(
            entry_op,
            ONEP_DPSS_ACTION_COPY,
            FilterList.callback
        );

        filter = filter->next;
    }

    // Try to set policy map persistent with name
    policy_map_try_set_persistent(
        table_cap,
        pmap_op,
        "onep-tahoe-pmap"
    );

    // Finish policy map
    policy_map_finish(
        pmap_op,
        pmap_op_list,
        &(FilterList.pmap_handle)
    );

    // Clean up
    if(cmap_op_list) {
        rc = onep_policy_op_list_destroy(&cmap_op_list);
        if(rc != ONEP_OK) {
            // Warning only
            PrintErrorMessage("GenerateFilters", "Destroy: cmap_op_list");
        }
    }
    if(pmap_op_list) {
        rc = onep_policy_op_list_destroy(&pmap_op_list);
        if(rc != ONEP_OK) {
            // Warning only
            PrintErrorMessage("GenerateFilters", "Destroy: cmap_op_list");
        }
    }

    return API_OK;
}

TApiStatus GenerateALC(TFilterData* data, onep_acl_t** acl)
{
    *acl = NULL;
    return API_OK;
}

TApiStatus L7ProtocolToString(TL7Protocol protocol, char** value)
{
    *value = "";
    TApiStatus s = API_OK;

    switch(protocol)
    {
        case HTTP:
            *value = "http";
            break;
        case DNS:
            *value = "dns";
            break;
        case DHCP:
            *value = "dhcp";
            break;
        case CIFS:
            *value = "cifs";
            break;
        case RTP:
            *value = "rtp";
            break;
        case RTCP:
            *value = "rtcp";
            break;
        default:
            *value = "";
            s = API_ERROR;
            break;
    }

    return s;
}