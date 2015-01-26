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