#include "dns_mysql.h"

bool mysql_save_dns_data(TResolutionItem* data_item)
{
    if(comm_mysql_connect() != COMM_MYSQL_OK)
    {
        fprintf(stderr, "[DNS] Could not connect to DB\n");
        return false;
    }

    MYSQL* con = comm_mysql_get_connection();

    char* str_src_ip;
    char* str_dst_ip;
    ip_to_str(data_item->resolution.query.src_ip, &str_src_ip);
    ip_to_str(data_item->resolution.query.dst_ip, &str_dst_ip);

    char query[COMM_MYSQL_QUERY_SIZE];
    sprintf(query, " \
        INSERT INTO DnsAnalyzerDatas \
        (SrcIP, DstIp, SrcPort, DstPort, DomainName) \
        VALUES \
        (%s, %s, %u, %u, %s)",
        str_src_ip, str_dst_ip,
        data_item->resolution.query.src_port, data_item->resolution.query.dst_port,
        data_item->resolution.query.domain);

    mysql_query(con, query);

    return true;
}