#include "dns_mysql.h"

bool mysql_save_dns_data(TResolutionItem* data_item)
{
    printf("Saving to MySQL ...\n");

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
        INSERT INTO DnsAnalyzerDatas (SrcIP, DstIp, SrcPort, DstPort, DomainName) VALUES (\'%s\', \'%s\', \'%u\', \'%u\', \'%s\')",
        str_src_ip, str_dst_ip,
        data_item->resolution.query.src_port, data_item->resolution.query.dst_port,
        data_item->resolution.query.domain);

    printf("Query: %s\n", query);

    unsigned mysql_res = mysql_query(con, query);
    if(mysql_res != 0)
    {
        printf("Error: writing data to database: %u\n", mysql_res);
    }
    else
    {
        printf("Data stored.\n");
    }

    unsigned long last_id = mysql_insert_id(con);

    // Resolution
    if(data_item->resolution.response.data != NULL)
    {
        int i = 0;
        while(data_item->resolution.response.data[i] != NULL)
        {
            char* str;
            ip_to_str(data_item->resolution.response.data[i], &str);
            sprintf(query, " \
                INSERT INTO DnsResponseAddresses (IpAddress, DnsAnalyzerDataId) VALUES (\'%s\', \'%u\')",
                str, last_id);
            i++;

            unsigned mysql_res = mysql_query(con, query);
            if(mysql_res != 0)
            {
                printf("Error: writing data to database: %u\n", mysql_res);
            }
            else
            {
                printf("Data stored.\n");
            }
        }
    }

    return true;
}