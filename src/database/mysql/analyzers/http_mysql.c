#include "http_mysql.h"

bool mysql_save_http_data(THttpStats* data_item)
{
    if(comm_mysql_connect() != COMM_MYSQL_OK)
    {
        fprintf(stderr, "[HTTP] Could not connect to DB\n");
        return false;
    }

    MYSQL* con = comm_mysql_get_connection();

    char* str_src_ip;
    char* str_dst_ip;
    ip_to_str(data_item->source_ip, &str_src_ip);
    ip_to_str(data_item->destination_ip, &str_dst_ip);

    char query[COMM_MYSQL_QUERY_SIZE];

    sprintf(query, " \
        SELECT * FROM HttpAnalyzerDatas \
        WHERE SourceIp = \'%s\' AND DestinationIp = \'%s\' AND Method = %d",
        str_src_ip, str_dst_ip, data_item->method);
    mysql_query(con, query);
    MYSQL_RES* result = mysql_store_result(con);

    if(mysql_num_rows(result) > 0)
    {
        sprintf(query, " \
            UPDATE HttpAnalyzerDatas \
            SET Quantity=%u \
            WHERE SourceIp = \'%s\' AND DestinationIp = \'%s\' AND Method = %d",
            data_item->quantity,
            str_src_ip, str_dst_ip, data_item->method);
        mysql_query(con, query);
    }
    else
    {
        sprintf(query, " \
            INSERT INTO HttpAnalyzerDatas \
            (SourceIp, DestinationIp, Method, Quantity) \
            VALUES \
            (%s, %s, %u, %u)",
            str_src_ip, str_dst_ip,
            data_item->method, data_item->quantity);
        mysql_query(con, query);
    }

    return true;
}