#include "common_mysql.h"

MYSQL* comm_con = NULL;

TCommMysqlStatus comm_mysql_connect()
{
    if(comm_con != NULL)
    {
        return COMM_MYSQL_OK;
    }

    comm_con = mysql_init(NULL);

    // Connect to MySQL
    if(mysql_real_connect(comm_con, config->database->hostname, config->database->username,
                        config->database->password, config->database->results, 0, NULL, 0
                        ) == NULL)
    {
        fprintf(stderr, "Cannot connect to MySQL (%s).\n", config->database->schema);
        return COMM_MYSQL_ERROR;
    }

    return COMM_MYSQL_OK;
}

MYSQL* comm_mysql_get_connection()
{
    return comm_con;
}