#ifndef __DB_MYSQL_COMMON__
#define __DB_MYSQL_COMMON__

#include <my_global.h>
#include <mysql.h>
#include "../../../utils/config.h"

#define COMM_MYSQL_QUERY_SIZE 2048

typedef enum {
    COMM_MYSQL_OK,
    COMM_MYSQL_WARNING,
    COMM_MYSQL_ERROR
} TCommMysqlStatus;

TCommMysqlStatus comm_mysql_connect();
MYSQL* comm_mysql_get_connection();

#endif
