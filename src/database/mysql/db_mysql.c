#include "db_mysql.h"

//
void print_version()
{
    printf("MySQL client version: %s\n", mysql_get_client_info());
}