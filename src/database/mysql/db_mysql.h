#include <my_global.h>
#include <mysql.h>
#include "../db_scheme.h"

#define QUERY_BUFFER_SIZE 512	// Maximum size of SQL query in chars

//
//
void print_version();
TMApplication* get_application_mysql(int);	
int init_database();	
