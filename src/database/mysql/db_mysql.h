#include <my_global.h>
#include <mysql.h>
#include "../db_scheme.h"

#define QUERY_BUFFER_SIZE 2048	// Maximum size of SQL query in chars

//
//
void print_version();
TMApplication* get_application_mysql(int);	
TMFilter* get_application_filters(int);
TMAccess_list* get_filter_access_lists(int);
TMNbar_protocol* get_filter_nbar_protocols(int);
TMRouter* get_application_routers(int);
int init_database();	
