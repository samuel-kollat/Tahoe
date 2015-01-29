#include "db_wrapper.h"


void print_db_version()
{
    print_version();
}

TMApplication* get_application(int application_id)
{
	return get_application_mysql(application_id);
}

