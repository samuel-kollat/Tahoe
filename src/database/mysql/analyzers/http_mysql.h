#ifndef __DB_MYSQL_DNS__
#define __DB_MYSQL_DNS__

#include <my_global.h>
#include <mysql.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common_mysql.h"
#include "../../../processing/modules/http/http_statistics.h"

bool mysql_save_http_data(
    THttpStats* data_item
);

#endif