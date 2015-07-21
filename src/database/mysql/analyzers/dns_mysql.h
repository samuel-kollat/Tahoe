#ifndef __DB_MYSQL_DNS__
#define __DB_MYSQL_DNS__

#include <my_global.h>
#include <mysql.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common_mysql.h"
#include "../../../processing/modules/dns/dns_resolutions.h"

bool mysql_save_dns_data(
    TResolutionItem* data_item
);

#endif