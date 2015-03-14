#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../database/db_scheme.h"

typedef enum {
	DB_MYSQL
} TDbType;

typedef struct dbinfo {
	TDbType type;
	char* hostname;
	char* username;
	char* password;
	char* schema;
} TConfigDbInfo;


/*typedef struct dpinfo {
	char* username;
	char* password;
	char* ip;
	char* interface;
	char* local_cert;
	char* remote_cert;
} TConfigDpInfo;*/

typedef struct config {
	TConfigDbInfo* database;
	//TConfigDpInfo* datapath;
	int application_id;
	TMApplication* application;
} TConfig;

TConfig* config;

TConfig* parse_config(char*);
int string_cpy(char**, char*);
void set_appl(TMApplication* app);
char* get_config_value(char* config_name);

#endif