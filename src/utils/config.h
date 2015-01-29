#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

typedef struct config {
	TConfigDbInfo* database;
	int application_id;
} TConfig;

TConfig* config;

TConfig* parse_config(char*);
int string_cpy(char**, char*);

#endif