#include "config.h"

int string_cpy(char** destination, char* source)
{
	if(source == NULL)
	{
		*destination = NULL;
		return 1;
	}


	*destination = (char*) malloc(strlen(source) * sizeof(char));
	if(destination==NULL)
		return 1;
	strcpy(*destination, source);
	return 0;
}

TConfig* parse_config(char* config_filename)
{

	FILE* config_fd = fopen(config_filename, "r");
	if(config_fd==NULL)
		exit(EXIT_FAILURE);

	size_t cflen;
	ssize_t cfread;
	char* line = NULL;
	unsigned int state = 0;

	config = malloc(sizeof(TConfig));
	if(config==NULL)
		exit(EXIT_FAILURE);

	while((cfread = getline(&line, &cflen, config_fd)) != -1)
	{
		// skip empty lines
		if(strlen(line)<3)
			continue;
		// remove last new-line character
		line[strlen(line)-1] = 0;

		if(line[0]=='[')
			state = 0;
		
		if(strcmp(line, "[DATABASE]")==0)
		{
			state = 1;	// change state to database section
			config->database = malloc(sizeof(TConfigDbInfo));
			if(config->database==NULL)
				exit(EXIT_FAILURE);
		}
		else if(strcmp(line, "[APPLICATION]")==0)
		{
			state = 2;	// change state to application section
		}
		/*else if(strcmp(line, "[DATAPATH]")==0)
		{
			state = 3;	// change state to datapath section
			config->datapath = malloc(sizeof(TConfigDpInfo));
			if(config->datapath==NULL)
				exit(EXIT_FAILURE);
		}*/
		// [DATABASE]
		else if(state==1)
		{
			char* left = strtok(line, "=");
			char* right = strtok(NULL, "=");
			if(strcmp(left,"type")==0)
			{
				if(strcmp(right,"mysql")==0)
				{
					config->database->type = DB_MYSQL;
				} else {
					fprintf(stderr, "Unknown type of database \"%s\"\n.", right);
					exit(EXIT_FAILURE);
				}
			}
			else if(strcmp(left,"hostname")==0)
			{
				string_cpy(&(config->database->hostname), right);
			}
			else if(strcmp(left,"username")==0)
			{
				string_cpy(&(config->database->username), right);
			}
			else if(strcmp(left,"password")==0)
			{
				string_cpy(&(config->database->password), right);
			}
			else if(strcmp(left,"schema")==0)
			{
				string_cpy(&(config->database->schema), right);
			}
		}
		// [APPLICATION]
		else if(state==2)
		{
			char* left = strtok(line, "=");
			char* right = strtok(NULL, "=");
			if(strcmp(left,"id")==0)
			{
				config->application_id = atoi(right);
			}
		}
		/*
		// [DATAPATH]
		else if(state==3)
		{
			char* left = strtok(line, "=");
			char* right = strtok(NULL, "=");
			if(strcmp(left,"username")==0)
			{
				string_cpy(&(config->datapath->username), right);
			}
			else if(strcmp(left,"password")==0)
			{
				string_cpy(&(config->datapath->password), right);
			}
			else if(strcmp(left,"ip")==0)
			{
				string_cpy(&(config->datapath->ip), right);
			}
			else if(strcmp(left,"interface")==0)
			{
				string_cpy(&(config->datapath->interface), right);
			}
			else if(strcmp(left,"local_cert")==0)
			{
				string_cpy(&(config->datapath->local_cert), right);
			}
			else if(strcmp(left,"remote_cert")==0)
			{
				string_cpy(&(config->datapath->remote_cert), right);
			}
		}*/ else {

		}
	}
}