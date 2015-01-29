#include "db_mysql.h"
#include "../../utils/config.h";

MYSQL *con = NULL;

int init_database()
{
	con = mysql_init(NULL);
	// connect to MySQL
	if(mysql_real_connect(	con, config->database->hostname, config->database->username, 
							config->database->password, config->database->schema, 0, NULL, 0
						 )==NULL)
	{
		fprintf(stderr, "Cannot connect to database MySQL.\n");
		return 0;
	}

	return 1;
}

//
void print_version()
{
    printf("MySQL client version: %s\n", mysql_get_client_info());
}

TMApplication* get_application_mysql(int application_id)
{
	int retc;
	if(con==NULL)
		if((retc=init_database())==0)
			return retc;
	
	char query_buffer[QUERY_BUFFER_SIZE];
	sprintf(query_buffer, " \
		SELECT application.id, application.name, application.certificate_id, application.analyzer_id, \
			   analyzer.name, analyzer.description, analyzer.src, \
			   certificate.name, certificate.data \
			FROM application \
		LEFT JOIN certificate \
			ON certificate.id = application.certificate_id \
		LEFT JOIN analyzer \
			ON analyzer.id = application.analyzer_id \
		WHERE application.id='%d' \
		LIMIT 1;", application_id);
	mysql_query(con, query_buffer);

	MYSQL_RES* result = mysql_store_result(con);
	printf("num-rows: %d\n", mysql_num_rows(result));

	if(mysql_num_rows(result)==0)
		return NULL;

	TMApplication* application = (TMApplication*)malloc(sizeof(TMApplication));
	if(application==NULL)
		return NULL;

	MYSQL_ROW* row = mysql_fetch_row(result);

	application->id = atoi(row[0]);
	string_cpy(&(application->name), row[1]);
	application->certificate = (TMCertificate*)malloc(sizeof(TMCertificate));
	if(application->certificate==NULL)
		return NULL;
	application->certificate->id = atoi(row[2]);
	string_cpy(&(application->certificate->name), row[7]);
	string_cpy(&(application->certificate->data), row[8]);

	application->analyzer = (TMAnalyzer*)malloc(sizeof(TMAnalyzer));
	if(application->analyzer==NULL)
		return NULL;
	application->analyzer->id = atoi(row[3]);

	return (TMApplication*) application;
	
	//return NULL;
}

TMFilter* get_application_filters(int application_id)
{
	int retc;
	TMFilter* return_filter = NULL;
	if(con==NULL)
		if((retc=init_database())==0)
			return retc;

	char query_buffer[QUERY_BUFFER_SIZE];
	sprintf(query_buffer, " \
		SELECT filter.id, filter.name \
		FROM filter \
		WHERE filter.application_id='%d'; \
		", application_id);
	mysql_query(con, query_buffer);
	MYSQL_RES* result = mysql_store_result(con);
	printf("num-rows: %d\n", mysql_num_rows(result));

	if(mysql_num_rows(result)==0)
		return NULL;	

	MYSQL_ROW* row;
	TMFilter* filter;
	while((row = mysql_fetch_row(result)))
	{
		TMFilter* last_filter = filter;
		filter = (TMFilter*)malloc(sizeof(TMFilter));
		if(filter==NULL)
			return NULL;
		if(return_filter==NULL)
			return_filter = filter;
		else
			filter->next = filter;
		filter->id = atoi(row[0]);
		string_cpy(filter->name, row[1]);
	}

	return (TMFilter*)return_filter;
}