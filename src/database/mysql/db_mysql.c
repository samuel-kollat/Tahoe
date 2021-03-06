/* * * * * * * * * * * * * * * * * * * * *
 *              O n e M o n              *
 *                                       *
 * File: db_mysql.c                      *
 *                                       *
 * * * * * * * * * * * * * * * * * * * * */


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
		SELECT Applications.id, Applications.name, Applications.certificate_id, Applications.analyzer_id, \
			   Analyzers.name, Analyzers.description, Analyzers.src, \
			   Certificates.name, Certificates.root_cert_path, Analyzers.args \
			FROM Applications \
		LEFT JOIN Certificates \
			ON Certificates.id = Applications.certificate_id \
		LEFT JOIN Analyzers \
			ON Analyzers.id = Applications.analyzer_id \
		WHERE Applications.id='%d' \
		LIMIT 1;", application_id);
	mysql_query(con, query_buffer);

	MYSQL_RES* result = mysql_store_result(con);
	//printf("num-rows: %d\n", mysql_num_rows(result));

	if(mysql_num_rows(result)==0)
		return NULL;

	TMApplication* application = (TMApplication*)malloc(sizeof(TMApplication));
	if(application==NULL)
		return NULL;

	MYSQL_ROW* row = mysql_fetch_row(result);
	if(row[0]!=NULL)
		application->id = atoi(row[0]);
	string_cpy(&(application->name), row[1]);
	application->certificate = (TMCertificate*)malloc(sizeof(TMCertificate));
	if(application->certificate==NULL)
		return NULL;
	if(row[2]!=NULL)
		application->certificate->id = atoi(row[2]);
	string_cpy(&(application->certificate->name), row[7]);
	string_cpy(&(application->certificate->root_cert_path), row[8]);

	application->analyzer = (TMAnalyzer*)malloc(sizeof(TMAnalyzer));
	if(application->analyzer==NULL)
		return NULL;
	if(row[3]!=NULL) {
		application->analyzer->id = atoi(row[3]);
		string_cpy(&(application->analyzer->name), row[4]);
		string_cpy(&(application->analyzer->description), row[5]);
		string_cpy(&(application->analyzer->src), row[6]);
		string_cpy(&(application->analyzer->args), row[9]);
	}

	mysql_free_result(result);

	sprintf(query_buffer, " \
		SELECT application_config.id, application_config.config_name, application_config.config_value \
		FROM application_config \
		WHERE application_config.application_id = '%d'", application_id);
	mysql_query(con, query_buffer);

	result = mysql_store_result(con);

	application->config = NULL;

	if(mysql_num_rows(result)>0)
	{
		MYSQL_ROW row;
		TMApplication_config* config = NULL;
		while((row = mysql_fetch_row(result)))
		{	
			//TMApplication_config* config = 

			TMApplication_config* last_config = config;
			config = (TMApplication_config*)malloc(sizeof(TMApplication_config));		
			if(config==NULL)
				exit(1);

			config->next=NULL;

			if(last_config==NULL)
				application->config = config;
			else
				last_config->next = config;
			if(row[0]!=NULL)
			{
				config->id = atoi(row[0]);
				string_cpy(&(config->config_name), row[1]);
				string_cpy(&(config->config_value), row[2]);
			}
		}
		mysql_free_result(result);

	}

	return (TMApplication*) application;
	
	//return NULL;
}

TMFilter* get_application_filters(int application_id)
{
	/*TMFilter* filter = (TMFilter*)malloc(sizeof(TMFilter));
	filter->name = "15";
	printf("1>%s\n", filter->name);

	return filter;*/

	int retc;
	TMFilter* return_filter = NULL;
	if(con==NULL)
		if((retc=init_database())==0)
			return retc;

	char query_buffer[QUERY_BUFFER_SIZE];
	sprintf(query_buffer, " \
		SELECT Filters.id, Filters.name \
		FROM Filters \
		WHERE Filters.application_id='%d'; \
		", application_id);
	mysql_query(con, query_buffer);
	MYSQL_RES* result = mysql_store_result(con);
	//printf("num-rows: %d\n", mysql_num_rows(result));

	//printf("%d\n", mysql_num_rows(result));
	if(mysql_num_rows(result)==0)
		return NULL;	

	MYSQL_ROW row;
	TMFilter* filter;
	while((row = mysql_fetch_row(result)))
	{		
		TMFilter* last_filter = filter;
		filter = (TMFilter*)malloc(sizeof(TMFilter));		
		if(filter==NULL)
			return NULL;

		filter->next=NULL;

		if(return_filter==NULL)
			return_filter = filter;
		else
			last_filter->next = filter;
		if(row[0]!=NULL)
			filter->id = atoi(row[0]);
		string_cpy(&(filter->name), row[1]);
		filter->access_list = get_filter_access_lists(filter->id);
		filter->nbar_protocol = get_filter_nbar_protocols(filter->id);

	}
	mysql_free_result(result);

	return (TMFilter*)return_filter;
}

TMAccess_list* get_filter_access_lists(int filter_id)
{
	int retc;
	TMAccess_list* return_acl = NULL;
	if(con==NULL)
		if((retc=init_database())==0)
			return retc;

	char query_buffer[QUERY_BUFFER_SIZE];

	sprintf(query_buffer, " \
		SELECT AccessLists.id, AccessLists.action, AccessLists.protocol, \
		SRC.address as src_address, SRC.mask as src_mask,\
		DST.address as dst_address, DST.mask as dst_mask, \
		PNS.greater_or_equal, PNS.less_or_equal, \
		PND.greater_or_equal, PND.less_or_equal \
		FROM AccessLists \
		LEFT JOIN IpNetworks SRC \
			ON AccessLists.ip_source = SRC.id \
		LEFT JOIN IpNetworks DST \
			ON AccessLists.ip_destination = DST.id \
		LEFT JOIN Ports PNS \
			ON AccessLists.pn_source = PNS.id \
		LEFT JOIN Ports PND \
			ON AccessLists.pn_destination = PND.id \
		WHERE AccessLists.filter_id='%d'; \
		", filter_id);

	mysql_query(con, query_buffer);

	//printf("%s\n", mysql_error(con));

	MYSQL_RES* result = mysql_store_result(con);
	//printf("FACnum-rows: %d\n", mysql_num_rows(result));

	if(mysql_num_rows(result)==0)
		return NULL;	

	MYSQL_ROW row;
	TMAccess_list* acl;

	while((row = mysql_fetch_row(result)))
	{		
		TMAccess_list* last_acl = acl;
		acl = (TMAccess_list*)malloc(sizeof(TMAccess_list));		
		if(acl==NULL)
			return NULL;

		acl->next=NULL;

		if(return_acl==NULL)
			return_acl = acl;
		else
			last_acl->next = acl;

		//filter->id = atoi(row[0]);
		if(row[0]!=NULL)
			acl->id = atoi(row[0]);
		if(strcmp(row[1], "permit")==0)
			acl->action = PERMIT;
		else
			acl->action = DENY;
		string_cpy(&(acl->protocol), row[2]);

		acl->ip_source = (TMIp_network*)malloc(sizeof(TMIp_network));
		acl->ip_destination = (TMIp_network*)malloc(sizeof(TMIp_network));
		if(acl->ip_source==NULL || acl->ip_destination==NULL)
			return NULL;
		string_cpy(&(acl->ip_source->address), row[3]);
		if(row[4]!=NULL)
			acl->ip_source->mask = atoi(row[4]);

		string_cpy(&(acl->ip_destination->address), row[5]);
		if(row[6]!=NULL)
			acl->ip_destination->mask = atoi(row[6]);		

		// Source ports
		if(row[7]!=NULL && row[8]!=NULL)
		{
			acl->pn_source = (TMPorts*)malloc(sizeof(TMPorts));
			if(acl->pn_source==NULL)
				return NULL;
			
			acl->pn_source->greater_or_equal = atoi(row[7]);
			acl->pn_source->less_or_equal = atoi(row[8]);
			//printf(">%d %d\n", acl->pn_source->greater_or_equal, acl->pn_source->less_or_equal);
		} else {
			acl->pn_source = NULL;
		}

		// Destination ports
		if(row[9]!=NULL && row[10]!=NULL)
		{
			acl->pn_destination = (TMPorts*)malloc(sizeof(TMPorts));
			if(acl->pn_destination==NULL)
				return NULL;

			acl->pn_destination->greater_or_equal = atoi(row[9]);
			acl->pn_destination->less_or_equal = atoi(row[10]);
			//printf(">%d %d\n", acl->pn_destination->greater_or_equal, acl->pn_destination->less_or_equal);
		} else {
			acl->pn_destination = NULL;
		}
	}

	mysql_free_result(result);

	return (TMAccess_list*)return_acl;
}

TMNbar_protocol* get_filter_nbar_protocols(int filter_id)
{
	int retc;
	TMNbar_protocol* return_nbar_protocol = NULL;
	if(con==NULL)
		if((retc=init_database())==0)
			return retc;

	char query_buffer[QUERY_BUFFER_SIZE];

	sprintf(query_buffer, " \
		SELECT NbarProtocols.id, NbarProtocols.protocol_name, NbarProtocols.protocol_description, \
		NbarProtocols.protocol_id \
		FROM NbarProtocols \
		INNER JOIN FilterHasNbarProtocols ON FilterHasNbarProtocols.filter_id = '%d' \
		AND FilterHasNbarProtocols.nbar_protocol_id = NbarProtocols.id; \
		", filter_id);

	mysql_query(con, query_buffer);

	//printf("%s\n", mysql_error(con));

	MYSQL_RES* result = mysql_store_result(con);
	//printf("NBPnum-rows: %d\n", mysql_num_rows(result));

	if(mysql_num_rows(result)==0)
		return NULL;	

	MYSQL_ROW row;
	TMNbar_protocol* nbar_protocol;

	while((row = mysql_fetch_row(result)))
	{		
		TMNbar_protocol* last_nbar_protocol = nbar_protocol;
		nbar_protocol = (TMNbar_protocol*)malloc(sizeof(TMNbar_protocol));		
		if(nbar_protocol==NULL)
			return NULL;

		nbar_protocol->next=NULL;

		if(return_nbar_protocol==NULL)
			return_nbar_protocol = nbar_protocol;
		else
			last_nbar_protocol->next = nbar_protocol;

		if(row[0]!=NULL)
			nbar_protocol->id = atoi(row[0]);

		string_cpy(&(nbar_protocol->protocol_name), row[1]);
		string_cpy(&(nbar_protocol->protocol_description), row[2]);
		string_cpy(&(nbar_protocol->protocol_id), row[3]);

		//printf("last_nbar_protocol %d nbar_protocol %d next %d\n", last_nbar_protocol, nbar_protocol, nbar_protocol->next);

	}
	return (TMNbar_protocol*) return_nbar_protocol;
}

TMRouter* get_application_routers(int application_id)
{
	int retc;
	TMRouter* return_router = NULL;
	if(con==NULL)
		if((retc=init_database())==0)
			return retc;

	char query_buffer[QUERY_BUFFER_SIZE];

	sprintf(query_buffer, " \
		SELECT Routers.id, Routers.management_ip, Routers.name, Routers.username, Routers.password, Routers.interfaces \
		FROM Routers \
		WHERE Routers.application_id='%d'; \
		", application_id);

	mysql_query(con, query_buffer);

	//printf("%s\n", mysql_error(con));

	MYSQL_RES* result = mysql_store_result(con);
	//printf("NBPnum-rows: %d\n", mysql_num_rows(result));

	if(mysql_num_rows(result)==0)
		return NULL;	

	MYSQL_ROW row;
	TMRouter* router;

	while((row = mysql_fetch_row(result)))
	{		
		TMRouter* last_router = router;
		router = (TMRouter*)malloc(sizeof(TMRouter));		
		if(router==NULL)
			return NULL;

		router->next=NULL;

		if(return_router==NULL)
			return_router = router;
		else
			last_router->next = router;

		if(row[0]!=NULL)
			router->id = atoi(row[0]);
		string_cpy(&(router->management_ip), row[1]);
		string_cpy(&(router->name), row[2]);
		string_cpy(&(router->username), row[3]);
		string_cpy(&(router->password), row[4]);
		string_cpy(&(router->interfaces), row[5]);
	}
	return (TMRouter*) return_router;
}