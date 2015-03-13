#ifndef __DB_SCHEME__
#define __DB_SCHEME__

// TABLE certificate
typedef struct certificate {
	int id;
	char* name;
	char* root_cert_path;	
} TMCertificate;

struct router;
typedef struct router TMRouter;
typedef struct router {
	int id;
	char* management_ip;
	char* name;
	char* username;
	char* password;
	char* interfaces;
	TMRouter* next;
} TMRouter;

typedef struct ip_network {
	char* address;
	int mask;
} TMIp_network;

typedef struct ports {
	int greater_or_equal;
	int less_or_equal;
} TMPorts;

typedef enum {
	PERMIT,
	DENY
} acl_actions;

struct access_list;
typedef struct access_list TMAccess_list;
// TABLE access_list
typedef struct access_list {
	int id;
	acl_actions action;
	char* protocol;
	TMIp_network* ip_source;
	TMIp_network* ip_destination;
	TMPorts* pn_source;
	TMPorts* pn_destination;
	TMAccess_list* next;
} TMAccess_list;

struct nbar_protocol;
typedef struct nbar_protocol TMNbar_protocol;
typedef struct nbar_protocol {
	int id;
	char* protocol_name;
	char* protocol_description;
	char* protocol_id;
	TMNbar_protocol* next;	
} TMNbar_protocol;

struct filter;
typedef struct filter TMFilter;
// TABLE filter
typedef struct filter {
	int id;
	char* name;
	TMAccess_list* access_list;	// list of access lists
	TMFilter* next;
	TMNbar_protocol* nbar_protocol;
} TMFilter;

// TABLE analyzer
typedef struct analyzer {
	int id;
	char* name;
	char* description;
	char* src;
} TMAnalyzer;

// TABLE application
typedef struct application {
	int id;
	char* name;
	TMCertificate* certificate;
	TMAnalyzer* analyzer;
	TMFilter* filter;
	TMRouter* router;
} TMApplication;

#endif