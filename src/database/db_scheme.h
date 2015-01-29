#ifndef __DB_SCHEME__
#define __DB_SCHEME__

// TABLE certificate
typedef struct certificate {
	int id;
	char* name;
	char* data;	
} TMCertificate;


struct access_list;
typedef struct access_list TMAcl;
// TABLE access_list
typedef struct access_list {
	int id;
	TMAcl* next;
} TMAcl;

struct filter;
typedef struct filter TMFilter;
// TABLE filter
typedef struct filter {
	int id;
	char* name;
	TMAcl* access_list;	// list of access lists
	TMFilter* next;
} TMFilter;

// TABLE analyzer
typedef struct analyzer {
	int id;
} TMAnalyzer;

// TABLE application
typedef struct application {
	int id;
	char* name;
	TMCertificate* certificate;
	TMAnalyzer* analyzer;
	TMFilter* filter;
} TMApplication;

#endif