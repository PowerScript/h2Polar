
/*

	h2Polar - lightweight http/s proxy written in C with ssl intercepting 'n traffic features.
	RedToor, 2021 - https://github.com/PowerScript/h2Polar

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <Winsock2.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <Shlobj.h>
#include <gdiplus.h>
#include <time.h>
#include <ws2tcpip.h>
#include <Winhttp.h>
#ifdef OPENSSL
	#include <openssl/crypto.h>
	#include <openssl/x509.h>
	#include <openssl/x509v3.h>
	#include <openssl/pem.h>
	#include <openssl/ssl.h>
	#include <openssl/err.h>
	#define __CA_COUNTRY                "CO"
	#define __CA_COMPANY                "PowerScript"
	#define __CA_HOST                   "h2Polar"
	#define __CA_AFTER                  31536000L
	#define __CA_FILE                   "h2Polar.cer"
	#define __CA_KEYFILE                "h2Polar.key"
#endif
#ifdef THREAD_POOL
	#include <pthread.h>
	#define __POOL_NTHREAD              20
#endif
#define __AUTHOR                        "RedToor"
#define __VERSION                       "2022.01.20.2037"
#define __CAPTURE_FILE                  "h2Polar.log"
#define __DOWNLOAD_FOLDER               "%s"
#define __CONFIG_FILE                    "h2polar.cfg"
#define __PAC_FILE                      "/h2Polar.pac"
#define __INIT_SIZE_BUFFER              8192
#define __INTERFACE_BIND                "127.0.0.1"
#define __TIMEOUT_CONNECT               4
#define __TIMEOUT_TUNNEL                30
#define __PORT_BIND                     51234
#define __MAX_CLIENT                    100

#define COMMENT_RULE                    '#'
#define SETTING_FORMAT                  "%s = %s[^\n]\n"
#define DELIMITER_RULE_INFO             "|"
#define DELIMITER_RULE                  "\r\n"
#define DOWNLOAD_CONTENT_SLASH_REMPLACE ','
#define MAX_URL_SIZE                    2048
#define MAX_HOSTNAME_SIZE               512
#define MAX_ARG_1_SIZE                  1024
#define MAX_ARG_2_SIZE                  1024
#define MAX_STR_VALUE_HEADER_SIZE       100

#define true 1
#define false 0

typedef int bool;

#ifdef THREAD_POOL
	typedef struct _job {
		int socket;
		struct _job* next;
	} job, *pjob;

	typedef struct {
		pthread_mutex_t look;
		pthread_cond_t work_cond;
		pthread_cond_t working_cond;
		pjob fjob;
		pjob ljob;
		size_t executing;
		size_t nthreads;
		bool stop;
	} thread_pool, *pthread_pool;
#endif

enum {
	_INTERFACE,
	PORT,
	POOL_NTHREADS,
	TIMEOUT_CONNECT,
	TIMEOUT_TUNNEL,
	INIT_BUFFER_SIZE
};

typedef enum 
{
	INIT,
	HEAD_REQUEST,
	BODY_REQUEST,
	HEAD_RESPONSE,
	BODY_RESPONSE,
	INIT_KEEPALIVE
} HTTP_STAGE;

typedef enum {
	SWITCHING_PROTOCOLS = 101
} HTTP_STATUS;

typedef enum  {
	UNKNOW,
	ALL,
	CONNECT,
	GET,
	PUT,
	POST,
	HEAD,
	DELETE_
} PROXY_METHOD;

typedef enum {
	DIRECT,
	CAPTURE,
	MODIFY_BODY_RESPONSE,
	REDIRECT,
	REJECT,
	SCREENSHOT,
	FAKE_TLS_EXT_HOSTNAME,
	REMOVE_HEADER_REQUEST,
	REMOVE_HEADER_RESPONSE,
	ADD_HEADER_REQUEST,
	DOWNLOAD_CONTENT
} PROXY_ACTION;

typedef struct {
	char url[MAX_URL_SIZE];
	char hostname[MAX_HOSTNAME_SIZE];
	char tls_ext_hostname[MAX_HOSTNAME_SIZE];
	int port;
	char method[8];
	char version_protocol;
} reqinfo, *preqinfo;

typedef struct {
	bool chunked;
	struct {
		bool keep_alive;
		bool upgrade;
	} connection;
	u_int content_length;
	char* content_length_offset;
	char content_type[MAX_STR_VALUE_HEADER_SIZE];
	char upgrade[MAX_STR_VALUE_HEADER_SIZE];
} headers, *pheaders;

typedef struct {
	char* pointer;
	u_int written;
	u_int size_block;
} buffer, *pbuffer;

typedef struct _domain_cache
{
	char domain[MAX_HOSTNAME_SIZE];
	u_long ip;
	struct _domain_cache* next;
} domain_cache, *pdomain_cache;

typedef struct 
{
	char hostname[MAX_HOSTNAME_SIZE];
	u_int port;
} redirect, *predirect;

typedef struct 
{
	char hostname[MAX_HOSTNAME_SIZE];
} fake_tls_ext_hostname, *pfake_tls_ext_hostname;

typedef struct 
{
	char content_type[24];
} download_content, *pdownload_content;

typedef struct 
{
	char* prefix;
	char* inject;
	u_int prefix_length;
	u_int inject_length;
} injection, *pinjection;

typedef struct 
{
	char header[2048];
	u_int header_length;
} head, *phead;

typedef struct _rule {
	PROXY_ACTION action;
	char domain[MAX_HOSTNAME_SIZE];
	char url[MAX_URL_SIZE];
	bool ssl;
	u_int port;
	u_int method;
	void* extra_data;
	struct _rule* next;
} rule, *prule;

typedef struct _action {
	PROXY_ACTION action;
	void* extra_data;
	struct _action* next;
} action, *paction;

#ifdef OPENSSL
	char hex_map[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	u_char alpn_protocol[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
	u_int lentgh = sizeof(alpn_protocol);

	typedef struct _certificate_cache
	{
		char cache_hash[200];
		X509* certificate;
		struct _certificate_cache* next;
	} certificate_cache, *pcertificate_cache;

	typedef struct {
		X509* certificate;
		SSL_CTX* context;
		SSL* connection;
	} ssl_layer, *pssl_layer;
#endif

typedef struct {
	int error_code;
	int sock_browser;
	int sock_page;
	int response_code;
	PROXY_METHOD method;
	PROXY_ACTION action;
	HTTP_STAGE stage;
	buffer head_request;
	buffer body_request;
	buffer head_response;
	buffer body_response;
	paction actions;
	reqinfo info;
	headers headers_request;
	headers headers_response;
	DWORD thread_id;
	bool ssl;
	bool connection_established;
	u_int nrequests;
	#ifdef OPENSSL
		pssl_layer ssl_page;
		pssl_layer ssl_browser;
		char* ssl_error;
	#endif
} client, *pclient;

struct {
	char _interface[20];
	u_int port;
	u_int nthreads;
	u_long timeout_connect;
	u_long timeout_tunnel;
	u_int init_buffer_size;
	char* cfg_file;
	#ifdef OPENSSL
		X509* certificate;
		EVP_PKEY* client_key;
		EVP_PKEY* certificate_key;
 		X509_NAME* ca_issuer;
 		#ifdef CA_MEM_CACHE
			pcertificate_cache certificate_cache;
		#endif
	#endif
	#ifdef DEBUG
		CRITICAL_SECTION stdout_lock;
	#endif
	#ifdef DNS_MEM_CACHE
		CRITICAL_SECTION domain_cache_lock;
	#endif
	CRITICAL_SECTION certificate_cache_lock;
	pdomain_cache domain_cache;
	HANDLE proxy_thread;
	SOCKET socket;
	prule proxy_rules;
	buffer pac_request;
} proxy_config, *pproxy_config;

struct {
	char* phttpsd2s;
	char* parse_http_url;
	char* parse_http_url_port;
	char* parse_https_url;
	char* parse_https_url_port;
	char* parse_response_code;
	char* transfer_encoding;
	char* proxy_connection;
	char* keep_alive;
	char* content_lentghrnrn;
	char* content_lentgh;
	char* content_type;
	char* upgrade;
	char* websocket;
	char* hostname;
	char* parse_hostname;
	char* connection;
	char* screenshot;
	char* format_int_value_header;
	char* format_str_value_header;
	char* chunked;
	char* endchunk;
	char* dot_bmp;
	char* accept_encoding;
	char* head_connection_established;
	char* http_get;
	char* http_post;
	char* http_put;
	char* http_connect;
	char* http_head;
	char* http_delete;
	char* head_pac_response;
	char* pac_response_1;
	char* pac_response_2;
	char* pac_response_3;
} const_char, *pconst_char;

char* PROXY_ACTIONS[] = { [DIRECT] = "DIRECT", [CAPTURE] = "CAPTURE", [MODIFY_BODY_RESPONSE] = "MODIFY_BODY_RESPONSE", [REDIRECT] = "REDIRECT", 
						  [REJECT] = "REJECT", [SCREENSHOT] = "SCREENSHOT", [FAKE_TLS_EXT_HOSTNAME] = "FAKE_TLS_EXT_HOSTNAME", 
						  [REMOVE_HEADER_REQUEST] = "REMOVE_HEADER_REQUEST", [REMOVE_HEADER_RESPONSE] = "REMOVE_HEADER_RESPONSE",
						  [ADD_HEADER_REQUEST] = "ADD_HEADER_REQUEST", [DOWNLOAD_CONTENT] = "DOWNLOAD_CONTENT" };
char* PROXY_METHODS[] = { [UNKNOW] = "UNKNOW", [ALL] = "ALL", [CONNECT] = "CONNECT", [GET] = "GET", [PUT] = "PUT", [POST] = "POST", [HEAD] = "HEAD", [DELETE_] = "DELETE" };
char* KEY_SETTING[] = {   [_INTERFACE] = "INTERFACE", [PORT] = "PORT", [POOL_NTHREADS] = "POOL_NTHREADS", [TIMEOUT_CONNECT] = "TIMEOUT_CONNECT",
						  [TIMEOUT_TUNNEL] = "TIMEOUT_TUNNEL", [INIT_BUFFER_SIZE] = "INIT_BUFFER_SIZE" };

#define RETN_OK return true;
#define RETN_FAIL return false;

#ifndef DEBUG
	#define LOGGER(FORMAT, ...)
#else
	char* HTTP_SSL[] = { "NO", "YES" };
	char* PROXY_STAGES[] = { [INIT] = "INIT", [HEAD_REQUEST] = "HEAD_REQUEST", [BODY_REQUEST] = "BODY_REQUEST", [HEAD_RESPONSE] = "HEAD_RESPONSE", [BODY_RESPONSE] = "BODY_RESPONSE", [INIT_KEEPALIVE] = "INIT_KEEPALIVE" };
	#define LOGGER(FORMAT, ...) EnterCriticalSection(&proxy_config.stdout_lock); \
									printf("%d\t%20s\t%lu\t%lu\t" FORMAT ".\n", __LINE__, __FUNCTION__, GetCurrentThreadId(), GetLastError(), ##__VA_ARGS__); \
								LeaveCriticalSection(&proxy_config.stdout_lock);
#endif

#define ADD_ITEM(array, item) if (array == 0){ array = item; } else { item->next = array; } array = item;
#define ITER_LLIST(item, array) for (item=array; item; item=item->next)
#define TRY_EXECUTION(execute) if (!execute) goto __exception;
#define IF_EXTRADATA(action) action == MODIFY_BODY_RESPONSE || REDIRECT == action || action == FAKE_TLS_EXT_HOSTNAME || DOWNLOAD_CONTENT == action

#define ADD_ACTION(actions, naction) ADD_ITEM(actions, naction)
#define ADD_RULE(nrule) ADD_ITEM(proxy_config.proxy_rules, nrule)
#define ADD_DOMAIN_CACHE(ndomain_cache) ADD_ITEM(proxy_config.domain_cache, ndomain_cache)
#define ADD_CERTIFICATE_CACHE(ncertificate_cache) ADD_ITEM(proxy_config.certificate_cache, ncertificate_cache)

#define IF_ZERO(expr) if ((expr) != 0){ LOGGER("__exception") RETN_FAIL }
#define IF_GZERO(expr) if ((expr) <= 0){ LOGGER("__exception") RETN_FAIL }
#define CHECK_REALLOC(castype, function, pointer, ...) if ((pointer = (castype*)function(__VA_ARGS__)) == 0){ LOGGER("__except_heap_corruption") exit(1); }
#define CHECK_ALLOC(castype, function, pointer, ...) CHECK_REALLOC(castype, function, pointer, __VA_ARGS__, sizeof(castype))
#define STR2INT(X) #X
#define IN2STR(X) STR2INT(X)

void load_strings()
{
	strcpy(proxy_config._interface, __INTERFACE_BIND);
	proxy_config.port = __PORT_BIND;
	proxy_config.timeout_connect = __TIMEOUT_CONNECT;
	proxy_config.timeout_tunnel = __TIMEOUT_TUNNEL;
	proxy_config.init_buffer_size = __INIT_SIZE_BUFFER;
	proxy_config.cfg_file = __CONFIG_FILE;
	const_char.http_get = "GET";
	const_char.http_post = "POST";
	const_char.http_connect = "CONNECT";
	const_char.http_put = "PUT";
	const_char.http_head = "HEAD";
	const_char.http_delete = "DELETE";
	const_char.parse_http_url = "http://%" IN2STR(MAX_HOSTNAME_SIZE) "[^/]%" IN2STR(MAX_URL_SIZE) "s";
	const_char.parse_http_url_port = "http://%" IN2STR(MAX_HOSTNAME_SIZE) "[^:]:%d%" IN2STR(MAX_URL_SIZE) "[^\n]";
	const_char.parse_https_url = "https://%" IN2STR(MAX_HOSTNAME_SIZE) "[^/]%" IN2STR(MAX_URL_SIZE) "s";
	const_char.parse_https_url_port = "https://%" IN2STR(MAX_HOSTNAME_SIZE) "[^:]:%d%" IN2STR(MAX_URL_SIZE) "[^\n]";
	const_char.parse_response_code = "%*s %d %*s\r\n";
	const_char.content_lentghrnrn = "Content-Length: %d\r\n\r\n";
	const_char.transfer_encoding = "Transfer-Encoding:";
	const_char.content_lentgh = "Content-Length:";
	const_char.content_type = "Content-Type:";
	const_char.proxy_connection = "Proxy-Connection:";
	const_char.connection = "Connection:";
	const_char.accept_encoding = "Accept-Encoding:";
	const_char.upgrade = "Upgrade:";
	const_char.hostname = "Host:";
	const_char.parse_hostname = "Host: %s\r\n\r\n";
	const_char.format_int_value_header = "%*s %d";
	const_char.format_str_value_header = "%*s %" IN2STR(MAX_STR_VALUE_HEADER_SIZE) "s";
	const_char.chunked = "chunked";
	const_char.websocket = "websocket";
	const_char.keep_alive = "keep-alive";
	const_char.endchunk = "0\r\n\r\n";
	const_char.dot_bmp = ".bmp";
	const_char.screenshot = "sc";
	const_char.head_pac_response = "HTTP/1.0 200\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nConnection: Close\r\nContent-Length: %d\r\n\r\n";
	const_char.head_connection_established = "HTTP/1.1 200 Connection established\r\n\r\n";
	const_char.pac_response_1 = "function FindProxyForURL(url, host){if(";
	const_char.pac_response_2 = "dnsDomainIs(host, \"%s\")||";
	const_char.pac_response_3 = "){return \"PROXY %s:%d\"}return \"DIRECT\"}";
	const_char.phttpsd2s = "https://";
}

#ifdef OPENSSL
	void delete_extention(X509* dst_cert, int nid, int where)
	{
		X509_EXTENSION* ext = 0;
		int ex = 0;

		if ((ex = X509_get_ext_by_NID(dst_cert, nid, where)) >= 0) {
			if ((ext = X509_delete_ext(dst_cert, ex))){
				X509_EXTENSION_free(ext);
			}
		}
	}

	size_t bin2hex(const unsigned char* bin, size_t bin_lentgh, char* str, size_t str_lentgh)
	{
		char* p = 0;
		size_t i = 0;

		if (str_lentgh < (bin_lentgh + 1)){
			return 0;
		}
		p = str;
		for (i = 0; i < bin_lentgh; ++i){
			*p++ = hex_map[*bin >> 4];
			*p++ = hex_map[*bin & 0xf];
			++bin;
		}
		*p = 0;
		return p - str;
	}

	EVP_PKEY* generate_rsa_key()
	{
		EVP_PKEY* pkey = 0;
		RSA * rsa = 0;

		if(!(pkey = EVP_PKEY_new())){
			RETN_FAIL
		}
		if(!(rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL))){
			RETN_FAIL
		}
		if(!EVP_PKEY_assign_RSA(pkey, rsa)){
			EVP_PKEY_free(pkey);
			RETN_FAIL
		}
		return pkey;
	}

	X509* generate_x509(EVP_PKEY* pkey)
	{
		X509 * x509 = 0;
		X509_NAME * gname =  0;

		if(!(x509 = X509_new())){
			RETN_FAIL
		}
		X509_set_version(x509, 2);
		ASN1_INTEGER_set(X509_get_serialNumber(x509), 0);
		X509_gmtime_adj(X509_get_notBefore(x509), 0);
		X509_gmtime_adj(X509_get_notAfter(x509), __CA_AFTER);
		X509_set_pubkey(x509, pkey);
		gname = X509_get_subject_name(x509);
		X509_NAME_add_entry_by_txt(gname, "C",  MBSTRING_ASC, (unsigned char *)__CA_COUNTRY, -1, -1, 0);
		X509_NAME_add_entry_by_txt(gname, "O",  MBSTRING_ASC, (unsigned char *)__CA_COMPANY, -1, -1, 0);
		X509_NAME_add_entry_by_txt(gname, "CN", MBSTRING_ASC, (unsigned char *)__CA_HOST, -1, -1, 0);
		X509_set_issuer_name(x509, gname);
		if(!X509_sign(x509, pkey, EVP_sha1())){
			X509_free(x509);
			RETN_FAIL
		}
		return x509;
	}

	bool load_ssl_files()
	{
		BIO* bio = 0;

		if (!(bio = BIO_new_file(__CA_FILE, "rb"))) goto __exception;
		if (!(proxy_config.certificate = PEM_read_bio_X509(bio, 0, 0, 0))) goto __exception;
		BIO_free(bio);
		if (!(bio = BIO_new_file(__CA_KEYFILE, "rb"))) goto __exception;
		if (!(proxy_config.certificate_key = PEM_read_bio_PrivateKey(bio, 0, 0, 0))) goto __exception;
		BIO_free(bio);
		if (!(proxy_config.client_key = generate_rsa_key())) goto __exception;
		if (!(proxy_config.ca_issuer = X509_get_subject_name(proxy_config.certificate))) goto __exception;
		RETN_OK
		__exception:
			LOGGER("Error loading CA, KEY files: %s", ERR_error_string(ERR_get_error(), 0))
			RETN_FAIL
	}

	bool generate_ssl_files()
	{
 		FILE* certificate = 0;
 		FILE* certificate_key = 0;

		IF_GZERO(proxy_config.client_key = generate_rsa_key())
		IF_GZERO(proxy_config.certificate_key = generate_rsa_key())
		IF_GZERO(proxy_config.certificate = generate_x509(proxy_config.certificate_key))
		proxy_config.ca_issuer = X509_get_subject_name(proxy_config.certificate);
		IF_GZERO(certificate = fopen(__CA_FILE, "wb"))
		IF_GZERO(certificate_key = fopen(__CA_KEYFILE, "wb"))
		PEM_write_PrivateKey(certificate_key, proxy_config.certificate_key, 0, 0,0, 0, 0);
		PEM_write_X509(certificate, proxy_config.certificate);
		fclose(certificate);
		fclose(certificate_key);
		RETN_OK
	}

	bool page_ssl_handshake(pclient request)
	{
		IF_GZERO(request->ssl_page = (pssl_layer)calloc(1, sizeof(ssl_layer)));
		IF_GZERO(request->ssl_page->context = SSL_CTX_new(SSLv23_client_method()));
		if ((request->ssl_page->connection = SSL_new(request->ssl_page->context)) <= 0){
			RETN_FAIL
		}
		if ((request->error_code = SSL_set_fd(request->ssl_page->connection, request->sock_page) <= 0)) goto __exception;
		if ((request->error_code = SSL_set_tlsext_host_name(request->ssl_page->connection, request->info.tls_ext_hostname)) <= 0) goto __exception;
		SSL_set_alpn_protos(request->ssl_page->connection, alpn_protocol, lentgh);
		if ((request->error_code = SSL_connect(request->ssl_page->connection)) <= 0) goto __exception;
		if ((request->ssl_page->certificate = SSL_get_peer_certificate(request->ssl_page->connection)) <= 0) goto __exception;
		RETN_OK
		__exception:
			request->ssl_error = ERR_error_string(SSL_get_error(request->ssl_page->connection, request->error_code), 0);
			RETN_FAIL
	}

	bool browser_ssl_handshake(pclient request)
	{
		IF_GZERO(request->ssl_browser->context = SSL_CTX_new(SSLv23_server_method()));
		if ((request->error_code = SSL_CTX_use_certificate(request->ssl_browser->context, request->ssl_browser->certificate)) != 1) goto __exception;
		if ((request->error_code = SSL_CTX_use_PrivateKey(request->ssl_browser->context, proxy_config.client_key)) != 1) goto __exception;
		if ((request->ssl_browser->connection = SSL_new(request->ssl_browser->context)) <= 0) goto __exception;
		if ((request->error_code = SSL_set_fd(request->ssl_browser->connection, request->sock_browser)) <= 0) goto __exception;
		if ((request->error_code = SSL_accept(request->ssl_browser->connection)) <= 0) goto __exception;
		RETN_OK
		__exception:
			request->ssl_error = ERR_error_string(SSL_get_error(request->ssl_browser->connection, request->error_code), 0);
			RETN_FAIL
	}

	bool clone_certificate(pclient request)
	{
		CHECK_ALLOC(ssl_layer, calloc, request->ssl_browser, 1);
		#ifdef CA_MEM_CACHE
			pcertificate_cache certificate = 0;
			char cache_hash[200] = {0};
			char hash_name[sizeof(request->ssl_page->certificate->sha1_hash) * 2 + 1] = {0};
		
			bin2hex(request->ssl_page->certificate->sha1_hash, sizeof(request->ssl_page->certificate->sha1_hash), hash_name, sizeof(hash_name));
			sprintf(cache_hash, "%s", hash_name);
			EnterCriticalSection(&proxy_config.certificate_cache_lock);
			ITER_LLIST(certificate, proxy_config.certificate_cache){
				if (strcmp(certificate->cache_hash, cache_hash) == 0){
					IF_GZERO(request->ssl_browser->certificate = X509_dup(certificate->certificate));
					LeaveCriticalSection(&proxy_config.certificate_cache_lock);
					RETN_OK
				}
			}
			LeaveCriticalSection(&proxy_config.certificate_cache_lock);
		#endif
		if ((request->ssl_browser->certificate = X509_dup(request->ssl_page->certificate)) <= 0) goto __exception;
		delete_extention(request->ssl_browser->certificate, NID_crl_distribution_points, -1);
		delete_extention(request->ssl_browser->certificate, NID_info_access, -1);
		delete_extention(request->ssl_browser->certificate, NID_authority_key_identifier, -1);
		delete_extention(request->ssl_browser->certificate, NID_certificate_policies, 0);
		if ((request->error_code = X509_set_pubkey(request->ssl_browser->certificate, proxy_config.client_key)) == 0) goto __exception;
		X509_set_issuer_name(request->ssl_browser->certificate, proxy_config.ca_issuer);
		if (!(request->error_code = X509_sign(request->ssl_browser->certificate, proxy_config.certificate_key, EVP_sha256()))) goto __exception;
		#ifdef CA_MEM_CACHE
			CHECK_ALLOC(certificate_cache, calloc, certificate, 1)
			IF_GZERO(certificate->certificate = X509_dup(request->ssl_browser->certificate));
			strcpy(certificate->cache_hash, cache_hash);
			EnterCriticalSection(&proxy_config.certificate_cache_lock);
			ADD_CERTIFICATE_CACHE(certificate)
			LeaveCriticalSection(&proxy_config.certificate_cache_lock);
		#endif
		RETN_OK
		__exception:
			request->ssl_error = ERR_error_string(ERR_get_error(), 0);
			RETN_FAIL
	}

	bool load_ssl_files_pinning(pclient request)
	{
		LOGGER("-->ssl pinning")
		IF_GZERO(page_ssl_handshake(request))
		IF_GZERO(clone_certificate(request))
		IF_GZERO(send(request->sock_browser, const_char.head_connection_established, 39, 0));
		IF_GZERO(browser_ssl_handshake(request))
		request->head_request.written = 0;
		memset((void*)&request->info.url, 0, MAX_URL_SIZE);
		memset((void*)&request->headers_request, 0, sizeof(headers));
		RETN_OK
	}
#endif

char* strnstr(char* hay, int haysize, char* needle, int needlesize)
{
	int haypos = 0;
	int needlepos = 0;

	haysize -= needlesize;
	for (haypos = 0; haypos <= haysize; haypos++) {
		for (needlepos = 0; needlepos < needlesize; needlepos++){
			if (tolower(hay[haypos + needlepos]) != tolower(needle[needlepos])){
				break;
			}
		}
		if (needlepos == needlesize) {
			return hay + haypos;
		}
	}
	RETN_FAIL
}

int get_num_dig(unsigned size)
{
	if (size >= 1000000000) return 10;
	if (size >= 100000000) return 9;
	if (size >= 10000000) return 8;
	if (size >= 1000000) return 7;
	if (size >= 100000) return 6;
	if (size >= 10000) return 5;
	if (size >= 1000) return 4;
	if (size >= 100) return 3;
	if (size >= 10) return 2;
	return 1;
}

#ifdef DEBUG
	void printer(char* data, int size)
	{
		EnterCriticalSection(&proxy_config.stdout_lock);
		printf("------------------------------------------------------------------------\n");
		char a, line[17], c;
		int j;

		for (int i = 0; i < size; i++){
			c = data[i];
			printf(" %.2x", (unsigned char)c);
			a = (c >= 32 && c <= 128) ? (unsigned char)c : '.';
			line[i % 16] = a;
			if ((i != 0 && (i + 1) % 16 == 0) || i == size - 1)
			{
				line[i % 16 + 1] = '\0';
				printf("		  ");
				for (j = strlen(line); j < 16; j++)
				{
					printf("   ");
				}
				printf("%s \n", line);
			}
		}
		printf("\n-----------------------------------------------------------------------%d\n", size);
		LeaveCriticalSection(&proxy_config.stdout_lock);
	}
#endif

void write_bmp(HBITMAP bitmap, HDC hDC, LPTSTR filename)
{
	BITMAP bmp = {0}; 
	BITMAPFILEHEADER hdr = {0};
	PBITMAPINFO pbmi = 0; 
	PBITMAPINFOHEADER pbih = 0;
	DWORD dwTmp = 0; 
	DWORD cb = 0;
	WORD cClrBits = 0; 
	HANDLE hf = 0;
	LPBYTE lpBits = 0;
	BYTE* hp = 0;

	if (GetObject(bitmap, sizeof(BITMAP), (LPSTR)&bmp)){
		cClrBits = (WORD)(bmp.bmPlanes * bmp.bmBitsPixel); 
		if (cClrBits == 1){ cClrBits = 1;  }
		else if (cClrBits <= 4) {
			cClrBits = 4;
		} else if (cClrBits <= 8) {
			cClrBits = 8;
		} else if (cClrBits <= 16){
			cClrBits = 16;
		} else if (cClrBits <= 24){
			cClrBits = 24;
		} else					{
			cClrBits = 32;
		} if (cClrBits != 24){
			pbmi = (PBITMAPINFO) LocalAlloc(LPTR, sizeof(BITMAPINFOHEADER) + sizeof(RGBQUAD) * (1 << cClrBits));
		}else{
			pbmi = (PBITMAPINFO) LocalAlloc(LPTR, sizeof(BITMAPINFOHEADER)); 
		}
		pbmi->bmiHeader.biSize = sizeof(BITMAPINFOHEADER); 
		pbmi->bmiHeader.biWidth = bmp.bmWidth; 
		pbmi->bmiHeader.biHeight = bmp.bmHeight; 
		pbmi->bmiHeader.biPlanes = bmp.bmPlanes; 
		pbmi->bmiHeader.biBitCount = bmp.bmBitsPixel; 
		if (cClrBits < 24){
			pbmi->bmiHeader.biClrUsed = (1 << cClrBits); 
		}
		pbmi->bmiHeader.biCompression = BI_RGB; 
		pbmi->bmiHeader.biSizeImage = (pbmi->bmiHeader.biWidth + 7) / 8 * pbmi->bmiHeader.biHeight * cClrBits; 
		pbmi->bmiHeader.biClrImportant = 0; 
		pbih = (PBITMAPINFOHEADER) pbmi; 
		if ((lpBits = (LPBYTE)GlobalAlloc(GMEM_FIXED, pbih->biSizeImage)) != 0){
			if (GetDIBits(hDC, bitmap, 0, (WORD) pbih->biHeight, lpBits, pbmi, DIB_RGB_COLORS)){
				if ((hf = CreateFile(filename, GENERIC_READ | GENERIC_WRITE, (DWORD) 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL)) != INVALID_HANDLE_VALUE){
					hdr.bfType = 0x4D42;
					hdr.bfSize = (DWORD)(sizeof(BITMAPFILEHEADER) + pbih->biSize + pbih->biClrUsed * sizeof(RGBQUAD) + pbih->biSizeImage);
					hdr.bfReserved1 = 0;
					hdr.bfReserved2 = 0; 
					hdr.bfOffBits = (DWORD) sizeof(BITMAPFILEHEADER) + pbih->biSize + pbih->biClrUsed * sizeof (RGBQUAD);
					WriteFile(hf, (LPVOID)&hdr, sizeof(BITMAPFILEHEADER), (LPDWORD) &dwTmp, NULL);
					WriteFile(hf, (LPVOID)pbih, sizeof(BITMAPINFOHEADER) + pbih->biClrUsed * sizeof (RGBQUAD), (LPDWORD) &dwTmp, NULL);
					cb = pbih->biSizeImage;
					hp = lpBits; 
					WriteFile(hf, (LPSTR)hp, (int)cb, (LPDWORD)&dwTmp, NULL);
					CloseHandle(hf);
				}
			}
			GlobalFree((HGLOBAL)lpBits);
		}
		GlobalFree((HGLOBAL)pbmi);
	}
}

bool generate_bmp(int x, int y, int width, int height)
{
	HDC hdc = 0;
	HBITMAP hbitmap = 0;
	char bmp_file[MAX_PATH] = {0};

	srand(time(NULL));
	sprintf(bmp_file, "%s%d%s", const_char.screenshot, (15535 + rand() % (65000 + 1 - 15535)), const_char.dot_bmp);
	IF_GZERO(hdc = CreateCompatibleDC(0));
	IF_GZERO(hbitmap = CreateCompatibleBitmap(GetDC(0), width, height));
	IF_GZERO(SelectObject(hdc, hbitmap));
	BitBlt(hdc, 0, 0, width, height, GetDC(0), x, y, SRCCOPY);
	write_bmp(hbitmap, hdc, bmp_file);
	DeleteObject(hbitmap);
	DeleteDC(hdc);
	RETN_OK
}

bool compare(char* init, int count, char* str, int count2)
{
	if (count2 == 0) RETN_OK
	if (count != count2) RETN_FAIL
	for (int i = 0; i < count; ++i){
		if (init[i] != str[i]) RETN_FAIL
	}
	RETN_OK
}

bool check_filter(char* mask_filter, char* str, char delimiter)
{
	u_int size_incomming = 0;
	u_int size_domain = 0;
	int count = 0;
	int count2 = 0;
	int read = 0;
	int read2 = 0;
	bool end = false;

	size_incomming = strlen(mask_filter) + 1;
	size_domain = strlen(str) + 1;
	for (int i = 0; i < size_domain; ++i){
		if (str[i] != delimiter && str[i] != '\0') {count++;}
		if (str[i] == delimiter || str[i] == '\0') {
			if (end) RETN_FAIL
			for (int d = 0; d < (size_incomming - read2); ++d){ 
				if (mask_filter[read2 + d] != delimiter && mask_filter[read2 + d] != '\0') count2++;
				if (mask_filter[read2 + d] == delimiter) break;
				if (mask_filter[read2 + d] == '\0') end = true;
			}
			if (mask_filter[read2]  == '!'){
				end = true;
				break;
			}
			if (compare(str + read, count, mask_filter + read2, count2) == false) RETN_FAIL
			read += count + 1;
			read2 += count2 + 1;
			count = 0;
			count2 = 0;
		}
	}
	return end;
}

void generate_pac_response()
{
	prule proxy_rule = 0;
	u_int body_length = 0;

	body_length = 39 + 35 + strlen(proxy_config._interface) + get_num_dig(proxy_config.port);
	ITER_LLIST(proxy_rule, proxy_config.proxy_rules){
		body_length += strlen(proxy_rule->domain) + 23;
	}
	body_length -= 2;
	proxy_config.pac_request.size_block = body_length + 140;
	CHECK_ALLOC(char, calloc, proxy_config.pac_request.pointer, proxy_config.pac_request.size_block)
	sprintf(proxy_config.pac_request.pointer, const_char.head_pac_response, body_length);
	proxy_config.pac_request.written += strlen(proxy_config.pac_request.pointer);
	memcpy(proxy_config.pac_request.pointer + proxy_config.pac_request.written, const_char.pac_response_1, 39);
	proxy_config.pac_request.written += 39;
	ITER_LLIST(proxy_rule, proxy_config.proxy_rules){
		sprintf(proxy_config.pac_request.pointer + proxy_config.pac_request.written, const_char.pac_response_2, proxy_rule->domain);
		proxy_config.pac_request.written += strlen(proxy_rule->domain) + 23;
	}
	proxy_config.pac_request.written -= 2;
	sprintf(proxy_config.pac_request.pointer + proxy_config.pac_request.written, const_char.pac_response_3, proxy_config._interface, proxy_config.port);
	proxy_config.pac_request.written += strlen(proxy_config.pac_request.pointer + proxy_config.pac_request.written);
}

void free_proxy_actions(pclient request)
{
	paction actions = request->actions;
	paction backup = 0;

	while (actions){
		if (IF_EXTRADATA(actions->action)){
			free(actions->extra_data);
		}
		backup = actions;
		actions = actions->next;
		free(backup);
	}
}

void close_handle(pclient request)
{
	LOGGER("<+free/closing objects/sockets")
	if (request != 0){
		if (request->sock_browser > 0){
			closesocket(request->sock_browser);
		}
		if (request->sock_page > 0){
			closesocket(request->sock_page);
		}
		if (request->head_request.size_block > 0){
			free(request->head_request.pointer);
		}
		if (request->body_request.size_block > 0){
			free(request->body_request.pointer);
		}
		if (request->head_response.size_block > 0){
			free(request->head_response.pointer);
		}
		if (request->body_response.size_block > 0){
			free(request->body_response.pointer);
		}
		free_proxy_actions(request);
		#ifdef OPENSSL
			if (request->ssl_browser > 0){
				if (request->ssl_browser->certificate > 0){
					X509_free(request->ssl_browser->certificate);
				}
				if (request->ssl_browser->connection > 0){
					SSL_shutdown(request->ssl_browser->connection);
					SSL_free(request->ssl_browser->connection);
				}
				if (request->ssl_browser->context > 0){
					SSL_CTX_free(request->ssl_browser->context);
				}
				free(request->ssl_browser);
			}
			if (request->ssl_page > 0){
				if (request->ssl_page->certificate > 0){
					X509_free(request->ssl_page->certificate);
				}
				if (request->ssl_page->connection > 0){
					SSL_shutdown(request->ssl_page->connection);
					SSL_free(request->ssl_page->connection);
				}
				if (request->ssl_page->context > 0){
					SSL_CTX_free(request->ssl_page->context);
				}
				free(request->ssl_page);
			}
		#endif
		free(request);
	}
}

bool get_method(char* buffer, u_int* method)
{
	if (strncmp(buffer, PROXY_METHODS[ALL], 3) == 0){
		*method = ALL;
		RETN_OK
	} else if (strncmp(buffer, PROXY_METHODS[GET], 3) == 0){
		*method = GET;
		RETN_OK
	}else if (strncmp(buffer, PROXY_METHODS[POST], 4) == 0){
		*method = POST;
		RETN_OK
	} else if (strncmp(buffer, PROXY_METHODS[CONNECT], 7) == 0){
		*method = CONNECT;
		RETN_OK
	} else if (strncmp(buffer, PROXY_METHODS[PUT], 3) == 0){
		*method = PUT;
		RETN_OK
	} else if (strncmp(buffer, PROXY_METHODS[HEAD], 4) == 0){
		*method = HEAD;
		RETN_OK
	} else if (strncmp(buffer, PROXY_METHODS[DELETE_], 6) == 0){
		*method = DELETE_;
		RETN_OK
	}
	RETN_FAIL
}

bool allow_buffer_space(char** pointer, u_int* written, u_int* size_block)
{
	if (*written == *size_block){
		*size_block += __INIT_SIZE_BUFFER;
		CHECK_REALLOC(char, realloc, *pointer, (void*)*pointer, *size_block * sizeof(char))
	}
	RETN_OK
}

int output_buffer(bool is_ssl, int socket, pssl_layer ssl, char* pointer, u_int size)
{
	int incomming = 0;

	if (is_ssl){
		if ((incomming = SSL_write(ssl->connection, pointer, size)) <= 0){
			#ifdef DEBUG
				int error = SSL_get_error(ssl->connection, incomming);
				LOGGER("---->ssl_write %d %d %d %d %s", incomming, error, size, WSAGetLastError(), ERR_error_string(error, 0))
			#endif
		}
	} else {
		incomming = send(socket, pointer, size, 0);
	}
	return incomming;
}

int input_buffer(bool is_ssl, int socket, pssl_layer ssl, char* pointer, u_int size)
{
	int incomming = 0;
	
	if (is_ssl){
		if ((incomming = SSL_read(ssl->connection, pointer, size)) <= 0){
			#ifdef DEBUG
				int error = SSL_get_error(ssl->connection, incomming);
				LOGGER("---->ssl_read %d %d %d %d %s", incomming, error, size, WSAGetLastError(), ERR_error_string(error, 0))
			#endif
		}
	} else {
		incomming = recv(socket, pointer, size, 0);
	}
	return incomming;
}

bool send_buffer(bool is_ssl, int socket, pssl_layer ssl, char* buffer, u_int size)
{
	u_int total_sent = 0;
	int outcomming_buffer = 0;

	while (total_sent != size){
		IF_GZERO(outcomming_buffer = output_buffer(is_ssl, socket, ssl, buffer + total_sent, size - total_sent))
		total_sent += (u_int)outcomming_buffer;
	}
	RETN_OK
}

bool add_http_header(pbuffer head_buffer, char* header, u_int header_length)
{
	u_int fix_length = head_buffer->written + header_length;

	IF_GZERO(head_buffer->pointer)
	if(fix_length > head_buffer->size_block){
		head_buffer->size_block = fix_length;
		CHECK_REALLOC(char, realloc, head_buffer->pointer, head_buffer->pointer, head_buffer->size_block)
	}
	head_buffer->written = head_buffer->written - 2;
	memcpy(head_buffer->pointer + head_buffer->written, header, header_length);
	head_buffer->written += header_length;
	memcpy(head_buffer->pointer + head_buffer->written, "\r\n\r\n", 4);
	head_buffer->written += 4;
	RETN_OK
}

bool remove_http_header(pbuffer head_buffer, char* headname)
{
	char* offset_header = 0;
	u_int fix_length = 0;
	u_int right_block = 0;
	u_int headname_lentgh = strlen(headname);

	IF_GZERO(head_buffer->pointer)
	if ((offset_header = strnstr(head_buffer->pointer, head_buffer->written, headname, headname_lentgh))){
		fix_length = (strstr(offset_header, "\r") - offset_header) + 2;
		right_block = head_buffer->written - (offset_header - head_buffer->pointer) - headname_lentgh;
		memmove(offset_header, offset_header + fix_length, right_block);
		head_buffer->written -= fix_length;
		RETN_OK
	}
	RETN_FAIL
}

bool get_body_request(bool is_ssl, int socket, pssl_layer ssl, pbuffer buffer, int content_length, pclient request)
{
	int incomming_buffer = 0;

	if (content_length == 0){
		RETN_OK
	} else if (content_length > buffer->size_block){
		CHECK_REALLOC(char, realloc, buffer->pointer, buffer->pointer, content_length * sizeof(char))
		buffer->size_block = content_length;
	}
	while (buffer->written != content_length){
		IF_GZERO(incomming_buffer = input_buffer(is_ssl, socket, ssl, buffer->pointer + buffer->written, content_length - buffer->written))
		if (request != 0){
			if (request->action != MODIFY_BODY_RESPONSE){
				IF_GZERO(send_buffer(request->ssl, request->sock_browser, request->ssl_browser, buffer->pointer + buffer->written, incomming_buffer))
			}
		}
		buffer->written += incomming_buffer;
	}
	RETN_OK
}

bool get_headers_request(bool is_ssl, int socket, pssl_layer ssl, pbuffer buffer)
{
	int incomming_buffer = 0;

	while (true){
		IF_GZERO(allow_buffer_space(&buffer->pointer, &buffer->written, &buffer->size_block))
		IF_GZERO(incomming_buffer = input_buffer(is_ssl, socket, ssl, buffer->pointer + buffer->written, 1))
		buffer->written += incomming_buffer;
		if (buffer->written > 10){
			if (buffer->pointer[buffer->written - 1] == '\n' && buffer->pointer[buffer->written - 2] == '\r' && buffer->pointer[buffer->written - 3] == '\n' && buffer->pointer[buffer->written - 4] == '\r'){
				RETN_OK
			}
		}
	}
	RETN_FAIL
}

bool parse_headers(pbuffer buffer, pheaders header)
{
	char* token = 0;
	char* token_name = 0;
	char* token_end = 0;
	int header_lentgh = 0;
	int value_length = 0;

	token = strnstr(buffer->pointer, buffer->written, "\n", 1);
	while (token != 0){
		token_end = strstr(token + 1, "\n");
		header_lentgh = token_end - (token + 2);
		if (header_lentgh == 0){
			break;
		}
		token_name = strstr(token + 1, ":");
		value_length = (token_name - token) + 1;
		//printer(token + 1, (token_name - token) + 1);
		//printer(token_name + 1, header_lentgh - value_length + 1);
		if (strnstr(token + 1, (token_name - token) + 1, const_char.content_lentgh, 15)){
			if (sscanf(token + 1, const_char.format_int_value_header, &header->content_length) == 1){
				header->content_length_offset = token + 17;
			}
		} else if (strnstr(token + 1, (token_name - token) + 1, const_char.transfer_encoding, 18)){
			if (strnstr(token_name + 1, header_lentgh - value_length + 1, const_char.chunked, 7)){
				header->chunked = true;
			}
		} else if (strnstr(token + 1, (token_name - token) + 1, const_char.connection, 11)){
			if (strnstr(token_name + 1, header_lentgh - value_length + 1, const_char.keep_alive, 10)){
				header->connection.keep_alive = true;
			} else if (strnstr(token_name + 1, header_lentgh - value_length + 1, const_char.upgrade, 7)){
				header->connection.upgrade = true;
			}
		} else if (strnstr(token + 1, (token_name - token) + 1, const_char.content_type, 13)){
			sscanf(token + 1, const_char.format_str_value_header, header->content_type);
		} else if (strnstr(token + 1, (token_name - token) + 1, const_char.upgrade, 8)){
			sscanf(token + 1, const_char.format_str_value_header, header->upgrade);
		}
		token = token_end;
	}
	RETN_OK
}

bool get_request(pclient request)
{
	LOGGER("--->getting http request")
	request->stage = HEAD_REQUEST;
	IF_GZERO(get_headers_request(request->ssl, request->sock_browser, request->ssl_browser, &request->head_request))
	IF_GZERO(get_method(request->head_request.pointer, &request->method))
	parse_headers(&request->head_request, &request->headers_request);
	request->stage = BODY_REQUEST;
	if (request->method == POST && request->headers_request.content_length > 0){
		IF_GZERO(get_body_request(request->ssl, request->sock_browser, request->ssl_browser, &request->body_request, request->headers_request.content_length, 0))
	}
	RETN_OK
}

void reset_request(pclient request)
{
	request->head_request.written = 0;
	request->body_request.written = 0;
	request->head_response.written = 0;
	request->body_response.written = 0;
	request->error_code = 0;
	request->response_code = 0;
	request->action = DIRECT;
	request->stage = INIT_KEEPALIVE;
	request->nrequests++;
	memset(request->info.url, 0, MAX_URL_SIZE);
	memset((void*)&request->headers_request, 0, sizeof(headers));
	memset((void*)&request->headers_response, 0, sizeof(headers));
	free_proxy_actions(request);
	request->actions = 0;
}

bool alloc_request(pclient* request)
{
	LOGGER("+>allocating request")

	CHECK_ALLOC(client, calloc, *request, 1)
	CHECK_ALLOC(char, calloc, (*request)->head_request.pointer, proxy_config.init_buffer_size)
	(*request)->stage = INIT;
	(*request)->method = UNKNOW;
	(*request)->action = DIRECT;
	(*request)->sock_browser = 0;
	(*request)->sock_page = 0;
	(*request)->info.port = 80;
	(*request)->connection_established = false;
	(*request)->ssl = false;
	(*request)->head_request.size_block = proxy_config.init_buffer_size;
	RETN_OK
}

bool get_info_request(pclient request)
{
	char* token = 0;
	int lentgh = 0;
	int method_lentgh = 0;
	int url_lentgh = 0;
	int index = 0;

	if (!(lentgh = strcspn(request->head_request.pointer, " "))) RETN_FAIL
	strncpy(request->info.method, request->head_request.pointer, lentgh);
	method_lentgh = lentgh + 1;
	if (!(token = strstr(request->head_request.pointer, "\r\n"))) RETN_FAIL
	lentgh = token - request->head_request.pointer - 1;
	request->info.version_protocol = request->head_request.pointer[lentgh];
	request->info.port = request->ssl ? request->info.port : 80;
	lentgh -= 8 + method_lentgh;
	token += 2;
	if(lentgh >= sizeof(request->info.url)){
		lentgh = sizeof(request->info.url) - 1;
	}
	strncpy(request->info.url, request->head_request.pointer + method_lentgh, lentgh);
	if ((token = strstr(token, const_char.hostname))){
		lentgh = strstr(token, "\r\n") - token - 6;
		strncpy(request->info.hostname, token + 6, lentgh);
		if ((token = strstr(request->info.hostname, ":"))){
			sscanf(token + 1, "%d", &request->info.port);
			*token = '\0';
		}
		strcpy(request->info.tls_ext_hostname, request->info.hostname);
	}
	if (strncmp(request->info.method, const_char.http_connect, 7) == 0){
		request->ssl = true;
		if (*request->info.url != '/'){
			strcpy(request->info.url, "/");
		}
		RETN_OK
	}
	if (*request->info.url != '/'){
		if (request->info.url[5] == 's' || 'S' == request->info.url[5]){
			request->ssl = true;
		}
		lentgh = strcspn(request->info.url + 8, "/") + 8;
		url_lentgh = strlen(request->info.url) - lentgh + 1;
		memmove(request->info.url, request->info.url + lentgh, url_lentgh);
		memmove(request->head_request.pointer + method_lentgh, request->head_request.pointer + method_lentgh + lentgh, request->head_request.written - lentgh);
		request->head_request.written -= lentgh;
	}
	for (index = 0; index < strlen(request->info.url); ++index){
		if (request->info.url[index] == '?' || ';' == request->info.url[index] || request->info.url[index] == '#'){
			request->info.url[index] = '\0';
			break;
		}
	}
	if ((token = strnstr(request->head_request.pointer, request->head_request.written, const_char.proxy_connection, 17))){
		memmove(token, token + 6, request->head_request.written - (token - request->head_request.pointer) - 6);
		request->head_request.written -= 6;
	}
	RETN_OK
}

bool lookup_domain(struct sockaddr_in* sockinfo, char* domain)
{
	struct hostent* host_resolv = 0;
	struct addrinfo* addr_host_resolv = 0;
	struct addrinfo hints = {0};
	u_long addr = 0;

	#ifdef DNS_MEM_CACHE
		pdomain_cache local_domain = 0;

		EnterCriticalSection(&proxy_config.domain_cache_lock);
		ITER_LLIST(local_domain, proxy_config.domain_cache){
			if (strcmp(local_domain->domain, domain) == 0){
				sockinfo->sin_addr.s_addr = local_domain->ip;
				LeaveCriticalSection(&proxy_config.domain_cache_lock);
				RETN_OK
			}
		}
		LeaveCriticalSection(&proxy_config.domain_cache_lock);
	#endif
	if ((addr = inet_addr(domain)) != INADDR_NONE){
		memcpy((void*)&sockinfo->sin_addr, &addr, sizeof(u_long));
		#ifdef DNS_MEM_CACHE
			goto __save_domain;
		#else
			RETN_OK
		#endif
	}
	if ((host_resolv = gethostbyname(domain)) != 0){
		memcpy((void*)&sockinfo->sin_addr, &*((unsigned int*)host_resolv->h_addr_list[0]), sizeof(u_long));
		#ifdef DNS_MEM_CACHE
			goto __save_domain;
		#else
			RETN_OK
		#endif
	}
	if (getaddrinfo(domain, 0, &hints, &addr_host_resolv) == 0){
		if (addr_host_resolv != 0){
			if (addr_host_resolv->ai_family == AF_INET){
				memcpy((void*)&sockinfo->sin_addr, (void*)&((struct sockaddr_in*)addr_host_resolv->ai_addr)->sin_addr, sizeof(u_long));
				freeaddrinfo(addr_host_resolv);
				#ifdef DNS_MEM_CACHE
					goto __save_domain;
				#else
					RETN_OK
				#endif
			}
		}
	}
	freeaddrinfo(addr_host_resolv);
	RETN_FAIL
	#ifdef DNS_MEM_CACHE
		__save_domain:
			CHECK_ALLOC(domain_cache, calloc, local_domain, 1)
			strcpy(local_domain->domain, domain);
			local_domain->ip = sockinfo->sin_addr.s_addr;
			EnterCriticalSection(&proxy_config.domain_cache_lock);
			ADD_DOMAIN_CACHE(local_domain)
			LeaveCriticalSection(&proxy_config.domain_cache_lock);
			RETN_OK
	#endif
}

bool set_socket_timeout(int socket, u_int timeout)
{
	u_long ltimeout = timeout;

	IF_ZERO(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (void*)&ltimeout, sizeof(u_long)))
	ltimeout = timeout;
	IF_ZERO(setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (void*)&ltimeout, sizeof(u_long)))
	RETN_OK
}

bool socket_connection(pclient request)
{
	struct sockaddr_in page = {0};

	IF_GZERO(lookup_domain(&page, request->info.hostname))
	IF_GZERO(request->sock_page = socket(2, 1, 0))
	page.sin_port = htons(request->info.port);
	page.sin_family = 2;
	set_socket_timeout(request->sock_page, proxy_config.timeout_connect);
	if (connect(request->sock_page, (struct sockaddr*)&page, sizeof(page)) != SOCKET_ERROR){
		RETN_OK
	}
	RETN_FAIL
}

bool send_pac_response(pclient request)
{
	LOGGER("->pac request")
	IF_GZERO(send_buffer(false, request->sock_browser, 0, proxy_config.pac_request.pointer, proxy_config.pac_request.written))
	request->action = REJECT;
	RETN_OK
}

void take_screenshot()
{
	GdiplusStartupInput gdiplusStartupInput = {0};
	ULONG_PTR gdiplusToken = 0;
	int x1 = 0;
	int y1 = 0;
	int x2 = 0;
	int y2 = 0;

	gdiplusStartupInput.GdiplusVersion = 1;
	GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
	x2 = GetSystemMetrics(SM_CXSCREEN);
	y2 = GetSystemMetrics(SM_CYSCREEN);
	generate_bmp(x1, y1, x2 - x1, y2 - y1);
	GdiplusShutdown(gdiplusToken);
}

bool apply_injection(pclient request, pinjection injection)
{
	char* offset_inj = 0;
	int fix_length = 0;
	int right_block = 0;
	int head_right_block = 0;
	int fix_lentgh_digits = 0;
	int fix_length_original = 0;
	int ndigits = 0;

	if (request->stage == BODY_REQUEST){
		remove_http_header(&request->head_request, const_char.accept_encoding);
	} else if (request->stage == BODY_RESPONSE){
		IF_GZERO(request->body_response.pointer)
		if ((offset_inj = strnstr(request->body_response.pointer, request->body_response.written, injection->prefix, injection->prefix_length))){
			fix_length = (request->body_response.written - injection->prefix_length) + injection->inject_length;
			right_block = request->body_response.written - (offset_inj - request->body_response.pointer) - injection->prefix_length;
			fix_lentgh_digits = get_num_dig(fix_length);
			ndigits = fix_lentgh_digits - fix_length_original;
			LOGGER("----->injecting body: real body %d, content_length %d, necesary size %d", request->body_response.written, request->headers_response.content_length, fix_length)
			if (ndigits > 0 && request->headers_response.content_length_offset > 0){
				head_right_block = request->head_response.written - (request->headers_response.content_length_offset - request->head_response.pointer) - fix_length_original;
				if (request->head_response.written == request->head_response.size_block){
					request->head_response.size_block += ndigits;
					CHECK_REALLOC(char, realloc, request->head_response.pointer, request->head_response.pointer, sizeof(char) * request->head_response.size_block)
					request->head_response.written = request->head_response.size_block;
				} else {
					request->head_response.written += ndigits;
				}
				memmove(request->headers_response.content_length_offset + fix_lentgh_digits, request->headers_response.content_length_offset + fix_length_original, head_right_block);
			}
			if (fix_length > request->body_response.size_block){
				request->body_response.size_block = fix_length;
				request->body_response.written = request->body_response.size_block;
				CHECK_REALLOC(char, realloc, request->body_response.pointer, request->body_response.pointer, sizeof(char) * request->body_response.size_block)
				offset_inj = strnstr(request->body_response.pointer, request->body_response.written, injection->prefix, injection->prefix_length);
			} else {
				request->body_response.written = fix_length;
			}
			memmove(offset_inj + injection->inject_length, offset_inj + injection->prefix_length, right_block);
			memcpy(offset_inj, injection->inject, injection->inject_length);
		}
		if (request->headers_response.chunked){
			remove_http_header(&request->head_response, const_char.transfer_encoding);
			fix_length = 20 + get_num_dig(request->body_response.written);
			if ((request->head_response.size_block - request->head_response.written) <= (request->head_response.written + fix_length)){
				request->head_response.size_block = request->head_response.written + fix_length;
				CHECK_REALLOC(char, realloc, request->head_response.pointer, request->head_response.pointer, sizeof(char) * request->head_response.size_block)
			}
			snprintf(request->head_response.pointer + request->head_response.written - 2, fix_length, const_char.content_lentghrnrn, request->body_response.written);
			request->head_response.written += (fix_length - 2);
		}
		if (request->headers_response.content_length_offset > 0) {
			snprintf(request->headers_response.content_length_offset, fix_lentgh_digits, "%d", request->body_response.written);
			request->headers_response.content_length = request->body_response.written;
		}
	}
	RETN_OK
}

bool apply_capture(pclient request)
{
	FILE* log_file = 0;

	IF_GZERO(log_file = fopen(__CAPTURE_FILE, "a"))
	if (request->stage == BODY_REQUEST){
		fwrite(request->head_request.pointer, sizeof(char), request->head_request.written, log_file);
		if (request->body_request.written > 0){
			fwrite(request->body_request.pointer, sizeof(char), request->body_request.written, log_file);
			fwrite("\n", sizeof(char), 1, log_file);
		}
	} else if (request->stage == BODY_RESPONSE){
		fwrite(request->head_response.pointer, sizeof(char), request->head_response.written, log_file);
	}
	fwrite("-----------------------------------------------------\n", sizeof(char), 54, log_file);
	fclose(log_file);
	RETN_OK
}

bool apply_redirect(pclient request, predirect redirect)
{
	if (request->stage == BODY_REQUEST){
		LOGGER("----->redirecting %s:%d -> %s:%d", request->info.hostname, request->info.port, redirect->hostname, redirect->port);
		strcpy(request->info.hostname, redirect->hostname);
		request->info.port = redirect->port;
	}
	RETN_OK
}

bool apply_fake_tls_hostname(pclient request, pfake_tls_ext_hostname fake_tls_ext_hostname)
{
	if (request->stage == BODY_REQUEST){
		LOGGER("----->fake tls ext hostname %s -> %s", request->info.hostname, fake_tls_ext_hostname->hostname);
		strcpy(request->info.tls_ext_hostname, fake_tls_ext_hostname->hostname);
	}
	RETN_OK
}

bool file_output(char* path, char* flag, char* buffer, u_int size)
{
	u_int total_sent = 0;
	int written = 0;
	FILE* fd_file = 0;

	IF_GZERO(fd_file = fopen(path, flag))
	while (total_sent != size){
		IF_GZERO(written = fwrite(buffer + total_sent, sizeof(char), size - total_sent, fd_file))
		total_sent += (u_int)written;
	}
	fclose(fd_file);
	RETN_OK
}

void apply_screenshot(pclient request)
{
	if (request->stage == BODY_REQUEST || BODY_RESPONSE == request->stage){
		LOGGER("----->taking screenshot");
		take_screenshot();
	}
}

bool apply_download_content(pclient request, pdownload_content download_content)
{
	char filename[3026] = {0};
	char url[2024] = {0};

	if (request->stage == BODY_RESPONSE){
		if (!strcmp(download_content->content_type, request->headers_response.content_type)){
			LOGGER("----->downloading content %s %s %d bytes %s", request->info.hostname, request->info.url, request->body_response.written, download_content->content_type);
			strcpy(url, request->info.url);
			for (int i = 0; i < strlen(url); ++i){
				if (url[i] == '/') url[i] = DOWNLOAD_CONTENT_SLASH_REMPLACE;
			}
			sprintf(filename, __DOWNLOAD_FOLDER, url);
			file_output(filename, "wb", request->body_response.pointer, request->body_response.written);
		}
	}
	RETN_OK
}

void apply_header_actions(pclient request, PROXY_ACTION action, phead header)
{
	if (action == REMOVE_HEADER_REQUEST && BODY_REQUEST == request->stage){
		LOGGER("----->removing header request: %s", header->header);
		remove_http_header(&request->head_request, header->header);
	} else if (action == REMOVE_HEADER_RESPONSE && HEAD_RESPONSE == request->stage){
		LOGGER("----->removing header response: %s", header->header);
		remove_http_header(&request->head_response, header->header);
	} else if (action == ADD_HEADER_REQUEST && BODY_REQUEST == request->stage){
		LOGGER("----->adding header request: %s", header->header);
		add_http_header(&request->head_request, header->header, header->header_length);
	}
}

int apply_action(pclient request)
{
	paction config = 0;

	ITER_LLIST(config, request->actions){
		LOGGER("---->checking action: %s", PROXY_ACTIONS[config->action])
		switch (config->action){
			case DIRECT:
				break;
			case CAPTURE:
				apply_capture(request);
				break;
			case MODIFY_BODY_RESPONSE:
				request->action = MODIFY_BODY_RESPONSE;
				apply_injection(request, ((pinjection)config->extra_data));
				break;
			case REDIRECT:
				apply_redirect(request, ((predirect)config->extra_data));
				break;
			case REJECT:
				return REJECT;
			case SCREENSHOT:
				apply_screenshot(request);
				break;
			case FAKE_TLS_EXT_HOSTNAME:
				apply_fake_tls_hostname(request, ((pfake_tls_ext_hostname)config->extra_data));
				break;
			case REMOVE_HEADER_REQUEST:
			case REMOVE_HEADER_RESPONSE:
			case ADD_HEADER_REQUEST:
				apply_header_actions(request, config->action, ((phead)config->extra_data));
				break;
			case DOWNLOAD_CONTENT:
				apply_download_content(request, ((pdownload_content)config->extra_data));
				break;
		}
	}
	return request->action;
}

bool check_action(pclient request)
{
	LOGGER("--->checking rules")
	paction naction = 0;
	prule proxy_rule = 0;

	if (!strcmp(request->info.url, __PAC_FILE) && proxy_config.port == request->info.port && (!strcmp(request->info.hostname, proxy_config._interface) ||
		!strcmp(request->info.hostname, __INTERFACE_BIND))){
		send_pac_response(request);
		RETN_OK
	}
	ITER_LLIST(proxy_rule, proxy_config.proxy_rules){
		if (check_filter(proxy_rule->domain, request->info.hostname, '.') &&
			check_filter(proxy_rule->url, request->info.url, '/') &&
			(proxy_rule->method == request->method || proxy_rule->method == ALL) &&
			proxy_rule->port == request->info.port && 
			proxy_rule->ssl == request->ssl){
			CHECK_ALLOC(action, calloc, naction, 1)
			naction->action = proxy_rule->action;
			if (naction->action == MODIFY_BODY_RESPONSE){
				CHECK_ALLOC(injection, calloc, naction->extra_data, 1)
				memcpy(naction->extra_data, proxy_rule->extra_data, sizeof(injection));
			} else if (naction->action == REDIRECT){
				CHECK_ALLOC(redirect, calloc, naction->extra_data, 1)
				memcpy(naction->extra_data, proxy_rule->extra_data, sizeof(redirect));
			} else if (naction->action == FAKE_TLS_EXT_HOSTNAME){
				CHECK_ALLOC(fake_tls_ext_hostname, calloc, naction->extra_data, 1)
				memcpy(naction->extra_data, proxy_rule->extra_data, sizeof(fake_tls_ext_hostname));
			} else if (naction->action == DOWNLOAD_CONTENT){
				CHECK_ALLOC(download_content, calloc, naction->extra_data, 1)
				memcpy(naction->extra_data, proxy_rule->extra_data, sizeof(download_content));
			} else if (naction->action == REMOVE_HEADER_RESPONSE || REMOVE_HEADER_REQUEST == naction->action || naction->action == ADD_HEADER_REQUEST){
				CHECK_ALLOC(head, calloc, naction->extra_data, 1)
				memcpy(naction->extra_data, proxy_rule->extra_data, sizeof(head));
			}
			ADD_ACTION(request->actions, naction);
			LOGGER("--->rule reached, an action was added: M[%s]SSL[%s]A[%s] :%d:%s:%s", PROXY_METHODS[proxy_rule->method], HTTP_SSL[proxy_rule->ssl], PROXY_ACTIONS[proxy_rule->action], proxy_rule->port, proxy_rule->domain, proxy_rule->url)
		}
	}
	RETN_OK
}

bool send_request(bool is_ssl, int socket, pssl_layer ssl, pbuffer head_buffer, pbuffer body_buffer)
{
	IF_GZERO(send_buffer(is_ssl, socket, ssl, head_buffer->pointer, head_buffer->written))
	if (body_buffer->written > 0){
		IF_GZERO(send_buffer(is_ssl, socket, ssl, body_buffer->pointer, body_buffer->written))
	}
	RETN_OK
}

bool get_chunk_data(pclient request)
{
	char chunk_size[20] = {0};
	char delimiter[3] = {0};
	int comming = 0;
	int size = 0;
	int size_incomming = 0;
	int total_received = 0;

	while (true){
		memset(chunk_size, 0, size_incomming);
		memset(delimiter, 0, 3);
		total_received = 0;
		comming = 0;
		size = 0;
		size_incomming = 0;
		while (strstr(chunk_size, "\r\n") == 0 && size_incomming <= 20){
			IF_GZERO(comming = input_buffer(request->ssl, request->sock_page, request->ssl_page, chunk_size + size_incomming, 1))
			size_incomming++;
		}
		if (sscanf(chunk_size, "%x\r\n", &size) != 1) RETN_FAIL
		if (size == 0){
			LOGGER("-->chunk completed!")
			if (request->action != MODIFY_BODY_RESPONSE){
				IF_GZERO(send_buffer(request->ssl, request->sock_browser, request->ssl_browser, const_char.endchunk, 5));
			}
			break;
		}
		if (request->action != MODIFY_BODY_RESPONSE){
			request->body_response.written = 0;
			if (request->body_response.size_block < size){
				request->body_response.size_block = size;
				CHECK_REALLOC(char, realloc, request->body_response.pointer, (void*)request->body_response.pointer, sizeof(char) * request->body_response.size_block)
			}
		} else {
			if (request->body_response.size_block < (request->body_response.written + size)){
				request->body_response.size_block += size;
				CHECK_REALLOC(char, realloc, request->body_response.pointer, (void*)request->body_response.pointer, sizeof(char) * request->body_response.size_block)
			}
		}
		while (total_received != size){
			IF_GZERO(comming = input_buffer(request->ssl, request->sock_page, request->ssl_page, request->body_response.pointer + request->body_response.written, size - total_received))
			total_received += comming;
			request->body_response.written += comming;
		}
		IF_GZERO(input_buffer(request->ssl, request->sock_page, request->ssl_page, delimiter, 2))
		if (request->action != MODIFY_BODY_RESPONSE){
			IF_GZERO(send_buffer(request->ssl, request->sock_browser, request->ssl_browser, chunk_size, size_incomming))
			IF_GZERO(send_buffer(request->ssl, request->sock_browser, request->ssl_browser, request->body_response.pointer, request->body_response.written))
			IF_GZERO(send_buffer(request->ssl, request->sock_browser, request->ssl_browser, "\r\n", 2))
		}
		LOGGER("-->chunk received: size %d, written %d, size_incomming %d", total_received, request->body_response.written, size_incomming)
	}
	RETN_OK
}

bool get_body_response(pclient request)
{
	request->stage = BODY_RESPONSE;
	if (request->action != MODIFY_BODY_RESPONSE){
		IF_GZERO(send_buffer(request->ssl, request->sock_browser, request->ssl_browser, request->head_response.pointer, request->head_response.written))
	}
	if (request->headers_response.chunked == false && request->headers_response.content_length > 0){
		LOGGER("-->content length method: %d", request->headers_response.content_length)
		IF_GZERO(get_body_request(request->ssl, request->sock_page, request->ssl_page, &request->body_response, request->headers_response.content_length, request))
	} else if (request->headers_response.chunked){
		LOGGER("-->chunk data method")
		IF_GZERO(get_chunk_data(request))
	}
	RETN_OK
}

bool send_http_request(pclient request)
{
	return send_request(request->ssl, request->sock_page, request->ssl_page, &request->head_request, &request->body_request);
}

bool send_new_response(pclient request)
{
	if (request->action == MODIFY_BODY_RESPONSE){
		return send_request(request->ssl, request->sock_browser, request->ssl_browser, &request->head_response, &request->body_response);
	}
	RETN_OK
}

bool get_head_response(pclient request)
{
	request->stage = HEAD_RESPONSE;
	IF_GZERO(get_headers_request(request->ssl, request->sock_page, request->ssl_page, &request->head_response))
	sscanf(request->head_response.pointer, const_char.parse_response_code, &request->response_code);
	parse_headers(&request->head_response, &request->headers_response);
	apply_action(request);
	RETN_OK
}

bool get_http_request(pclient request)
{
	IF_GZERO(get_request(request))
	IF_GZERO(get_info_request(request))
	LOGGER("-->hostname %s, port %d, url %s, ssl %s, method %s, head size %d, body size %d", request->info.hostname, request->info.port, request->info.url, HTTP_SSL[request->ssl], PROXY_METHODS[request->method], request->head_request.written, request->body_request.written)
	check_action(request);
	return (apply_action(request) == REJECT) ? false : true;
}
	
u_int socket_tunnel(pclient request)
{
	struct timeval timeout = {0};
	fd_set rd_set = {0};
	int maxfd = 0;
	int nread = 0;
	int nsent = 0;
	char buffer[__INIT_SIZE_BUFFER];

	LOGGER("-->starting socket tunnel")
	maxfd = (request->sock_page > request->sock_browser) ? request->sock_page : request->sock_browser;
	while(true){
		FD_ZERO(&rd_set);
		FD_SET(request->sock_page, &rd_set);
		FD_SET(request->sock_browser, &rd_set);
		timeout.tv_sec = proxy_config.timeout_tunnel;
		IF_GZERO(select(maxfd + 1, &rd_set, 0, 0, &timeout))
		if(FD_ISSET(request->sock_page, &rd_set)) {
			IF_GZERO(nread = input_buffer(request->ssl, request->sock_page, request->ssl_page, buffer, __INIT_SIZE_BUFFER))
			IF_GZERO(nsent = send_buffer(request->ssl, request->sock_browser, request->ssl_browser, buffer, nread))
		}
		if(FD_ISSET(request->sock_browser, &rd_set)){
			IF_GZERO(nread = input_buffer(request->ssl, request->sock_browser, request->ssl_browser, buffer, __INIT_SIZE_BUFFER))
			IF_GZERO(nsent = send_buffer(request->ssl, request->sock_page, request->ssl_page, buffer, nread))
		}
	}
	RETN_OK
}

bool handle_client(int client_socket)
{
	pclient request = 0;

	TRY_EXECUTION(alloc_request(&request))
	request->sock_browser = (SOCKET)client_socket;
	request->action = DIRECT;
	request->thread_id = GetCurrentThreadId();
	TRY_EXECUTION(set_socket_timeout(request->sock_browser, proxy_config.timeout_tunnel))

	keep_alive:
		LOGGER("->request %d", request->nrequests)
		TRY_EXECUTION(get_http_request(request))
		if (!request->connection_established){
			TRY_EXECUTION(socket_connection(request))
			TRY_EXECUTION(set_socket_timeout(request->sock_page, proxy_config.timeout_tunnel))
			#ifdef OPENSSL
				if (request->ssl){
					TRY_EXECUTION(load_ssl_files_pinning(request))
					TRY_EXECUTION(get_http_request(request))
				}
			#endif
			request->connection_established = true;
		}
		TRY_EXECUTION(send_http_request(request))
		TRY_EXECUTION(get_head_response(request))
		LOGGER("->head response size %d, body response size %d, response code %d, keep-alive/upgrade %d/%d, upgrade %s, content-type %s", 
			request->head_response.written, request->body_response.written, request->response_code, request->headers_response.connection.keep_alive, request->headers_response.connection.upgrade, request->headers_response.upgrade, request->headers_response.content_type)
		TRY_EXECUTION(get_body_response(request))
		apply_action(request);
		//printer(request->head_request.pointer, request->head_request.written);
		//printer(request->body_request.pointer, request->body_request.written);
		//printer(request->head_response.pointer, request->head_response.written);
		//printer(request->body_response.pointer, request->body_response.written);
		TRY_EXECUTION(send_new_response(request))
		if (request->headers_response.connection.keep_alive){
			reset_request(request);
			goto keep_alive;
		} else if (request->headers_response.connection.upgrade && request->response_code == SWITCHING_PROTOCOLS) {
			if(strncmp(request->headers_response.upgrade, const_char.websocket, 9) == 0){
				socket_tunnel(request);
			}
		}
		goto __finally;
	__exception:
		LOGGER("__exception: %s, stage: %s", request->ssl_error, PROXY_STAGES[request->stage])
	__finally:
		close_handle(request);
		RETN_OK
}

#ifdef THREAD_POOL
	bool add_pool_job(pthread_pool pool, int socket)
	{
		pjob njob = 0;

		CHECK_ALLOC(job, calloc, njob, 1)
		njob->socket = socket;
		pthread_mutex_lock(&pool->look);
		if (pool->fjob == 0) {
			pool->fjob = njob;
			pool->ljob = pool->fjob;
		} else {
			pool->ljob->next = njob;
			pool->ljob = njob;
		}
		pthread_cond_broadcast(&pool->work_cond);
		pthread_mutex_unlock(&pool->look);
		RETN_OK
	}

	pjob get_pool_job(pthread_pool pool)
	{
		pjob njob = 0;

		njob = pool->fjob;
		if (njob == 0){
			RETN_FAIL
		}
		if (njob->next == 0){
			pool->fjob = 0;
			pool->ljob = 0;
		} else {
			pool->fjob = njob->next;
		}
		return njob;
	}

	void* pool_worker(void* npool)
	{
		pthread_pool pool = npool;
		pjob njob = 0;

		while (true){
			pthread_mutex_lock(&pool->look);
			while (pool->fjob == 0 && !pool->stop){
				pthread_cond_wait(&pool->work_cond, &pool->look);
			}
			if (pool->stop){
				break;
			}
			njob = get_pool_job(pool);
			pool->executing++;
			pthread_mutex_unlock(&pool->look);
			if (njob != 0) {
				handle_client(njob->socket);
				free(njob);
			}
			pthread_mutex_lock(&pool->look);
			pool->executing--;
			if (!pool->stop && pool->executing == 0 && pool->fjob == 0){
				pthread_cond_signal(&pool->working_cond);
			}
			pthread_mutex_unlock(&pool->look);
		}
		pool->nthreads--;
		pthread_cond_signal(&pool->working_cond);
		pthread_mutex_unlock(&pool->look);
		return 0;
	}

	bool create_thread_pool(pthread_pool* nthread_pool, int nthreads)
	{
		LOGGER("-->creating thread pool %d", __POOL_NTHREAD)
		pthread_t thread = 0;

		CHECK_ALLOC(thread_pool, calloc, *nthread_pool, 1)
		pthread_mutex_init(&(*nthread_pool)->look, 0);
		pthread_cond_init(&(*nthread_pool)->work_cond, 0);
		pthread_cond_init(&(*nthread_pool)->working_cond, 0);
		(*nthread_pool)->nthreads = nthreads;
		for (nthreads = 0; nthreads < (*nthread_pool)->nthreads; nthreads++){
			pthread_create(&thread, 0, pool_worker, *nthread_pool);
			pthread_detach(thread);
		}
		RETN_OK
	}
#endif

bool parse_url(prule proxy_rule)
{
	proxy_rule->ssl = strstr(proxy_rule->url, const_char.phttpsd2s) != 0 ? true : false;
	proxy_rule->port = proxy_rule->ssl ? 443 : 80;

	if (proxy_rule->ssl){
		if (sscanf(proxy_rule->url, const_char.parse_https_url_port, proxy_rule->domain, &proxy_rule->port, proxy_rule->url) != 3){
			if (sscanf(proxy_rule->url, const_char.parse_https_url, proxy_rule->domain, proxy_rule->url) != 2){
				RETN_FAIL
			}
		}
	} else {
		if (sscanf(proxy_rule->url, const_char.parse_http_url_port, proxy_rule->domain, &proxy_rule->port, proxy_rule->url) != 3){
			if (sscanf(proxy_rule->url, const_char.parse_http_url, proxy_rule->domain, proxy_rule->url) != 2){
				RETN_FAIL
			}
		}
	}
	RETN_OK
}

pinjection make_inject_data(char* prefix, char* inject)
{
	pinjection ninjection = 0;

	CHECK_ALLOC(injection, calloc, ninjection, 1)
	ninjection->prefix_length = strlen(prefix);
	ninjection->inject_length = strlen(inject);
	CHECK_ALLOC(char, calloc, ninjection->prefix, ninjection->prefix_length + 1)
	CHECK_ALLOC(char, calloc, ninjection->inject, ninjection->inject_length + 1)
	strcpy(ninjection->inject, inject);
	strcpy(ninjection->prefix, prefix);
	return ninjection;
}

predirect make_redirect_data(char* ip, u_int port)
{
	predirect nredirect = 0;

	CHECK_ALLOC(redirect, calloc, nredirect, 1)
	strcpy(nredirect->hostname, ip);
	nredirect->port = port;
	return nredirect;
}

pfake_tls_ext_hostname make_fake_tls_ext_hostname_data(char* hostname)
{
	pfake_tls_ext_hostname nfake_tls_ext_hostname = 0;

	CHECK_ALLOC(fake_tls_ext_hostname, calloc, nfake_tls_ext_hostname, 1)
	strcpy(nfake_tls_ext_hostname->hostname, hostname);
	return nfake_tls_ext_hostname;
}

pdownload_content make_download_content_data(char* content_type)
{
	pdownload_content ndownload_content = 0;

	CHECK_ALLOC(download_content, calloc, ndownload_content, 1)
	strcpy(ndownload_content->content_type, content_type);
	return ndownload_content;
}

phead make_head_data(char* header)
{
	phead nhead = 0;

	CHECK_ALLOC(head, calloc, nhead, 1)
	strcpy(nhead->header, header);
	nhead->header_length = strlen(header);
	return nhead;
}

u_int get_size_file(char* path)
{
	WIN32_FILE_ATTRIBUTE_DATA fad = {0};
	LARGE_INTEGER size = {0};

	if(!GetFileAttributesEx(path, GetFileExInfoStandard, &fad)) return 0;
	size.HighPart = fad.nFileSizeHigh;
	size.LowPart = fad.nFileSizeLow;
	return size.QuadPart;
}

u_int get_rule_info(prule proxy_rule, char* config_line)
{
	u_int lentgh_action = 0;

	if ((lentgh_action = strcspn(config_line, DELIMITER_RULE_INFO)) >= 1){
		if (strnstr(config_line, lentgh_action, PROXY_ACTIONS[REDIRECT], 8)){
			proxy_rule->action = REDIRECT;
		} else if (strnstr(config_line, lentgh_action, PROXY_ACTIONS[CAPTURE], 7)){
			proxy_rule->action = CAPTURE;
		} else if (strnstr(config_line, lentgh_action, PROXY_ACTIONS[MODIFY_BODY_RESPONSE], 6)){
			proxy_rule->action = MODIFY_BODY_RESPONSE;
		} else if (strnstr(config_line, lentgh_action, PROXY_ACTIONS[SCREENSHOT], 10)){
			proxy_rule->action = SCREENSHOT;
		} else if (strnstr(config_line, lentgh_action, PROXY_ACTIONS[FAKE_TLS_EXT_HOSTNAME], 21)){
			proxy_rule->action = FAKE_TLS_EXT_HOSTNAME;
		} else if (strnstr(config_line, lentgh_action, PROXY_ACTIONS[REMOVE_HEADER_REQUEST], 21)){
			proxy_rule->action = REMOVE_HEADER_REQUEST;
		} else if (strnstr(config_line, lentgh_action, PROXY_ACTIONS[REMOVE_HEADER_RESPONSE], 22)){
			proxy_rule->action = REMOVE_HEADER_RESPONSE;
		} else if (strnstr(config_line, lentgh_action, PROXY_ACTIONS[ADD_HEADER_REQUEST], 18)){
			proxy_rule->action = ADD_HEADER_REQUEST;
		} else if (strnstr(config_line, lentgh_action, PROXY_ACTIONS[DOWNLOAD_CONTENT], 16)){
			proxy_rule->action = DOWNLOAD_CONTENT;
		} else if (strnstr(config_line, lentgh_action, PROXY_ACTIONS[REJECT], 6)){
			proxy_rule->action = REJECT;
		}
		lentgh_action++;
		IF_GZERO(get_method(config_line + lentgh_action, &proxy_rule->method));
	}
	if(proxy_rule->action == DIRECT || UNKNOW == proxy_rule->method){
		RETN_FAIL
	}
	RETN_OK
}

bool load_proxy_rules()
{
	prule proxy_rule = 0;
	FILE* config_file = 0;
	char config_line[2048] = {0};
	char arg_1[MAX_ARG_1_SIZE] = {0};
	char arg_2[MAX_ARG_2_SIZE] = {0};
	u_int arg_3 = 0;
	u_int line = 1;

	LOGGER("-->loading configuration: %s...", proxy_config.cfg_file)
	if((config_file = fopen(proxy_config.cfg_file, "r"))){
		while(fgets(config_line, 2048, config_file)){
			if (COMMENT_RULE != *config_line && *config_line != '\n'){
				if(sscanf(config_line, SETTING_FORMAT, arg_1, arg_2) == 2){
					if(!strcmp(arg_1, KEY_SETTING[_INTERFACE])){
						strcpy(proxy_config._interface, arg_2);
					} else if(!strcmp(arg_1, KEY_SETTING[PORT])){
						proxy_config.port = atoi(arg_2);
					} else if(!strcmp(arg_1, KEY_SETTING[POOL_NTHREADS])){
						proxy_config.nthreads = atoi(arg_2);
					} else if(!strcmp(arg_1, KEY_SETTING[TIMEOUT_CONNECT])){
						proxy_config.timeout_connect = atoi(arg_2) * 1000;
					} else if(!strcmp(arg_1, KEY_SETTING[TIMEOUT_TUNNEL])){
						proxy_config.timeout_tunnel = atoi(arg_2) * 1000;
					} else if(!strcmp(arg_1, KEY_SETTING[INIT_BUFFER_SIZE])){
						proxy_config.init_buffer_size = atoi(arg_2);
					} else {
						goto __exception;
					}
					continue;
				}
				CHECK_ALLOC(rule, calloc, proxy_rule, 1)
				TRY_EXECUTION(get_rule_info(proxy_rule, config_line));
				switch (proxy_rule->action){
					case MODIFY_BODY_RESPONSE:
						if (sscanf(config_line, "%*[^" DELIMITER_RULE_INFO "]" DELIMITER_RULE_INFO "%*[^" DELIMITER_RULE_INFO "]" DELIMITER_RULE_INFO "%" IN2STR(MAX_URL_SIZE) "[^" DELIMITER_RULE_INFO "]" DELIMITER_RULE_INFO "%" IN2STR(MAX_ARG_1_SIZE) "[^" DELIMITER_RULE_INFO "]" DELIMITER_RULE_INFO "%" IN2STR(MAX_ARG_2_SIZE) "[^\n]\n", proxy_rule->url, arg_1, arg_2) != 3){
							goto __exception;
						}
						break;
					case REDIRECT:
						if (sscanf(config_line, "%*[^" DELIMITER_RULE_INFO "]" DELIMITER_RULE_INFO "%*[^" DELIMITER_RULE_INFO "]" DELIMITER_RULE_INFO "%" IN2STR(MAX_URL_SIZE) "[^" DELIMITER_RULE_INFO "]" DELIMITER_RULE_INFO "%" IN2STR(MAX_ARG_1_SIZE) "[^" DELIMITER_RULE_INFO "]" DELIMITER_RULE_INFO "%d", proxy_rule->url, arg_1, &arg_3) != 3){
							goto __exception;
						}
						break;
					case REMOVE_HEADER_REQUEST:
					case REMOVE_HEADER_RESPONSE:
					case ADD_HEADER_REQUEST:
					case FAKE_TLS_EXT_HOSTNAME:
					case DOWNLOAD_CONTENT:
						if (sscanf(config_line, "%*[^" DELIMITER_RULE_INFO "]" DELIMITER_RULE_INFO "%*[^" DELIMITER_RULE_INFO "]" DELIMITER_RULE_INFO "%" IN2STR(MAX_URL_SIZE) "[^" DELIMITER_RULE_INFO "]" DELIMITER_RULE_INFO "%" IN2STR(MAX_ARG_1_SIZE) "[^\n]\n", proxy_rule->url, arg_1) != 2){
							goto __exception;
						}
						break;
					case SCREENSHOT:
					case CAPTURE:
					case REJECT:
					default:
						if (sscanf(config_line, "%*[^" DELIMITER_RULE_INFO "]" DELIMITER_RULE_INFO "%*[^" DELIMITER_RULE_INFO "]" DELIMITER_RULE_INFO "%" IN2STR(MAX_URL_SIZE) "[^\n]\n", proxy_rule->url) != 1){
							goto __exception;
						}
						break;
				}
				if (parse_url(proxy_rule)){
					if (proxy_rule->action == MODIFY_BODY_RESPONSE){
						proxy_rule->extra_data = make_inject_data(arg_1, arg_2);
					} else if (proxy_rule->action == REDIRECT){
						proxy_rule->extra_data = make_redirect_data(arg_1, arg_3);
					} else if (proxy_rule->action == FAKE_TLS_EXT_HOSTNAME){
						proxy_rule->extra_data = make_fake_tls_ext_hostname_data(arg_1);
					} else if (proxy_rule->action == DOWNLOAD_CONTENT){
						proxy_rule->extra_data = make_download_content_data(arg_1);
					} else if (proxy_rule->action == REMOVE_HEADER_RESPONSE || REMOVE_HEADER_REQUEST == proxy_rule->action || proxy_rule->action == ADD_HEADER_REQUEST){
						proxy_rule->extra_data = make_head_data(arg_1);
					}
					ADD_RULE(proxy_rule);
				} else {
					goto __exception;
				}
			}
		line++;
		}
	} else {
		LOGGER("-->h2Polar '%s' configuration file not was found.", __CONFIG_FILE)
		goto __exception;
	}
	fclose(config_file);
	#ifdef DEBUG
		int count = 0;
		LOGGER("-->interface %s port %d nthreads %d timeout-connect %lu timeout-tunnel %lu init-buffer-size %d max-clients %d", proxy_config._interface, proxy_config.port, proxy_config.nthreads, 
																															   proxy_config.timeout_connect, proxy_config.timeout_tunnel, proxy_config.init_buffer_size, __MAX_CLIENT)
		LOGGER("-->set your http/s client with http://%s:%d%s pac url.", proxy_config._interface, proxy_config.port, __PAC_FILE)
		LOGGER("-->rules loaded:")
		ITER_LLIST(proxy_rule, proxy_config.proxy_rules){
			count++;
			switch (proxy_rule->action){
				case MODIFY_BODY_RESPONSE:
					LOGGER("(#%d)[MODIFY_BODY_RESPONSE] [%s] [%s] [%d] [%s] [%s] [%s] [%s]", 
							count, PROXY_METHODS[proxy_rule->method], HTTP_SSL[proxy_rule->ssl], proxy_rule->port, proxy_rule->domain, proxy_rule->url, 
							((pinjection)proxy_rule->extra_data)->prefix, ((pinjection)proxy_rule->extra_data)->inject)
					break;
				case REDIRECT:
					LOGGER("(#%d)[REDIRECT] [%s] [%s] [%d] [%s] [%s] [%s] [%d]", 
							count, PROXY_METHODS[proxy_rule->method], HTTP_SSL[proxy_rule->ssl], proxy_rule->port, proxy_rule->domain, proxy_rule->url, 
							((predirect)proxy_rule->extra_data)->hostname, ((predirect)proxy_rule->extra_data)->port)
					break;
				case REMOVE_HEADER_REQUEST:
				case REMOVE_HEADER_RESPONSE:
				case ADD_HEADER_REQUEST:
					LOGGER("(#%d)[%s] [%s] [%s] [%d] [%s] [%s] [%s]", 
							count, PROXY_ACTIONS[proxy_rule->action], PROXY_METHODS[proxy_rule->method], HTTP_SSL[proxy_rule->ssl], proxy_rule->port, proxy_rule->domain, proxy_rule->url, 
							((phead)proxy_rule->extra_data)->header)
					break;
				case FAKE_TLS_EXT_HOSTNAME:
					LOGGER("(#%d)[%s] [%s] [%s] [%d] [%s] [%s] [%s]", 
							count, PROXY_ACTIONS[proxy_rule->action], PROXY_METHODS[proxy_rule->method], HTTP_SSL[proxy_rule->ssl], proxy_rule->port, proxy_rule->domain, proxy_rule->url, 
							((pfake_tls_ext_hostname)proxy_rule->extra_data)->hostname)
					break;
				case DOWNLOAD_CONTENT:
					LOGGER("(#%d)[%s] [%s] [%s] [%d] [%s] [%s] [%s]", 
							count, PROXY_ACTIONS[proxy_rule->action], PROXY_METHODS[proxy_rule->method], HTTP_SSL[proxy_rule->ssl], proxy_rule->port, proxy_rule->domain, proxy_rule->url, 
							((pdownload_content)proxy_rule->extra_data)->content_type)
					break;
				case SCREENSHOT:
				case CAPTURE:
				case REJECT:
					LOGGER("(#%d)[%s] [%s] [%s] [%d] [%s] [%s]", 
							count, PROXY_ACTIONS[proxy_rule->action], PROXY_METHODS[proxy_rule->method], HTTP_SSL[proxy_rule->ssl], proxy_rule->port, proxy_rule->domain, proxy_rule->url)
					break;	
				case DIRECT:
					break;
			}
		}
		LOGGER("")
	#endif
	generate_pac_response();
	RETN_OK
	__exception:
		LOGGER("->it was a error parsing the settings, line: %d, string: (%s)", line, config_line)
		RETN_FAIL
}

bool start_http_proxy()
{
	struct sockaddr_in client_addr = {0};
	struct sockaddr_in proxy_addr = {0};
	WSADATA wsd = {0};
	int dummy_struct_size = 0;
	int opt_reuse = 1;
	SOCKET client_socket = 0;
	#ifdef THREAD_POOL
		pthread_pool pool = 0;
	#endif

	dummy_struct_size = sizeof(proxy_addr);
	proxy_addr.sin_family = 2;
	proxy_addr.sin_port = htons(proxy_config.port);
	proxy_addr.sin_addr.s_addr = inet_addr(proxy_config._interface);

	TRY_EXECUTION(!WSAStartup(MAKEWORD(2, 2), &wsd))
	IF_GZERO(proxy_config.socket = socket(2, 1, 0))
	TRY_EXECUTION(!setsockopt(proxy_config.socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt_reuse, sizeof(int)))
	TRY_EXECUTION(!bind(proxy_config.socket, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)))
	TRY_EXECUTION(!listen(proxy_config.socket, __MAX_CLIENT))
	#ifdef THREAD_POOL
		IF_GZERO(create_thread_pool(&pool, proxy_config.nthreads))
	#endif
	#ifdef OPENSSL
		SSLeay_add_ssl_algorithms();
		if(!load_ssl_files()){
			generate_ssl_files();
		}
	#endif
	while (true){
		client_socket = accept(proxy_config.socket, (struct sockaddr*)&client_addr, &dummy_struct_size);
		#ifdef THREAD_POOL
			add_pool_job(pool, client_socket);
		#else
			CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)handle_client, (void*)client_socket, 0, 0));
		#endif
	}
	__exception:
		LOGGER("->it was a error starting proxy, error (%lu).", GetLastError())
	RETN_OK
}

int main(int argc, char** argv)
{
	#ifdef DNS_MEM_CACHE
		InitializeCriticalSection(&proxy_config.domain_cache_lock);
	#endif
	InitializeCriticalSection(&proxy_config.certificate_cache_lock);
	#ifdef DEBUG
		InitializeCriticalSection(&proxy_config.stdout_lock);
	#endif
	LOGGER("->h2Polar by %s V:%s", __AUTHOR, __VERSION)
	load_strings();
	if(argc == 2){
		proxy_config.cfg_file = argv[1];
	}
	IF_GZERO(load_proxy_rules())
	start_http_proxy();
	RETN_OK
}
