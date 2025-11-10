#pragma once
#include <dns_client.h>
#include <dns_blacklist.h>

typedef struct
{
	uint16_t listening_port;
	uint16_t upstream_port;
	uint32_t upstream_ip;
	const char* blacklist_filename;
	enum dns_blacklist_response_type blacklist_response_type;
	uint32_t blacklist_response_ip;
} dns_proxy_settings;

typedef struct
{
	int proxy_socket;
	dns_client upstream_dns;
	dns_proxy_settings settings;

	dns_blacklist blacklist;
	enum dns_blacklist_response_type blacklist_response_type;
	uint32_t blacklist_response_ip;
} dns_proxy_server;

bool dns_proxy_init(dns_proxy_server* this, const dns_proxy_settings* settings);
void dns_proxy_dispose(dns_proxy_server* this);
void dns_proxy_run(dns_proxy_server* this);