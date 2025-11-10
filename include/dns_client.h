#pragma once
#include <dns_message.h>

#include <netinet/in.h>

typedef struct
{
	int client_socket;
	struct sockaddr_in upstream_dns;
} dns_client;

bool dns_client_init(dns_client* client, uint16_t port, uint32_t upstream_ip);
bool dns_client_resolve(const dns_client* client, const dns_buffer* request, dns_buffer* response);
