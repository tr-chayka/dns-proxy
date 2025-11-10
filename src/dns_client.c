#include <dns_client.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

uint16_t message_id(const dns_buffer* buffer)
{
	return *(uint16_t*)buffer->begin;
}

bool dns_client_init(dns_client* client, uint16_t port, uint32_t upstream_ip)
{
	client->client_socket = socket(AF_INET, SOCK_DGRAM, 0);

	if (client->client_socket < 0)
	{
		printf("could not create socket for upstream dns\n");
		return false;
	}

	struct sockaddr_in client_addr = {0};
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(0);

	const int error = bind(client->client_socket, (struct sockaddr*)&client_addr, sizeof(client_addr));

	if (error != 0)
	{
		printf("could not bind dns client\n");
		return false;
	}

	memset(&client->upstream_dns, 0, sizeof(client->upstream_dns));
	client->upstream_dns.sin_family = AF_INET;
	client->upstream_dns.sin_port = htons(port);
	client->upstream_dns.sin_addr.s_addr = upstream_ip;

	return true;
}

bool dns_client_resolve(const dns_client* this, const dns_buffer* request, dns_buffer* response)
{
	const size_t request_length = request->it - request->begin;

	const long error = sendto(this->client_socket,
			request->begin,
			request_length,
			0,
			(struct sockaddr*)&this->upstream_dns,
			sizeof(this->upstream_dns));

	if (error < 0)
	{
		return false;
	}

	const size_t max_try_count = 10;

	for (size_t i = 0; i < max_try_count; i++)
	{
		const long read = recvfrom(this->client_socket, response->begin, DNS_UDP_MAX_LENGTH, 0, NULL, NULL);

		if (read >= DNS_MESSAGE_HEADER_SIZE && message_id(request) == message_id(response))
		{
			response->it = response->begin + read;
			return true;
		}
	}

	return false;
}