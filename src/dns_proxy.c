#include <dns_proxy.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

bool dns_proxy_init(dns_proxy_server* this, const dns_proxy_settings* settings)
{
	this->proxy_socket = socket(PF_INET, SOCK_DGRAM, 0);

	if (this->proxy_socket < 0)
	{
		printf("create socket failed\n");
		return false;
	}

	struct sockaddr_in proxy_addr = {0};
	proxy_addr.sin_port = htons(settings->listening_port);
	proxy_addr.sin_family = AF_INET;

	const int error = bind(this->proxy_socket, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr));

	if (error < 0)
	{
		printf("socket binding failed\n");
		return false;
	}

	if (!dns_blacklist_init(&this->blacklist, settings->blacklist_filename))
		this->blacklist.domains = NULL;

	if (!dns_client_init(&this->upstream_dns, settings->upstream_port, settings->upstream_ip))
		return false;

	this->blacklist_response_type = settings->blacklist_response_type;
	this->blacklist_response_ip = settings->blacklist_response_ip;

	return true;
}

void dns_proxy_dispose(dns_proxy_server *this)
{
	dns_blacklist_dispose(&this->blacklist);
}

void dns_proxy_run(dns_proxy_server* this)
{
	dns_buffer request_buffer = {0};
	dns_buffer response_buffer = {0};

	bool ok = true;
	ok = ok && dns_buffer_init(&request_buffer, DNS_UDP_MAX_LENGTH + 1);
	ok = ok && dns_buffer_init(&response_buffer, DNS_UDP_MAX_LENGTH + 1);

	if (!ok)
		return;

	dns_message request_msg = {0};
	dns_message response_msg = {0};

	struct sockaddr client_addr;
	socklen_t client_addr_len;

	printf("dns proxy server started\n");

	while (1)
	{
		long read = recvfrom(this->proxy_socket,
			request_buffer.begin,
			DNS_UDP_MAX_LENGTH,
			MSG_WAITALL,
			&client_addr,
			&client_addr_len);

		if (read > 0 && dns_read_message(&request_buffer, &request_msg) && request_msg.header.qdcount > 0)
		{
			// log print
			{
				char* ip = inet_ntoa(((struct sockaddr_in*)&client_addr)->sin_addr);
				// printf("request from ip: %s, name to resolve = %s\n", ip, request_msg.question[0].qname);
			}

			response_buffer.it = response_buffer.begin; // clear response buffer

			if (dns_blacklist_find(&this->blacklist, request_msg.question[0].qname))
			{
				// printf("requested name (%s) found in blacklist\n", request_msg.question->qname);
				request_msg.header.flags.qr = 1;

				// create response
				switch (this->blacklist_response_type)
				{
					case BLACKLIST_RESPONSE_IP: // return predefined ip
					{
						request_msg.header.flags.aa = 1;
						request_msg.header.ancount = 1;
						request_msg.header.nscount = 0;
						request_msg.header.arcount = 0;

						request_msg.answer = malloc(sizeof(dns_resource_record));
						strcpy(request_msg.answer->name, request_msg.question->qname);
						request_msg.answer->ttl = 1000;
						request_msg.answer->type = request_msg.question->qtype;
						request_msg.answer->class = request_msg.question->qclass;
						request_msg.answer->rdlength = sizeof(uint32_t);
						memcpy(request_msg.answer->rdata, &this->blacklist_response_ip, sizeof(uint32_t));

						dns_write_message(&response_buffer, &request_msg);
						break;
					}

					case BLACKLIST_RESPONSE_NOTFOUND: // return empty answer
						break;

					case BLACKLIST_RESPONSE_REFUSED:
						request_msg.header.flags.rcode = 5; // REFUSED
						break;

				}

				dns_write_message(&response_buffer, &request_msg);
			}
			else
			{
				// printf("request redirected to upstream dns\n");
				request_buffer.it = request_buffer.begin + read;
				dns_client_resolve(&this->upstream_dns, &request_buffer, &response_buffer);
			}

			size_t response_length = response_buffer.it - response_buffer.begin;
			sendto(this->proxy_socket,
				response_buffer.begin,
				response_length,
				0,
				&client_addr,
				client_addr_len);
		}

		request_buffer.it = request_buffer.begin;
		// clear request buffer
	}
}