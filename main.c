#include <dns_proxy.h>
#include <settings.h>

#include <stdio.h>
#include <arpa/inet.h>

#define DEFAULT_PORT 4150
#define DEFAULT_DNS_PORT 53

void set_settings_defaults(dns_proxy_settings *settings)
{
	settings->upstream_port = 53;
	settings->upstream_ip = inet_addr("8.8.8.8");
	settings->listening_port = DEFAULT_PORT;
	settings->blacklist_filename = "blacklist.txt";
	settings->blacklist_response_type = BLACKLIST_RESPONSE_REFUSED;
	settings->blacklist_response_ip = inet_addr("127.0.0.1");
}

int main(int argc, char* argv[])
{
	dns_proxy_settings settings;
	set_settings_defaults(&settings);

	bool ok = dns_read_settings(&settings, "settings.txt");

	if (!ok)
		printf("could not read setting file\n");

	dns_proxy_server proxy;
	if (dns_proxy_init(&proxy, &settings))
		dns_proxy_run(&proxy);

	return 0;
}