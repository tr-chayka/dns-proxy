#include <ctype.h>
#include <settings.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/_endian.h>

#define MAX_VALUE_LENGTH 256

bool handle_blacklist(dns_proxy_settings* settings, const char* value);
bool handle_blacklist_ip(dns_proxy_settings* settings, const char* value);
bool handle_upstream_ip(dns_proxy_settings* settings, const char* value);
bool handle_upstream_port(dns_proxy_settings* settings, const char* value);
bool handle_port(dns_proxy_settings* settings, const char* value);
bool handle_filter_type(dns_proxy_settings* settings, const char* value);

uint64_t hash(const char* str)
{
	uint64_t hash = 0;

	while (*str != 0)
	{
		const char ch = *str++;
		hash = hash * 31 + (ch == '_' ? 'Z' - 'A' + 1 : toupper(ch) - 'A');
	}

	return hash;
}

const char* COMMAND_NAMES[] =
{
	"BLACKLIST",
	"BLACKLIST_IP",
	"UPSTREAM_DNS_IP",
	"UPSTREAM_DNS_PORT",
	"PORT",
	"FILTER_TYPE",
};

const char* BLACKLIST_RESPONSES[] =
{
	"IP",
	"NOTFOUND",
	"REFUSED",
};

bool (*command_arg_handlers[])(dns_proxy_settings*, const char* value) =
{
	handle_blacklist,
	handle_blacklist_ip,
	handle_upstream_ip,
	handle_upstream_port,
	handle_port,
	handle_filter_type,
};

const size_t COMMAND_COUNT =
	sizeof(COMMAND_NAMES) / sizeof(const char*);

const size_t BLACKLIST_RESPONSE_COUNT =
	sizeof(BLACKLIST_RESPONSES) / sizeof(const char*);

uint64_t NAME_HASH[COMMAND_COUNT] = {0};
uint64_t BLACKLIST_RESPONSE_HASH[BLACKLIST_RESPONSE_COUNT] = {0};


void init_tables()
{
	for (size_t i = 0; i < COMMAND_COUNT; i++)
		NAME_HASH[i] = hash(COMMAND_NAMES[i]);

	for (size_t i = 0; i < BLACKLIST_RESPONSE_COUNT; i++)
		BLACKLIST_RESPONSE_HASH[i] = hash(BLACKLIST_RESPONSES[i]);
}

int find_hash(const uint64_t hash, const uint64_t* hash_list, size_t length)
{
	for (size_t i = 0; i < length; i++)
		if (hash_list[i] == hash)
			return (int)i;

	return -1;
}

int find_name(const uint64_t hash)
{
	return find_hash(hash, NAME_HASH, COMMAND_COUNT);
}

int find_blacklist_response(const uint64_t hash)
{
	return find_hash(hash, BLACKLIST_RESPONSE_HASH, BLACKLIST_RESPONSE_COUNT);
}

uint64_t read_name(FILE* file)
{
	uint64_t hash = 0;

	while (true)
	{
		const int ch = fgetc(file);

		if (isalpha(ch) || ch == '_')
			hash = hash * 31 + (ch == '_' ? 'Z' - 'A' + 1 : toupper(ch) - 'A');
		else
			break;
	}

	fseek(file, -1, SEEK_CUR);
	return hash;
}

int skip_whitespaces(FILE* file)
{
	while (true)
	{
		const int ch = fgetc(file);
		if (!isspace(ch))
			return ch;
	}
}

void skip_line(FILE* file)
{
	while (true)
	{
		const char ch = fgetc(file);
		if (ch == '\n' || ch == EOF)
			return;
	}
}

bool dns_read_settings(dns_proxy_settings* settings, const char* filename)
{
	FILE* file = fopen(filename, "r");
	bool ok = true;

	if (file == NULL)
		return false;

	init_tables();

	while (!feof(file))
	{
		uint64_t name_hash = read_name(file);
		int equals_sign = skip_whitespaces(file);
		int name_index = find_name(name_hash);

		if (name_index < 0 || equals_sign != '=')
		{
			skip_line(file);
			continue;
		}

		char value[MAX_VALUE_LENGTH] = {0};
		size_t position = 0;

		int ch = skip_whitespaces(file);
		while (ch != '\n' && ch != EOF)
		{
			if (position < MAX_VALUE_LENGTH - 1)
				value[position++] = (char)ch;

			ch = fgetc(file);
		}

		ok = ok && command_arg_handlers[name_index](settings, value);
	}

	fclose(file);
	return ok;
}

uint32_t parse_ipv4(const char* str)
{
	uint32_t ip = 0;
	char ch = *str++;

	uint32_t num = 0;
	uint32_t position = 0;

	while (true)
	{
		if (isdigit(ch))
		{
			num = num * 10 + (ch - '0');
			if (num > 0xFF)
				return 0;
		}
		else
		{
			if (position >= 4)
				return ip;

			ip = (ip << 8) + num;
			position++;
			num = 0;

			if (ch != '.')
				break;
		}

		ch = *str++;
	}

	return ip;
}

uint32_t read_port(const char* str)
{
	uint32_t port = 0;
	char ch = *str++;

	while (true)
	{
		if (isdigit(ch))
		{
			port = port * 10 + (ch - '0');

			if (port > 0xFFFF)
				return 0;
		}
		else
			break;

		ch = *str++;
	}

	return port;
}

//

bool handle_blacklist(dns_proxy_settings* settings, const char* value)
{
	bool ok = false;
	FILE *black_list_file = fopen(value, "r");

	if (black_list_file != NULL)
	{
		ok = true;
		settings->blacklist_filename = strdup(value);
	}

	fclose(black_list_file);
	return ok;
}

bool handle_blacklist_ip(dns_proxy_settings* settings, const char* value)
{
	uint32_t addr_v4 = parse_ipv4(value);
	if (addr_v4 != 0)
		settings->blacklist_response_ip = htonl(addr_v4);

	return addr_v4 != 0;
}

bool handle_upstream_ip(dns_proxy_settings* settings, const char* value)
{
	uint32_t addr_v4 = parse_ipv4(value);
	if (addr_v4 != 0)
		settings->upstream_ip = htonl(addr_v4);

	return addr_v4 != 0;
}

bool handle_upstream_port(dns_proxy_settings* settings, const char* value)
{
	uint32_t port = read_port(value);
	if (port != 0)
		settings->upstream_port = port;

	return port != 0;
}

bool handle_port(dns_proxy_settings* settings, const char* value)
{
	uint32_t port = read_port(value);
	if (port != 0)
		settings->listening_port = port;

	return port != 0;
}

bool handle_filter_type(dns_proxy_settings* settings, const char* value)
{
	int response_type = find_blacklist_response(hash(value));

	if (response_type >= 0)
		settings->blacklist_response_type = response_type;

	return response_type >= 0;
}