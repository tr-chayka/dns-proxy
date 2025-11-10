#pragma once
#include <generic_buffer.h>

#include <stdbool.h>

enum dns_blacklist_response_type
{
	BLACKLIST_RESPONSE_IP = 0,
	BLACKLIST_RESPONSE_NOTFOUND = 1,
	BLACKLIST_RESPONSE_REFUSED = 2,
};

typedef struct
{
	generic_buffer* domains;
} dns_blacklist;

bool dns_blacklist_init(dns_blacklist* this, const char* filename);
void dns_blacklist_dispose(dns_blacklist* this);
bool dns_blacklist_find(const dns_blacklist* this, const char* domain);