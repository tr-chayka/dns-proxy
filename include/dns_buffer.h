#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct
{
	uint8_t* begin;
	uint8_t* end;
	uint8_t* it;
} dns_buffer;

bool dns_buffer_init(dns_buffer* this, size_t length);
void dns_buffer_dispose(dns_buffer* this);
