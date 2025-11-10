#include <dns_buffer.h>

#include <stdlib.h>
#include <string.h>

bool dns_buffer_init(dns_buffer* this, size_t length)
{
	memset(this, 0, sizeof(dns_buffer));
	this->begin = (uint8_t*)malloc(length);

	if (this->begin == NULL)
		return false;

	this->end = this->begin + length;
	this->it = this->begin;

	return true;
}

void dns_buffer_dispose(dns_buffer* this)
{
	if (this->begin != NULL)
	{
		free(this->begin);

		this->begin = NULL;
		this->end = NULL;
		this->it = NULL;
	}
}